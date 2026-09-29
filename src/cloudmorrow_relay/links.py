"""Linking a box to an account, the way a television signs in.

The box asks for a link code (`POST /v1/links`, no token) and shows it:
*Open cloudmorrow.com/link and enter KXRT-4829.* The person signs in there,
enters the code and picks a name; the website approves the code with that
name and the account over the admin API (admin.py), which makes the cloud.
Meanwhile the box polls (`POST /v1/links/poll` with the `poll` secret it
was given, which nobody else has): 202 while it waits, then once 200 with
its token and its acme-dns credentials, 410 when the code ran out or was
refused.

A link code is eight characters from the same alphabet as invites (no
0/O, 1/I/L), shown as two groups of four, valid fifteen minutes. The
website is the only one that can try a code, and it does so for a person
who is signed in; the codes are kept hashed like invites.
"""

from __future__ import annotations

import re
import secrets
import time

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from .pairing import ALPHABET
from .store import Cloud, iso

CODE_LENGTH = 8
LIFETIME = 900
POLL_INTERVAL = 5


def new_code() -> str:
    return "".join(secrets.choice(ALPHABET) for _ in range(CODE_LENGTH))


def show(code: str) -> str:
    return f"{code[:4]}-{code[4:]}"


def normalise_code(value: str) -> str | None:
    code = re.sub(r"[\s\-]", "", value or "").upper()
    if len(code) != CODE_LENGTH or any(c not in ALPHABET for c in code):
        return None
    return code


def acme_dns(svc, cloud: Cloud) -> dict:
    """Fresh acme-dns credentials for the cloud, as acme-dns's own
    `register` answers them; any earlier ones stop working.
    """
    cfg = svc.cfg
    user, password, subdomain = svc.store.acme_register(cloud.id)
    return {
        "username": user,
        "password": password,
        "subdomain": subdomain,
        # The record is published at the name itself, so no CNAME is
        # needed: fulldomain is where the TXT already lives.
        "fulldomain": f"_acme-challenge.{cfg.public_host(cloud.name)}",
        "allowfrom": [],
        "server_url": f"{cfg.control_url}/v1/acme-dns",
    }


def handover(svc, cloud: Cloud) -> dict:
    """What a box gets once, when its cloud is made: a new token and new
    acme-dns credentials (both replace whatever there was).
    """
    cfg = svc.cfg
    token = svc.store.new_token(cloud.id)
    return {
        "cloud_id": cloud.id,
        "token": token,
        "name": cloud.name,
        "zone": cfg.zone,
        "login_server": cfg.login_server,
        "acme_dns": acme_dns(svc, cloud),
    }


class PollBody(BaseModel):
    model_config = ConfigDict(extra="ignore")
    poll: str = Field(max_length=200)


def router(svc) -> APIRouter:
    r = APIRouter()

    @r.post("/v1/links", status_code=201)
    async def start(request: Request):
        if not svc.links.allow(svc.client_ip(request)):
            raise HTTPException(429, "Too many link codes from this address. Try again later.")
        expires = time.time() + LIFETIME
        poll = secrets.token_urlsafe(32)
        while True:
            code = new_code()
            if svc.store.add_link(code, poll, expires):
                break
        return {
            "code": show(code),
            "poll": poll,
            "url": svc.cfg.link_url,
            "expires_at": iso(expires),
            "interval": POLL_INTERVAL,
        }

    @r.post("/v1/links/poll")
    async def poll(body: PollBody):
        result = svc.store.collect_link(body.poll, LIFETIME)
        if result == "waiting":
            return JSONResponse({"detail": "The link code has not been approved yet."}, 202)
        if result == "gone":
            raise HTTPException(410, "That link code has run out or was refused. Ask for a new one.")
        return handover(svc, result)

    return r
