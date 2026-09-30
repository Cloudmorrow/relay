"""The admin API (`/admin/v1`): what the website asks of the relay.

Only the website calls it, with `Authorization: Bearer <admin secret>`
(the secret comes from the environment or a file, config.py; without one
the admin API answers 503 to everything). Accounts are opaque to the
relay: the website's account id, a string it hands us and nothing else.
Every call that acts on a cloud names the account, and a cloud that is not
that account's is answered like one that does not exist.

    GET    /admin/v1/names/{name}               can this name be taken?
    GET    /admin/v1/links/{code}               is this link code waiting?
                                                (404 never given, 410 gone)
    POST   /admin/v1/links/{code}/approve       make the cloud, for the box
    POST   /admin/v1/links/{code}/refuse        the person said no
    GET    /admin/v1/accounts/{account}/clouds  the account's clouds
    PATCH  /admin/v1/clouds/{id}                rename; the offline page
    GET    /admin/v1/clouds/{id}/logo           the logo, shown or not
    PUT    /admin/v1/clouds/{id}/logo           the logo (the body)
    DELETE /admin/v1/clouds/{id}/logo
    POST   /admin/v1/clouds/{id}/invites        an invite code (retired)
    DELETE /admin/v1/clouds/{id}                unlink

What the website learns about a cloud is its name, when it was made,
whether its box is online and how much of the last thirty days it was,
whether it is reachable from anywhere (the box decides that; the website
only shows it), and what the owner chose for the offline page. Nothing
about its devices or its people.

Invites are retired: nothing shows a code any more. The call stays, for
now, and makes the same invite a box would.
"""

from __future__ import annotations

import logging
import time

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field

from . import landing, links, logos, meshwatch, pairing
from .headscale import HeadscaleError
from .names import name_problem, normalise_name
from .store import Cloud, LinkGone, NameTaken, iso, tokens_equal

log = logging.getLogger("cloudmorrow_relay.admin")

ACCOUNT_MAX = 200
DISPLAY_NAME_MAX = 80


class Body(BaseModel):
    model_config = ConfigDict(extra="ignore")


class ApproveBody(Body):
    account: str = Field(min_length=1, max_length=ACCOUNT_MAX)
    name: str = Field(max_length=200)


class AccountBody(Body):
    account: str = Field(min_length=1, max_length=ACCOUNT_MAX)


class PatchBody(Body):
    account: str = Field(min_length=1, max_length=ACCOUNT_MAX)
    name: str | None = Field(default=None, max_length=200)
    display_name: str | None = Field(default=None, max_length=DISPLAY_NAME_MAX)
    show_name: bool | None = None
    show_logo: bool | None = None


def router(svc) -> APIRouter:
    cfg = svc.cfg
    store = svc.store

    def admin(request: Request, authorization: str | None = Header(default=None)) -> None:
        # The website calls the relay host; the login host is for devices.
        if svc.entry_name(request) == cfg.login_host:
            raise HTTPException(404, "There is nothing here.")
        secret = svc.admin_secret
        if not secret:
            raise HTTPException(503, "The admin API is not set up on this relay.")
        ip = svc.client_ip(request)
        if svc.bad_auth.blocked(ip):
            raise HTTPException(429, "Too many failed attempts. Wait a minute.")
        given = ""
        if authorization and authorization[:7].lower() == "bearer ":
            given = authorization[7:].strip()
        if not given or not tokens_equal(given, secret):
            svc.bad_auth.hit(ip)
            raise HTTPException(401, "A valid admin secret is required.", headers={"WWW-Authenticate": "Bearer"})

    r = APIRouter(prefix="/admin/v1", dependencies=[Depends(admin)])

    def owned(cloud_id: str, account: str) -> Cloud:
        cloud = store.cloud(cloud_id)
        if cloud is None or not account or cloud.account != account:
            raise HTTPException(404, "There is no such cloud on this account.")
        return cloud

    def entry(cloud: Cloud) -> dict:
        return {
            "cloud_id": cloud.id,
            "name": cloud.name,
            "created": iso(cloud.created_at),
            **meshwatch.status(store, cloud),
            "public": cloud.public,
            "show_name": cloud.show_name,
            "show_logo": cloud.show_logo,
            "display_name": cloud.display_name,
            "has_logo": store.has_logo(cloud.id),
        }

    def checked_name(value: str) -> str:
        name = normalise_name(value)
        problem = name_problem(name, cfg.reserved())
        if problem:
            raise HTTPException(422, problem)
        return name

    # --- names and links -----------------------------------------------------

    @r.get("/names/{name}")
    async def name_available(name: str):
        name = normalise_name(name)
        problem = name_problem(name, cfg.reserved())
        if problem is None and store.cloud_by_name(name) is not None:
            problem = f"The name {name} is taken."
        return {"available": problem is None, "problem": problem}

    @r.get("/links/{code}")
    async def link_status(code: str):
        normal = links.normalise_code(code)
        row = store.link(normal) if normal else None
        if row is None:
            raise HTTPException(404, "There is no such link code.")
        if row["state"] != "waiting" or row["expires_at"] <= time.time():
            raise HTTPException(410, "That link code has run out or was used.")
        return {"waiting": True, "expires_at": iso(row["expires_at"])}

    @r.post("/links/{code}/approve", status_code=201)
    async def approve(code: str, body: ApproveBody):
        normal = links.normalise_code(code)
        name = checked_name(body.name)
        if normal is None:
            raise HTTPException(410, "That link code has run out or was never given.")
        try:
            cloud = store.approve_link(normal, name, body.account)
        except LinkGone:
            raise HTTPException(410, "That link code has run out or was never given.") from None
        except NameTaken:
            raise HTTPException(409, f"The name {name} is taken.") from None
        log.info("cloud %s linked as %s", cloud.id, name)
        # Clears anything a previous owner of the name left in DNS.
        await svc.dns_changed([name])
        return entry(cloud)

    @r.post("/links/{code}/refuse", status_code=204)
    async def refuse(code: str):
        normal = links.normalise_code(code)
        if normal is None or not store.refuse_link(normal):
            raise HTTPException(410, "That link code has run out or was never given.")
        return Response(status_code=204)

    # --- an account's clouds ---------------------------------------------------

    @r.get("/accounts/{account}/clouds")
    async def clouds_of(account: str):
        return [entry(c) for c in store.clouds_of(account)]

    @r.patch("/clouds/{cloud_id}")
    async def patch(cloud_id: str, body: PatchBody):
        cloud = owned(cloud_id, body.account)
        if body.name is not None:
            name = normalise_name(body.name)
            if name != cloud.name:
                name = checked_name(name)
                try:
                    store.rename(cloud.id, name)
                except NameTaken:
                    raise HTTPException(409, f"The name {name} is taken.") from None
                log.info("cloud %s renamed to %s", cloud.id, name)
                svc.meshwatch.write_records()
                await svc.dns_changed([cloud.name, name])
        changes: dict = {}
        if body.display_name is not None:
            changes["display_name"] = " ".join(body.display_name.split()) or None
        if body.show_name is not None:
            changes["show_name"] = body.show_name
        if body.show_logo is not None:
            changes["show_logo"] = body.show_logo
        if changes:
            store.set_landing(cloud.id, **changes)
        return entry(store.cloud(cloud.id))

    @r.put("/clouds/{cloud_id}/logo", status_code=204)
    async def put_logo(
        cloud_id: str, request: Request, account: str = Query(max_length=ACCOUNT_MAX),
        content_type: str = Header(default=""),
    ):
        cloud = owned(cloud_id, account)
        data = await request.body()
        try:
            kind = logos.check(content_type, data)
        except logos.LogoError as exc:
            raise HTTPException(422, str(exc)) from None
        store.set_logo(cloud.id, kind, data)
        return Response(status_code=204)

    @r.get("/clouds/{cloud_id}/logo")
    async def get_logo(cloud_id: str, account: str = Query(max_length=ACCOUNT_MAX)):
        # For My Clouds' preview, whether or not the offline page shows it.
        found = store.logo(owned(cloud_id, account).id)
        if found is None:
            raise HTTPException(404, "This cloud has no logo.")
        return Response(found[1], media_type=found[0], headers=landing.LOGO_HEADERS)

    @r.delete("/clouds/{cloud_id}/logo", status_code=204)
    async def delete_logo(cloud_id: str, account: str = Query(max_length=ACCOUNT_MAX)):
        cloud = owned(cloud_id, account)
        store.delete_logo(cloud.id)
        return Response(status_code=204)

    @r.post("/clouds/{cloud_id}/invites", status_code=201)
    async def invite(cloud_id: str, body: AccountBody):
        cloud = owned(cloud_id, body.account)
        if svc.headscale is None:
            raise HTTPException(503, "The mesh is not set up on this relay.")
        # One allowance per cloud, whether the box or the website asks.
        if not svc.pair_codes.allow(cloud.id):
            raise HTTPException(429, "Too many invites this hour. Try again later.")
        code, expires = pairing.issue_code(store, cloud.id)
        log.info("invite made on the website for cloud %s", cloud.id)
        return {"code": code, "expires_at": iso(expires), "login_server": cfg.login_server}

    @r.delete("/clouds/{cloud_id}", status_code=204)
    async def unlink(cloud_id: str, account: str = Query(max_length=ACCOUNT_MAX)):
        cloud = owned(cloud_id, account)
        try:
            await svc.unlink(cloud)
        except HeadscaleError as exc:
            log.warning("Headscale failed while unlinking %s: %s (status %s)", cloud.id, exc, exc.status)
            raise HTTPException(502, "The coordination server did not answer. Try again.") from None
        return Response(status_code=204)

    return r
