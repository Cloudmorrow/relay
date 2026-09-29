"""Invite codes, and pairing a phone with one.

An invite is six characters, made by a cloud (Me → Invite a device), good
once, for ten minutes. It works two ways: a computer's client installer
trades it for a one-time key (`POST /v1/invites/redeem`, control.py), and a
phone types it on the page here.

A phone joins the mesh through Tailscale's own app, pointed at the login
server. The app asks Headscale to register it; Headscale answers with a
URL, `/register/<auth_id>`, and the app opens it in a browser. Headscale's
own page there tells an administrator to run a command. Ours asks for the
invite code instead: the relay routes browsers on the login host here
(router.py), so the person sees this page, types the code, and the relay
registers the phone to that cloud's Headscale user. The code is the only
thing that says which cloud, and guessing is rate limited per address and
per waiting phone.

The pages are deliberately plain HTML with no script, a strict content
security policy, and every value escaped.
"""

from __future__ import annotations

import html
import re
import secrets
import time

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse

# No 0/O, 1/I/L: a code is read off one screen and typed on another.
ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"
CODE_LENGTH = 6
CODE_LIFETIME = 600
AUTH_ID_RE = re.compile(r"^[A-Za-z0-9_:\-]{1,128}$")

HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def new_code() -> str:
    return "".join(secrets.choice(ALPHABET) for _ in range(CODE_LENGTH))


def normalise_code(value: str) -> str | None:
    code = re.sub(r"[\s\-]", "", value or "").upper()
    if len(code) != CODE_LENGTH or any(c not in ALPHABET for c in code):
        return None
    return code


def issue_code(store, cloud_id: str) -> tuple[str, float]:
    expires = time.time() + CODE_LIFETIME
    while True:
        code = new_code()
        if store.add_invite(cloud_id, code, expires):
            return code, expires


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
 body{{font:17px/1.5 system-ui,sans-serif;margin:0;background:#f6f4ef;color:#1d1b16}}
 main{{max-width:26rem;margin:12vh auto;padding:0 1rem}}
 h1{{font-size:1.4rem}} p.err{{color:#a3261b}}
 input{{font:600 1.6rem ui-monospace,monospace;letter-spacing:.3em;text-transform:uppercase;
   width:100%;box-sizing:border-box;padding:.5rem;border:2px solid #1d1b16;border-radius:6px}}
 button{{margin-top:1rem;font:inherit;padding:.6rem 1.2rem;border:0;border-radius:6px;background:#1d1b16;color:#fff}}
 @media (prefers-color-scheme: dark){{body{{background:#16151a;color:#eee}}
   input{{background:#222;color:#eee;border-color:#eee}} button{{background:#eee;color:#16151a}}}}
</style></head>
<body><main>{body}</main></body></html>"""


def page(title: str, body: str, status: int = 200) -> HTMLResponse:
    return HTMLResponse(PAGE.format(title=html.escape(title), body=body), status, headers=HEADERS)


def form(auth_id: str, error: str = "") -> str:
    err = f'<p class="err">{html.escape(error)}</p>' if error else ""
    return f"""<h1>Pair this device</h1>
<p>Ask someone on the cloud for an invite (<b>Me → Invite a device</b>), and type its code.</p>
{err}
<form method="post" action="/register/{html.escape(auth_id)}">
<input name="code" autocomplete="one-time-code" autocapitalize="characters"
 maxlength="9" required autofocus aria-label="Invite code">
<button type="submit">Pair</button>
</form>"""


def router(svc) -> APIRouter:
    r = APIRouter()

    @r.get("/register/{auth_id}", include_in_schema=False)
    async def register_page(auth_id: str):
        if not AUTH_ID_RE.match(auth_id):
            return page("Not found", "<h1>This link is not right.</h1>", 404)
        return page("Pair this device", form(auth_id))

    @r.post("/register/{auth_id}", include_in_schema=False)
    async def register(auth_id: str, request: Request, code: str = Form("")):
        if not AUTH_ID_RE.match(auth_id):
            return page("Not found", "<h1>This link is not right.</h1>", 404)
        ip = svc.client_ip(request)
        if not svc.pair_attempts.allow(f"ip:{ip}") or not svc.pair_attempts.allow(f"reg:{auth_id}"):
            return page(
                "Too many tries",
                form(auth_id, "Too many tries. Wait a few minutes, then ask for a new invite."),
                429,
            )
        normal = normalise_code(code)
        cloud = svc.store.claim_invite(normal) if normal else None
        if cloud is None:
            return page(
                "Pair this device",
                form(auth_id, "That code did not work. Invites work once, for ten minutes."),
                400,
            )
        if svc.headscale is None:
            svc.store.release_invite(normal)
            return page("Not available", "<h1>The mesh is not set up on this server.</h1>", 503)
        try:
            await svc.headscale.register_node(cloud.mesh_user, auth_id)
        except Exception as exc:  # HeadscaleError, or anything on the way
            svc.store.release_invite(normal)
            status = getattr(exc, "status", None)
            if status and 400 <= status < 500:
                message = (
                    "This device's sign-in request has expired or is unknown. "
                    "Start again from the Tailscale app; your code still works."
                )
            else:
                message = "The coordination server did not answer. Try again in a minute."
            return page("Pair this device", form(auth_id, message), 502)
        host = html.escape(svc.cfg.public_host(cloud.name))
        return page(
            "Paired",
            f"<h1>Paired</h1><p>This device is now part of <b>{host}</b>. "
            "Go back to the Tailscale app; it connects on its own.</p>",
        )

    @r.get("/", include_in_schema=False)
    async def home():
        return page(
            "Cloudmorrow",
            "<h1>Cloudmorrow</h1><p>This server connects clouds and the devices "
            "their people enroll. There is nothing to see here in a browser.</p>",
        )

    return r
