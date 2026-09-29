"""The control API (`/v1`), as HOSTING.md lays it out.

A box gets its token by linking (links.py): the website approves its link
code, and the box collects the token once. After that every call is
`Authorization: Bearer <token>` and acts on that cloud only (`/me`). The
answers are JSON; errors are `{"detail": "<a plain sentence>"}` — the core
shows them to people, so they read as sentences, not codes.

Status codes, where the contract leaves them open: a create answers 201
(`/v1/links`, `…/mesh/keys`, `…/mesh/invites`, `/v1/invites/redeem`,
`/v1/acme-dns/register`, as acme-dns itself does), a delete 204 with no
body, everything else 200. 401 for a missing or wrong token, 404 for what
is not there, 409 for a name that is taken, 410 for a link code that is
gone, 413 for a body over the cap, 422 for a request that does not make
sense (a bad name, a reserved one, a malformed field), 429 when a limit is
reached, 502 when Headscale did not answer, 503 when the mesh is not
configured on this relay at all.

The same app serves the admin API for the website (admin.py), the pairing
pages for the login host (pairing.py) and, on port 80, the files lego or
certbot put in the ACME webroot for the relay's own certificate.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, ConfigDict, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import admin, links, logos, pairing
from .headscale import BOX_HOSTNAME, HeadscaleError, box_node, device
from .names import name_problem, normalise_name
from .store import Cloud, NameTaken, iso

log = logging.getLogger("cloudmorrow_relay.control")

ACME_TXT_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
DRAIN_MAX = 1024 * 1024
INVITE_KEY_LIFETIME = 3600


# --- request bodies ------------------------------------------------------


class Strict(BaseModel):
    # Unknown fields are ignored: an older box's `for` label on a key or
    # an invite is dropped here, never stored.
    model_config = ConfigDict(extra="ignore")


class ClaimBody(Strict):
    name: str = Field(max_length=200)


class KeyBody(Strict):
    ephemeral: bool = False
    expires_in: int = Field(default=3600, ge=60, le=30 * 24 * 3600)


class RedeemBody(Strict):
    name: str = Field(max_length=200)
    code: str = Field(max_length=32)


class AddressBody(Strict):
    address: str | None = Field(default=None, max_length=64)


class AcmeUpdate(Strict):
    subdomain: str = Field(max_length=64)
    txt: str = Field(max_length=64)


# --- the body cap ----------------------------------------------------------


class BodyCap:
    """Refuse request bodies over a size, whether or not they say their
    length up front. Pure ASGI, so it sits under everything. A logo is the
    one body allowed to be bigger (`big`, for paths ending in `/logo`).
    """

    def __init__(self, app, limit: int, big: int = 0):
        self.app = app
        self.small = limit
        self.big = max(big, limit)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        limit = self.big if scope.get("path", "").endswith("/logo") else self.small
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    too_big = int(value) > limit
                except ValueError:
                    too_big = True
                if too_big:
                    return await _too_large(send)
        # Read the whole body here, up to the cap, and replay it: bodies
        # are small, and a streamed one that runs over is refused before
        # any route sees a byte of it.
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] != "http.request":
                return
            body += message.get("body", b"")
            if len(body) > limit:
                # Swallow a little more, so an honest client that is still
                # sending sees the 413 rather than a reset connection.
                drained = 0
                while message.get("more_body") and drained < DRAIN_MAX:
                    message = await receive()
                    drained += len(message.get("body", b""))
                return await _too_large(send)
            if not message.get("more_body"):
                break
        replayed = False

        async def replay():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


async def _too_large(send) -> None:
    body = b'{"detail":"The request body is too large."}'
    await send({"type": "http.response.start", "status": 413,
                "headers": [(b"content-type", b"application/json"), (b"connection", b"close")]})
    await send({"type": "http.response.body", "body": body})


# --- the app -------------------------------------------------------------


def create_app(svc) -> FastAPI:
    cfg = svc.cfg
    store = svc.store
    app = FastAPI(title="Cloudmorrow relay", docs_url=None, redoc_url=None, openapi_url=None)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        detail = exc.detail if isinstance(exc.detail, str) else "Something went wrong."
        if exc.status_code == 404 and detail == "Not Found":
            detail = "There is nothing here."
        if exc.status_code == 405:
            detail = "That method is not allowed here."
        return JSONResponse({"detail": detail}, exc.status_code, headers=getattr(exc, "headers", None))

    @app.exception_handler(RequestValidationError)
    async def invalid(request: Request, exc: RequestValidationError):
        errors = exc.errors()
        if errors:
            first = errors[0]
            where = ".".join(str(p) for p in first.get("loc", []) if p not in ("body",))
            if first.get("type") == "json_invalid":
                sentence = "The request body is not valid JSON."
            elif where:
                sentence = f"{where}: {first.get('msg', 'is not valid')}."
            else:
                sentence = f"{first.get('msg', 'The request is not valid')}."
        else:
            sentence = "The request is not valid."
        return JSONResponse({"detail": sentence}, 422)

    def cloud_for(request: Request, authorization: str | None = Header(default=None)) -> Cloud:
        ip = svc.client_ip(request)
        if svc.bad_auth.blocked(ip):
            raise HTTPException(429, "Too many failed attempts. Wait a minute.")
        token = ""
        if authorization and authorization[:7].lower() == "bearer ":
            token = authorization[7:].strip()
        cloud = store.cloud_by_token(token) if token else None
        if cloud is None:
            svc.bad_auth.hit(ip)
            raise HTTPException(401, "A valid token is required.", headers={"WWW-Authenticate": "Bearer"})
        return cloud

    def need_headscale():
        if svc.headscale is None:
            raise HTTPException(503, "The mesh is not set up on this relay.")
        return svc.headscale

    def unanswered() -> HTTPException:
        return HTTPException(502, "The coordination server did not answer. Try again.")

    # --- clouds ------------------------------------------------------------

    @app.post("/v1/clouds", status_code=201)
    async def claim(body: ClaimBody, request: Request):
        # Only on a relay that lets anybody take a name (a self-hosted one
        # with no website); otherwise names come through linking.
        if not cfg.open_claims:
            raise HTTPException(403, "This relay gives out names through linking only. Ask for a link code.")
        if not svc.enrol.allow(svc.client_ip(request)):
            raise HTTPException(429, "Too many names claimed from this address. Try again later.")
        name = normalise_name(body.name)
        problem = name_problem(name, cfg.reserved())
        if problem:
            raise HTTPException(422, problem)
        try:
            cloud, _ = store.create_cloud(name)
        except NameTaken:
            raise HTTPException(409, f"The name {name} is taken.") from None
        log.info("cloud %s claimed %s", cloud.id, name)
        # Clears anything a previous owner of the name left in DNS.
        await svc.dns_changed([name])
        return links.handover(svc, cloud)

    @app.get("/v1/clouds/me")
    async def me(cloud: Cloud = Depends(cloud_for)):
        return {
            "cloud_id": cloud.id,
            "name": cloud.name,
            "zone": cfg.zone,
            "mesh_address": cloud.mesh_address,
            "login_server": cfg.login_server,
        }

    @app.delete("/v1/clouds/me", status_code=204)
    async def delete(cloud: Cloud = Depends(cloud_for)):
        try:
            await svc.unlink(cloud)
        except HeadscaleError:
            # Keep the cloud rather than leave devices behind in a user
            # nobody can reach any more.
            raise unanswered() from None
        return Response(status_code=204)

    # --- the mesh ----------------------------------------------------------

    @app.post("/v1/clouds/me/mesh/keys", status_code=201)
    async def mesh_key(body: KeyBody | None = None, cloud: Cloud = Depends(cloud_for)):
        body = body or KeyBody()
        hs = need_headscale()
        if not svc.mesh_keys.allow(cloud.id):
            raise HTTPException(429, "Too many keys this hour. Try again later.")
        try:
            nodes = await hs.list_nodes(cloud.mesh_user)
            key = await hs.create_key(cloud.mesh_user, ephemeral=body.ephemeral, expires_in=body.expires_in)
        except HeadscaleError:
            raise unanswered() from None
        # The hostname a node joining with this key would be expected to
        # take: the box's own, while the cloud has no box on the mesh.
        hint = BOX_HOSTNAME if box_node(nodes, cloud.mesh_user) is None else None
        return {
            "key": key["key"],
            "login_server": cfg.login_server,
            "expires_at": key.get("expiration"),
            "node_hint": hint,
        }

    async def invite(cloud: Cloud = Depends(cloud_for)):
        need_headscale()
        if not svc.pair_codes.allow(cloud.id):
            raise HTTPException(429, "Too many invites this hour. Try again later.")
        code, expires = pairing.issue_code(store, cloud.id)
        return {"code": code, "expires_at": iso(expires), "login_server": cfg.login_server}

    app.post("/v1/clouds/me/mesh/invites", status_code=201)(invite)
    # The name older boxes know it by.
    app.post("/v1/clouds/me/mesh/pair", status_code=201, include_in_schema=False)(invite)

    @app.post("/v1/invites/redeem", status_code=201)
    async def redeem(body: RedeemBody, request: Request):
        hs = need_headscale()
        ip = svc.client_ip(request)
        name = normalise_name(body.name)
        if not svc.pair_attempts.allow(f"ip:{ip}") or not svc.redeems.allow(f"name:{name}"):
            raise HTTPException(429, "Too many tries. Wait a few minutes, then ask for a new invite.")
        cloud = store.cloud_by_name(name)
        code = pairing.normalise_code(body.code)
        claimed = store.claim_invite(code, cloud.id) if (cloud and code) else None
        if claimed is None:
            raise HTTPException(404, "That invite did not work. Invites work once, for ten minutes.")
        try:
            key = await hs.create_key(claimed.mesh_user, ephemeral=False, expires_in=INVITE_KEY_LIFETIME)
        except HeadscaleError:
            store.release_invite(code)
            raise unanswered() from None
        return {"key": key["key"], "login_server": cfg.login_server, "expires_at": key.get("expiration")}

    @app.get("/v1/clouds/me/mesh/devices")
    async def mesh_devices(cloud: Cloud = Depends(cloud_for)):
        hs = need_headscale()
        try:
            nodes = await hs.list_nodes(cloud.mesh_user)
        except HeadscaleError:
            raise unanswered() from None
        return {"devices": [device(n) for n in nodes]}

    @app.delete("/v1/clouds/me/mesh/devices/{node_id}", status_code=204)
    async def mesh_remove(node_id: str, cloud: Cloud = Depends(cloud_for)):
        hs = need_headscale()
        try:
            nodes = await hs.list_nodes(cloud.mesh_user)
            # Only ever a node of this cloud's own user.
            if not any(str(n["id"]) == node_id for n in nodes):
                raise HTTPException(404, "There is no such device in this cloud.")
            await hs.delete_node(node_id)
        except HeadscaleError:
            raise unanswered() from None
        svc.meshwatch.poke()
        return Response(status_code=204)

    @app.put("/v1/clouds/me/mesh/address", include_in_schema=False)
    async def mesh_address(body: AddressBody | None = None, cloud: Cloud = Depends(cloud_for)):
        # Older boxes report their mesh address here. The relay reads it
        # from Headscale itself now; the call only makes it look sooner.
        svc.meshwatch.poke()
        return {"address": body.address if body else None}

    # --- acme-dns ------------------------------------------------------------

    @app.post("/v1/acme-dns/register", status_code=201)
    async def acme_register(cloud: Cloud = Depends(cloud_for)):
        return links.acme_dns(svc, cloud)

    @app.post("/v1/acme-dns/update")
    async def acme_update(
        body: AcmeUpdate,
        request: Request,
        x_api_user: str = Header(default=""),
        x_api_key: str = Header(default=""),
    ):
        ip = svc.client_ip(request)
        if svc.bad_auth.blocked(ip):
            raise HTTPException(429, "Too many failed attempts. Wait a minute.")
        cloud = store.acme_check(x_api_user, x_api_key) if x_api_user and x_api_key else None
        if cloud is None:
            svc.bad_auth.hit(ip)
            raise HTTPException(401, "Those acme-dns credentials are not right.")
        if body.subdomain != cloud.acme_subdomain:
            raise HTTPException(401, "That subdomain belongs to other credentials.")
        if not ACME_TXT_RE.match(body.txt):
            raise HTTPException(400, "txt: an ACME challenge value is 43 base64url characters.")
        store.acme_set_txt(cloud.id, body.txt)
        # The one change that must be in DNS before we answer: the box's
        # ACME client asks Let's Encrypt to look right after.
        if not await svc.dns_changed([cloud.name], strict=True):
            raise HTTPException(502, "The DNS provider did not take the record. Try again.")
        return {"txt": body.txt}

    # --- the relay's own certificate (port 80) --------------------------------

    @app.get("/.well-known/acme-challenge/{token}", include_in_schema=False)
    async def acme_challenge(token: str):
        root: Path | None = cfg.acme_webroot
        if root is None or not re.match(r"^[A-Za-z0-9_-]{1,256}$", token):
            raise HTTPException(404, "There is nothing here.")
        path = root / ".well-known" / "acme-challenge" / token
        if not path.is_file():
            raise HTTPException(404, "There is nothing here.")
        return FileResponse(path, media_type="text/plain")

    app.include_router(links.router(svc))
    app.include_router(admin.router(svc))
    app.include_router(pairing.router(svc))

    @app.middleware("http")
    async def https_only(request: Request, call_next):
        # Port 80 reaches this app only for the relay's own names; apart
        # from the ACME challenge, everything there moves to https.
        if svc.is_plain(request) and not request.url.path.startswith("/.well-known/acme-challenge/"):
            host = (request.headers.get("host") or "").split(":")[0].lower()
            if host not in (cfg.relay_host, cfg.login_host):
                host = cfg.relay_host
            port = cfg.advertised_https_port or cfg.https_port
            suffix = "" if port == 443 else f":{port}"
            return RedirectResponse(f"https://{host}{suffix}{request.url.path}", 308)
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Cache-Control", "no-store")
        return response

    return BodyCap(app, cfg.limits.body_max_bytes, big=logos.MAX_BYTES + 1024)
