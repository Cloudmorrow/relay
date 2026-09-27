"""The control API (`/v1`), as HOSTING.md lays it out.

A box claims a name once and gets a token; after that every call is
`Authorization: Bearer <token>` and acts on that cloud only (`/me`). The
answers are JSON; errors are `{"detail": "<a plain sentence>"}` — the core
shows them to people, so they read as sentences, not codes.

Status codes, where the contract leaves them open: a create answers 201
(`POST /v1/clouds`, `…/mesh/keys`, `…/mesh/pair`, `/v1/acme-dns/register`,
as acme-dns itself does), a delete 204 with no body, everything else 200.
401 for a missing or wrong token, 404 for what is not there, 409 for a name
that is taken, 413 for a body over the cap, 422 for a request that does not
make sense (a bad name, a reserved one, a malformed field), 429 when a
limit is reached, 502 when Headscale did not answer, 503 when private
access is not configured on this relay at all.

The same app serves the pairing pages for the login host (pairing.py) and,
on port 80, the files certbot puts in the ACME webroot for the relay's own
certificate.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import unicodedata
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, ConfigDict, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import pairing
from .headscale import HeadscaleError, device
from .store import Cloud, NameTaken

log = logging.getLogger("cloudmorrow_relay.control")

NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,38})[a-z0-9]$")
ACME_TXT_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
LABEL_MAX = 64
DRAIN_MAX = 1024 * 1024


# --- names ---------------------------------------------------------------


def normalise_name(value: str) -> str:
    """What a person typed, as the name it would become: compatibility
    forms folded (a full-width "Ｌ" is an "l"), outer space dropped, lower
    case. Nothing else is changed; the rules below then accept or refuse.
    """
    return unicodedata.normalize("NFKC", value or "").strip().lower()


def name_problem(name: str, reserved: frozenset[str]) -> str | None:
    if not 3 <= len(name) <= 40:
        return "A name is 3 to 40 characters long."
    if not NAME_RE.match(name):
        return "A name is made of a-z, 0-9 and hyphens, and starts and ends with a letter or digit."
    if "--" in name:
        return "A name cannot have two hyphens in a row."
    if name in reserved:
        return f"The name {name} is reserved."
    return None


# --- request bodies ------------------------------------------------------


class Strict(BaseModel):
    model_config = ConfigDict(extra="ignore")


class ClaimBody(Strict):
    name: str = Field(max_length=200)


class PatchBody(Strict):
    name: str | None = Field(default=None, max_length=200)
    public: bool | None = None


class KeyBody(Strict):
    ephemeral: bool = False
    expires_in: int = Field(default=3600, ge=60, le=30 * 24 * 3600)
    for_: str = Field(default="", alias="for", max_length=LABEL_MAX)


class PairBody(Strict):
    for_: str = Field(default="", alias="for", max_length=LABEL_MAX)


class AddressBody(Strict):
    address: str | None = Field(default=None, max_length=64)


class AcmeUpdate(Strict):
    subdomain: str = Field(max_length=64)
    txt: str = Field(max_length=64)


# --- the body cap ----------------------------------------------------------


class BodyCap:
    """Refuse request bodies over a size, whether or not they say their
    length up front. Pure ASGI, so it sits under everything.
    """

    def __init__(self, app, limit: int):
        self.app = app
        self.limit = limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    too_big = int(value) > self.limit
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
            if len(body) > self.limit:
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
            raise HTTPException(503, "Private access is not set up on this relay.")
        return svc.headscale

    def record(cloud: Cloud, devices: list | None = None) -> dict:
        tunnel = svc.registry.get(cloud.id)
        live_in = live_out = 0
        if tunnel is not None:
            done_in, done_out = svc.registry._flushed.get(id(tunnel), (0, 0))
            live_in, live_out = tunnel.bytes_in - done_in, tunnel.bytes_out - done_out
        out = {
            "cloud_id": cloud.id,
            "name": cloud.name,
            "zone": cfg.zone,
            "public_host": cfg.public_host(cloud.name),
            "public": cloud.public,
            "tunnel": {
                "connected": tunnel is not None,
                "connected_since": _iso(tunnel.connected_since) if tunnel else None,
            },
            "bytes_in": cloud.bytes_in + live_in,
            "bytes_out": cloud.bytes_out + live_out,
            "mesh_address": cloud.mesh_address,
            "login_server": cfg.login_server,
        }
        if devices is not None:
            out["devices"] = devices
        return out

    async def devices_of(cloud: Cloud) -> list[dict]:
        nodes = await svc.headscale.list_nodes(cloud.mesh_user)
        labels = store.labels(cloud.id)
        return [device(n, labels) for n in nodes]

    # --- clouds ------------------------------------------------------------

    @app.post("/v1/clouds", status_code=201)
    async def claim(body: ClaimBody, request: Request):
        if not svc.enrol.allow(svc.client_ip(request)):
            raise HTTPException(429, "Too many names claimed from this address. Try again later.")
        name = normalise_name(body.name)
        problem = name_problem(name, cfg.reserved())
        if problem:
            raise HTTPException(422, problem)
        try:
            cloud, token = store.create_cloud(name)
        except NameTaken:
            raise HTTPException(409, f"The name {name} is taken.") from None
        log.info("cloud %s claimed %s", cloud.id, name)
        return {
            "cloud_id": cloud.id,
            "token": token,
            "name": cloud.name,
            "zone": cfg.zone,
            "public_host": cfg.public_host(cloud.name),
            "relay_host": cfg.relay_host,
            "login_server": cfg.login_server,
        }

    @app.get("/v1/clouds/me")
    async def me(cloud: Cloud = Depends(cloud_for)):
        devices: list = []
        if svc.headscale is not None:
            try:
                devices = await devices_of(cloud)
            except HeadscaleError:
                # The record is still worth having without the device list.
                devices = []
        return record(cloud, devices)

    @app.patch("/v1/clouds/me")
    async def patch(body: PatchBody, cloud: Cloud = Depends(cloud_for)):
        if body.name is not None:
            name = normalise_name(body.name)
            if name != cloud.name:
                problem = name_problem(name, cfg.reserved())
                if problem:
                    raise HTTPException(422, problem)
                try:
                    store.rename(cloud.id, name)
                except NameTaken:
                    raise HTTPException(409, f"The name {name} is taken.") from None
                log.info("cloud %s renamed to %s", cloud.id, name)
                tunnel = svc.registry.get(cloud.id)
                if tunnel is not None:
                    tunnel.name = name
        if body.public is not None and body.public != cloud.public:
            store.set_public(cloud.id, body.public)
            if not body.public:
                await svc.registry.drop(cloud.id)
        svc.update_mesh_records()
        return record(store.cloud(cloud.id))

    @app.delete("/v1/clouds/me", status_code=204)
    async def delete(cloud: Cloud = Depends(cloud_for)):
        if svc.headscale is not None:
            try:
                await svc.headscale.delete_user(cloud.mesh_user)
            except HeadscaleError:
                # Keep the cloud rather than leave devices behind in a user
                # nobody can reach any more.
                raise HTTPException(502, "The coordination server did not answer. Try again.") from None
        await svc.registry.drop(cloud.id)
        store.delete_cloud(cloud.id)
        svc.update_mesh_records()
        log.info("cloud %s gave its name back", cloud.id)
        return Response(status_code=204)

    # --- the mesh ----------------------------------------------------------

    @app.post("/v1/clouds/me/mesh/keys", status_code=201)
    async def mesh_key(body: KeyBody | None = None, cloud: Cloud = Depends(cloud_for)):
        body = body or KeyBody()
        hs = need_headscale()
        if not svc.mesh_keys.allow(cloud.id):
            raise HTTPException(429, "Too many keys this hour. Try again later.")
        try:
            key = await hs.create_key(cloud.mesh_user, ephemeral=body.ephemeral, expires_in=body.expires_in)
        except HeadscaleError:
            raise HTTPException(502, "The coordination server did not answer. Try again.") from None
        store.set_label("key", str(key.get("id")), cloud.id, body.for_.strip())
        return {"key": key["key"], "login_server": cfg.login_server, "expires_at": key.get("expiration")}

    @app.post("/v1/clouds/me/mesh/pair", status_code=201)
    async def mesh_pair(body: PairBody | None = None, cloud: Cloud = Depends(cloud_for)):
        body = body or PairBody()
        need_headscale()
        if not svc.pair_codes.allow(cloud.id):
            raise HTTPException(429, "Too many pairing codes this hour. Try again later.")
        code, expires = pairing.issue_code(store, cloud.id, body.for_.strip())
        return {"code": code, "expires_at": _iso(expires), "login_server": cfg.login_server}

    @app.get("/v1/clouds/me/mesh/devices")
    async def mesh_devices(cloud: Cloud = Depends(cloud_for)):
        need_headscale()
        try:
            return {"devices": await devices_of(cloud)}
        except HeadscaleError:
            raise HTTPException(502, "The coordination server did not answer. Try again.") from None

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
            raise HTTPException(502, "The coordination server did not answer. Try again.") from None
        store.drop_label("node", node_id)
        return Response(status_code=204)

    @app.put("/v1/clouds/me/mesh/address")
    async def mesh_address(body: AddressBody, cloud: Cloud = Depends(cloud_for)):
        address = None
        if body.address:
            try:
                ip = ipaddress.ip_address(body.address.strip())
            except ValueError:
                raise HTTPException(422, "address: that is not an IP address.") from None
            # Only a mesh address: the name must not become a way to point
            # a name in our zone at any machine on the internet.
            if not any(ip in ipaddress.ip_network(p) for p in cfg.mesh_prefixes):
                raise HTTPException(422, "address: that is not a mesh address.")
            if svc.headscale is not None:
                try:
                    nodes = await svc.headscale.list_nodes(cloud.mesh_user)
                except HeadscaleError:
                    nodes = None
                if nodes is not None and not any(str(ip) in n.get("ipAddresses", []) for n in nodes):
                    raise HTTPException(422, "address: no device of this cloud has that address.")
            address = str(ip)
        store.set_mesh_address(cloud.id, address)
        svc.update_mesh_records()
        return {"address": address}

    # --- acme-dns ------------------------------------------------------------

    @app.post("/v1/acme-dns/register", status_code=201)
    async def acme_register(cloud: Cloud = Depends(cloud_for)):
        user, password, subdomain = store.acme_register(cloud.id)
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

    return BodyCap(app, cfg.limits.body_max_bytes)


def _iso(ts: float) -> str:
    import datetime as dt

    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
