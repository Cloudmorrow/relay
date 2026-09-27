"""A stand-in for Headscale, for dev mode and the tests.

It answers the handful of REST calls the relay makes (users, pre-auth
keys, nodes, registration, policy) the way Headscale 0.29 does, keeps
everything in memory, and has two extra doors a real one does not:
`POST /fake/join` (a device joining with a pre-auth key, which in real
life `tailscale up` does) and `POST /fake/pending` (a phone that opened
the register URL and is waiting). Nothing about WireGuard is faked; the
point is the relay's side of the conversation.
"""

from __future__ import annotations

import datetime as dt
import itertools
import secrets

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse

POLICY = '{"acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"]}]}'


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class FakeHeadscale:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.users: dict[str, dict] = {}
        self.keys: dict[str, dict] = {}
        self.nodes: dict[str, dict] = {}
        self.pending: set[str] = set()
        self.policy = POLICY
        self._ids = itertools.count(1)
        self._ips = itertools.count(1)
        self.app = self._build()

    def user_by_name(self, name: str) -> dict | None:
        return next((u for u in self.users.values() if u["name"] == name), None)

    def _node(self, user: dict, hostname: str, key: dict | None) -> dict:
        n = next(self._ips)
        node = {
            "id": str(next(self._ids)),
            "name": hostname,
            "givenName": hostname,
            "user": user,
            "ipAddresses": [f"100.64.{n // 250}.{n % 250 + 1}", f"fd7a:115c:a1e0::{n:x}"],
            "online": True,
            "lastSeen": _now(),
            "createdAt": _now(),
            "preAuthKey": key,
        }
        self.nodes[node["id"]] = node
        return node

    def _build(self) -> FastAPI:
        app = FastAPI()
        fake = self

        @app.middleware("http")
        async def auth(request: Request, call_next):
            if request.url.path.startswith("/api/"):
                if request.headers.get("authorization") != f"Bearer {fake.api_key}":
                    return JSONResponse({"code": 16, "message": "Unauthorized"}, 401)
            return await call_next(request)

        def err(status: int, message: str):
            return JSONResponse({"code": 5, "message": message, "details": []}, status)

        @app.get("/api/v1/user")
        async def users(name: str | None = None):
            found = [u for u in fake.users.values() if name is None or u["name"] == name]
            return {"users": found}

        @app.post("/api/v1/user")
        async def create_user(body: dict):
            if fake.user_by_name(body["name"]):
                return err(400, "user already exists")
            user = {"id": str(next(fake._ids)), "name": body["name"], "createdAt": _now()}
            fake.users[user["id"]] = user
            return {"user": user}

        @app.delete("/api/v1/user/{uid}")
        async def delete_user(uid: str):
            if uid not in fake.users:
                return err(404, "user not found")
            if any(n["user"]["id"] == uid for n in fake.nodes.values()):
                return err(400, "user has nodes")
            del fake.users[uid]
            return {}

        @app.post("/api/v1/preauthkey")
        async def create_key(body: dict):
            user = fake.users.get(str(body.get("user")))
            if user is None:
                return err(400, "user not found")
            key = {
                "id": str(next(fake._ids)),
                "key": "hskey-auth-" + secrets.token_hex(12),
                "user": user,
                "reusable": body.get("reusable", False),
                "ephemeral": body.get("ephemeral", False),
                "used": False,
                "expiration": body.get("expiration"),
                "createdAt": _now(),
                "aclTags": [],
            }
            fake.keys[key["id"]] = key
            return {"preAuthKey": key}

        @app.get("/api/v1/preauthkey")
        async def list_keys():
            return {"preAuthKeys": list(fake.keys.values())}

        @app.delete("/api/v1/preauthkey")
        async def delete_key(id: str):
            fake.keys.pop(id, None)
            return {}

        @app.get("/api/v1/node")
        async def list_nodes(user: str | None = None):
            nodes = [n for n in fake.nodes.values() if user is None or n["user"]["name"] == user]
            return {"nodes": nodes}

        @app.get("/api/v1/node/{nid}")
        async def get_node(nid: str):
            if nid not in fake.nodes:
                return err(404, "node not found")
            return {"node": fake.nodes[nid]}

        @app.delete("/api/v1/node/{nid}")
        async def delete_node(nid: str):
            if fake.nodes.pop(nid, None) is None:
                return err(404, "node not found")
            return {}

        @app.post("/api/v1/node/register")
        async def register(user: str, key: str):
            u = fake.user_by_name(user)
            if u is None:
                return err(400, "user not found")
            if key not in fake.pending:
                return err(404, "no pending registration")
            fake.pending.discard(key)
            return {"node": fake._node(u, "phone", None)}

        @app.get("/api/v1/policy")
        async def get_policy():
            return {"policy": fake.policy}

        @app.put("/api/v1/policy")
        async def set_policy(body: dict):
            fake.policy = body["policy"]
            return {"policy": fake.policy}

        # --- the fake's own doors ---------------------------------------

        @app.post("/fake/join")
        async def join(body: dict):
            key = next((k for k in fake.keys.values() if k["key"] == body["key"]), None)
            if key is None or key["used"]:
                raise HTTPException(400, "bad key")
            key["used"] = True
            return {"node": fake._node(key["user"], body.get("hostname", "cloud"), key)}

        @app.post("/fake/pending")
        async def pending():
            auth_id = "hskey-authreq-" + secrets.token_urlsafe(18)  # Headscale's shape
            fake.pending.add(auth_id)
            return {"auth_id": auth_id}

        # --- what Tailscale clients would hit ----------------------------

        @app.get("/health")
        async def health():
            return {"status": "pass"}

        @app.get("/key")
        async def key():
            return PlainTextResponse("fake-headscale-noise-key")

        @app.get("/register/{auth_id}")
        async def headscale_register_page(auth_id: str):
            # Headscale's own page, which the relay must never let a browser see.
            return PlainTextResponse(f"headscale nodes register --key {auth_id}")

        return app
