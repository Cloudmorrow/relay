"""A stand-in for Cloudflare's DNS API (v4), just the calls the relay makes,
kept in memory. The tests never talk to the real one.
"""

from __future__ import annotations

import itertools

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


class FakeCloudflare:
    def __init__(self, token: str, zone: str):
        self.token = token
        self.zone = zone
        self.zone_id = "zone0123"
        self.records: dict[str, dict] = {}
        self.fail = False
        self.calls: list[tuple[str, str]] = []
        self._ids = itertools.count(1)
        self.app = self._build()

    def add(self, rtype: str, name: str, content: str, comment: str = "") -> dict:
        rec = {"id": f"rec{next(self._ids)}", "type": rtype, "name": name, "content": content,
               "ttl": 1, "proxied": False, "comment": comment or None}
        self.records[rec["id"]] = rec
        return rec

    def find(self, name: str, rtype: str | None = None) -> list[dict]:
        return [r for r in self.records.values() if r["name"] == name and (rtype is None or r["type"] == rtype)]

    def _build(self) -> FastAPI:
        app = FastAPI()
        fake = self

        def ok(result, **extra):
            return {"success": True, "errors": [], "messages": [], "result": result, **extra}

        def err(status, message):
            return JSONResponse({"success": False, "errors": [{"code": 1000, "message": message}]}, status)

        @app.middleware("http")
        async def auth(request: Request, call_next):
            fake.calls.append((request.method, request.url.path))
            if request.headers.get("authorization") != f"Bearer {fake.token}":
                return err(403, "Invalid API token")
            if fake.fail:
                return err(500, "internal error")
            return await call_next(request)

        @app.get("/client/v4/zones")
        async def zones(name: str = ""):
            return ok([{"id": fake.zone_id, "name": fake.zone}] if name == fake.zone else [])

        @app.get("/client/v4/zones/{zid}/dns_records")
        async def records(zid: str, name: str | None = None, page: int = 1, per_page: int = 100):
            found = [r for r in fake.records.values() if name is None or r["name"] == name]
            per_page = min(per_page, 3)  # small pages, so paging is exercised
            pages = max(1, -(-len(found) // per_page))
            chunk = found[(page - 1) * per_page : page * per_page]
            return ok(chunk, result_info={"page": page, "per_page": per_page, "total_pages": pages, "total_count": len(found)})

        @app.post("/client/v4/zones/{zid}/dns_records")
        async def create(zid: str, body: dict):
            if body["type"] == "TXT" and not body["content"].startswith('"'):
                return err(400, "TXT content should be quoted")
            rec = fake.add(body["type"], body["name"], body["content"], body.get("comment") or "")
            rec["ttl"] = body.get("ttl", 1)
            return ok(rec)

        @app.delete("/client/v4/zones/{zid}/dns_records/{rid}")
        async def delete(zid: str, rid: str):
            if fake.records.pop(rid, None) is None:
                return err(404, "Record does not exist")
            return ok({"id": rid})

        return app
