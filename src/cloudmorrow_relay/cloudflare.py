"""The zone at Cloudflare: writing only what the wildcard cannot say.

The zone has `*.<zone>` pointing at this machine (DNS only, not proxied:
the relay must see the visitor's TLS as it is). That one record already
makes every cloud's name (its landing page), the relay host and the login
host resolve. What it cannot say, the relay writes, and only that:

- `_acme-challenge.<name>` TXT, the values a box posts to
  /v1/acme-dns/update (the latest two, as acme-dns keeps);
- `<name>` A/AAAA → the relay's own address, for a cloud that has
  challenge values. The TXT record makes `<name>` an "empty non-terminal",
  and by the DNS rules (RFC 4592) a wildcard does not cover those; an
  explicit record says what the wildcard would have.

A box's mesh address is never published here: devices on the mesh learn
it from Headscale's extra records (meshwatch.py), and everybody else gets
the landing page.

Every record the relay creates carries the comment `cloudmorrow-relay`
(`dns.tag`), and the relay only ever changes or deletes records carrying
it. Records anybody made by hand, the wildcard included, are never touched.

The API token comes from the environment (`CLOUDFLARE_API_TOKEN`), never
from the config file; it needs Zone → DNS → Edit on this one zone.
"""

from __future__ import annotations

import asyncio
import logging
import os

import httpx

from .dnsbackend import DnsBackend, DnsError

log = logging.getLogger("cloudmorrow_relay.cloudflare")

TTL = 60
SYNC_EVERY = 600.0


def _txt(value: str) -> str:
    # Cloudflare wants TXT content quoted, and hands it back that way.
    return f'"{value}"'


def _unquote(value: str) -> str:
    return value[1:-1] if len(value) >= 2 and value[0] == value[-1] == '"' else value


class CloudflareDns(DnsBackend):
    def __init__(self, cfg, store, transport: httpx.AsyncBaseTransport | None = None):
        self.cfg = cfg
        self.store = store
        self.tag = cfg.dns_tag
        token = os.environ.get(cfg.cloudflare_token_env, "")
        if not token:
            raise DnsError(f"dns.backend is cloudflare but ${cfg.cloudflare_token_env} is not set")
        self._http = httpx.AsyncClient(
            base_url=cfg.cloudflare_api_url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=15.0,
            transport=transport,
        )
        self.zone_name = cfg.cloudflare_zone or cfg.zone
        self.zone_id: str | None = None
        self._lock = asyncio.Lock()
        self._sync_task: asyncio.Task | None = None

    # --- the API -------------------------------------------------------------

    async def _call(self, method: str, path: str, **kwargs) -> dict:
        try:
            resp = await self._http.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise DnsError(f"Cloudflare did not answer: {exc.__class__.__name__}") from exc
        try:
            data = resp.json()
        except ValueError:
            data = {}
        if resp.status_code >= 400 or not data.get("success", False):
            errors = "; ".join(e.get("message", "") for e in data.get("errors", [])) or resp.text[:200]
            raise DnsError(f"Cloudflare said {resp.status_code}: {errors}")
        return data

    async def _zone(self) -> str:
        if self.zone_id is None:
            data = await self._call("GET", "/zones", params={"name": self.zone_name})
            if not data.get("result"):
                raise DnsError(f"Cloudflare has no zone {self.zone_name} for this token")
            self.zone_id = data["result"][0]["id"]
        return self.zone_id

    async def _records(self, **params) -> list[dict]:
        """Records of the zone (all pages), ours only."""
        zone = await self._zone()
        out, page = [], 1
        while True:
            data = await self._call(
                "GET", f"/zones/{zone}/dns_records", params={**params, "page": page, "per_page": 500}
            )
            out += data.get("result", [])
            info = data.get("result_info") or {}
            if page >= int(info.get("total_pages", 1) or 1):
                break
            page += 1
        return [r for r in out if r.get("comment") == self.tag]

    # --- what the records should be ------------------------------------------

    def _fqdns(self, name: str) -> tuple[str, str]:
        host = self.cfg.public_host(name)
        return host, f"_acme-challenge.{host}"

    def desired(self, name: str) -> set[tuple[str, str, str]]:
        """(type, fqdn, content) for everything we should have for `name`."""
        cloud = self.store.cloud_by_name(name)
        if cloud is None:
            return set()
        host, challenge = self._fqdns(name)
        txts = self.store.acme_txt(cloud.id)
        want = {("TXT", challenge, _txt(t)) for t in txts}
        if txts:
            if self.cfg.public_ipv4:
                want.add(("A", host, self.cfg.public_ipv4))
            if self.cfg.public_ipv6:
                want.add(("AAAA", host, self.cfg.public_ipv6))
        return want

    async def _apply(self, want: set[tuple[str, str, str]], have: list[dict]) -> None:
        zone = await self._zone()
        seen = set()
        for rec in have:
            key = (rec["type"], rec["name"], rec["content"] if rec["type"] != "TXT" else _txt(_unquote(rec["content"])))
            if key in want and key not in seen:
                seen.add(key)
                continue
            await self._call("DELETE", f"/zones/{zone}/dns_records/{rec['id']}")
        for rtype, fqdn, content in sorted(want - seen):
            await self._call(
                "POST",
                f"/zones/{zone}/dns_records",
                json={
                    "type": rtype, "name": fqdn, "content": content, "ttl": TTL,
                    "proxied": False, "comment": self.tag,
                },
            )

    # --- the interface ---------------------------------------------------------

    async def names_changed(self, names: list[str]) -> None:
        async with self._lock:
            for name in dict.fromkeys(names):
                host, challenge = self._fqdns(name)
                have = await self._records(name=host) + await self._records(name=challenge)
                await self._apply(self.desired(name), have)

    async def sync_all(self) -> None:
        """Every record we own against every cloud: stale ones (a cloud
        deleted while Cloudflare was unreachable) go, missing ones come.
        """
        async with self._lock:
            have = await self._records()
            want: set[tuple[str, str, str]] = set()
            for cloud in self.store.all_clouds():
                want |= self.desired(cloud.name)
            await self._apply(want, have)

    async def start(self) -> None:
        self._sync_task = asyncio.create_task(self._sync_loop())

    async def _sync_loop(self) -> None:
        while True:
            try:
                await self.sync_all()
            except DnsError as exc:
                log.warning("syncing records with Cloudflare: %s", exc)
            await asyncio.sleep(SYNC_EVERY)

    async def stop(self) -> None:
        if self._sync_task:
            self._sync_task.cancel()
        await self._http.aclose()
