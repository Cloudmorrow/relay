"""All the parts, started together in one process.

The relay (443 and 80), the control API (behind it, on loopback), and the
DNS server (53, UDP and TCP) share one database and one event loop. One
process is the whole service: a small VPS runs it, a restart restarts all
of it, and the parts never disagree about what a name is.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import socket
from urllib.parse import urlparse

import uvicorn

from . import control
from .dnsbackend import BuiltinDns, DnsBackend, DnsError
from .config import Config
from .headscale import Headscale, write_extra_records
from .acme import Renewer
from .limits import RateLimiter
from .router import CertStore, Router
from .store import Store
from .tunnel import Registry

log = logging.getLogger("cloudmorrow_relay")

FLUSH_EVERY = 60.0


async def start_uvicorn(app, sockets: list[socket.socket] | None = None, **kwargs) -> tuple[uvicorn.Server, asyncio.Task]:
    """Run an ASGI app with uvicorn inside our own event loop. `Server.serve`
    would install its own signal handlers; we want ours (SIGHUP reloads the
    certificate), so this does what it does without them.
    """
    config = uvicorn.Config(
        app, log_level="warning", access_log=False, lifespan="off",
        proxy_headers=False, server_header=False, date_header=False, **kwargs,
    )
    config.load()
    server = uvicorn.Server(config)
    server.lifespan = config.lifespan_class(config)
    await server.startup(sockets=sockets)
    return server, asyncio.create_task(server.main_loop())


class Service:
    def __init__(self, cfg: Config, headscale: Headscale | None = None, dns_transport=None):
        self.cfg = cfg
        self.store = Store(cfg.db_path)
        self.dns: DnsBackend
        if cfg.dns_backend == "cloudflare":
            from .cloudflare import CloudflareDns

            self.dns = CloudflareDns(cfg, self.store, transport=dns_transport)
        else:
            self.dns = BuiltinDns(cfg, self.store)
        self.registry = Registry(on_bytes=self.store.add_bytes)
        self.certs = CertStore(cfg.tls_cert, cfg.tls_key)
        self.renewer = Renewer(cfg, self.certs) if cfg.acme.client == "lego" else None
        lim = cfg.limits
        self.enrol = RateLimiter(lim.enrol_per_hour, 3600)
        self.pair_codes = RateLimiter(lim.pair_codes_per_hour, 3600)
        self.pair_attempts = RateLimiter(lim.pair_attempts_per_10min, 600)
        self.mesh_keys = RateLimiter(lim.mesh_keys_per_hour, 3600)
        self.bad_auth = RateLimiter(lim.bad_auth_per_minute, 60)
        self.headscale = headscale
        api_key = cfg.headscale_api_key
        if not api_key and cfg.headscale_api_key_file:
            api_key = cfg.headscale_api_key_file.read_text().strip()
        if self.headscale is None and cfg.headscale_url and api_key:
            self.headscale = Headscale(cfg.headscale_url, api_key)
        self.headscale_upstream: tuple[str, int] | None = None
        if cfg.headscale_url:
            u = urlparse(cfg.headscale_url)
            self.headscale_upstream = (u.hostname, u.port or (443 if u.scheme == "https" else 80))
        # local port of a relay→control hop → (visitor's address, came in on 80)
        self.peers: dict[int, tuple[str, bool]] = {}
        self.router = Router(self)
        self.control_port = 0
        self.https_port = self.http_port = self.dns_port = 0
        self._servers: list = []
        self._udp: list = []
        self._uvicorn: uvicorn.Server | None = None
        self._uvicorn_task: asyncio.Task | None = None
        self._control_sock: socket.socket | None = None
        self._flush_task: asyncio.Task | None = None

    # --- what the control app asks of us ---------------------------------------

    def client_ip(self, request) -> str:
        client = request.client
        if client is None:
            return "?"
        peer = self.peers.get(client.port) if client.host == "127.0.0.1" else None
        return peer[0] if peer else client.host

    def is_plain(self, request) -> bool:
        client = request.client
        peer = self.peers.get(client.port) if client and client.host == "127.0.0.1" else None
        return bool(peer and peer[1])

    async def dns_changed(self, names: list[str], strict: bool = False) -> bool:
        """Tell the DNS backend these names may need other records. A
        failure is logged and left to the periodic sync, unless `strict`.
        """
        try:
            await self.dns.names_changed(names)
            return True
        except DnsError as exc:
            log.warning("DNS update for %s failed: %s", ", ".join(names), exc)
            return False

    def update_mesh_records(self) -> None:
        """Rewrite Headscale's extra DNS records: each cloud with a mesh
        address has its public name point there, inside the mesh.
        """
        path = self.cfg.extra_records_path
        if path is None:
            return
        records = []
        for cloud in self.store.all_clouds():
            if not cloud.mesh_address:
                continue
            ip = ipaddress.ip_address(cloud.mesh_address)
            records.append({
                "name": self.cfg.public_host(cloud.name),
                "type": "A" if ip.version == 4 else "AAAA",
                "value": str(ip),
            })
        try:
            write_extra_records(path, records)
        except OSError as exc:
            log.warning("could not write %s: %s", path, exc)

    # --- life ---------------------------------------------------------------------

    async def start(self) -> None:
        cfg = self.cfg
        app = control.create_app(self)
        self._control_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._control_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._control_sock.bind(("127.0.0.1", 0))
        self.control_port = self._control_sock.getsockname()[1]
        self._uvicorn, self._uvicorn_task = await start_uvicorn(app, [self._control_sock])

        https, http = await self.router.start(cfg.listen, cfg.https_port, cfg.http_port)
        self.https_port = https.sockets[0].getsockname()[1]
        self.http_port = http.sockets[0].getsockname()[1]
        await self.dns.start()
        self.dns_port = getattr(self.dns, "port", 0)
        self._servers = [https, http]
        self.update_mesh_records()
        self._flush_task = asyncio.create_task(self._flush_loop())
        if self.headscale is not None:
            asyncio.create_task(self._check_headscale())
        if self.renewer is not None:
            self.renewer.start()

    async def _flush_loop(self) -> None:
        while True:
            await asyncio.sleep(FLUSH_EVERY)
            self.registry.flush_all()

    async def _check_headscale(self) -> None:
        try:
            policy = await self.headscale.policy()
        except Exception as exc:
            log.warning("Headscale did not answer at start (%s); private access waits for it", exc)
            return
        if "autogroup:self" not in policy:
            log.warning(
                "Headscale's policy does not limit devices to their own user "
                "(no autogroup:self): clouds' devices could reach each other. "
                "Use deploy/headscale/policy.hujson."
            )

    def reload_certs(self) -> None:
        self.certs.reload()

    async def stop(self) -> None:
        if self._flush_task:
            self._flush_task.cancel()
        if self.renewer is not None:
            await self.renewer.stop()
        for server in self._servers:
            server.close()
        await self.dns.stop()
        for tunnel in list(self.registry.tunnels.values()):
            await tunnel.close()
            self.registry.flush(tunnel)
        for server in self._servers:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(server.wait_closed(), 2)
        if self._uvicorn is not None:
            self._uvicorn.should_exit = True
            with contextlib.suppress(Exception):
                await self._uvicorn_task
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._uvicorn.shutdown(sockets=[self._control_sock]), 3)
        if self.headscale is not None:
            await self.headscale.aclose()
        self.store.close()
