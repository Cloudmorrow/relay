"""All the parts, started together in one process.

The relay (443 and 80), the control API and the landing page (behind it,
on loopback), the DNS server (53, UDP and TCP), and the watch on the boxes
through Headscale share one database and one event loop. One process is
the whole service: a small VPS runs it, a restart restarts all of it, and
the parts never disagree about what a name is.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import socket
from urllib.parse import urlparse

import uvicorn

from . import control, landing
from .acme import Renewer
from .config import Config, ConfigError
from .dnsbackend import BuiltinDns, DnsBackend, DnsError
from .headscale import Headscale
from .limits import RateLimiter
from .meshwatch import MeshWatch
from .router import CertStore, Router
from .store import Cloud, Store

log = logging.getLogger("cloudmorrow_relay")

# An admin secret shorter than this is a mistake, not a secret.
ADMIN_SECRET_MIN = 24


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


def by_port(apps: dict[int, object], default):
    """One ASGI app in front of several, picked by the local port the
    connection came in on.
    """

    async def app(scope, receive, send):
        server = scope.get("server") or (None, None)
        return await apps.get(server[1], default)(scope, receive, send)

    return app


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
        self.certs = CertStore(cfg.tls_cert, cfg.tls_key)
        self.renewer = Renewer(cfg, self.certs) if cfg.acme.client == "lego" else None
        lim = cfg.limits
        self.enrol = RateLimiter(lim.enrol_per_hour, 3600)
        self.links = RateLimiter(lim.links_per_hour, 3600)
        self.pair_codes = RateLimiter(lim.pair_codes_per_hour, 3600)
        self.pair_attempts = RateLimiter(lim.pair_attempts_per_10min, 600)
        self.redeems = RateLimiter(lim.redeems_per_name_10min, 600)
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
        self.admin_secret = self._admin_secret()
        # local port of a relay→app hop → (visitor's address, came in on
        # 80, the name it asked for)
        self.peers: dict[int, tuple[str, bool, str]] = {}
        self.router = Router(self)
        self.meshwatch = MeshWatch(self)
        self.control_port = self.landing_port = 0
        self.https_port = self.http_port = self.dns_port = 0
        self._servers: list = []
        self._udp: list = []
        self._uvicorn: uvicorn.Server | None = None
        self._uvicorn_task: asyncio.Task | None = None
        self._sockets: list[socket.socket] = []

    def _admin_secret(self) -> str | None:
        cfg = self.cfg
        secret = os.environ.get(cfg.admin_secret_env, "").strip()
        if not secret and cfg.admin_secret_file is not None:
            secret = cfg.admin_secret_file.read_text().strip()
        if not secret:
            log.info("no admin secret (%s): the admin API is off", cfg.admin_secret_env)
            return None
        if len(secret) < ADMIN_SECRET_MIN:
            raise ConfigError(f"the admin secret is shorter than {ADMIN_SECRET_MIN} characters")
        return secret

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

    def entry_name(self, request) -> str | None:
        """The name the visitor asked the relay for (SNI, or Host on 80),
        rather than whatever Host header came after it.
        """
        client = request.client
        peer = self.peers.get(client.port) if client and client.host == "127.0.0.1" else None
        if peer:
            return peer[2]
        return (request.headers.get("host") or "").split(":")[0].lower() or None

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

    async def unlink(self, cloud: Cloud) -> None:
        """Give the name back: the Headscale user and its devices first (a
        HeadscaleError leaves everything as it was), then the cloud with
        its token, invites, logo and uptime, then its records.
        """
        if self.headscale is not None:
            await self.headscale.delete_user(cloud.mesh_user)
        self.store.delete_cloud(cloud.id)
        self.meshwatch.write_records()
        await self.dns_changed([cloud.name])
        log.info("cloud %s gave its name back", cloud.id)

    # --- life ---------------------------------------------------------------------

    async def start(self) -> None:
        cfg = self.cfg
        # One uvicorn on two loopback ports: the control API and the
        # landing page, told apart by the port a request came in on.
        for _ in range(2):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", 0))
            self._sockets.append(sock)
        self.control_port = self._sockets[0].getsockname()[1]
        self.landing_port = self._sockets[1].getsockname()[1]
        app = by_port({self.landing_port: landing.create_app(self)}, control.create_app(self))
        self._uvicorn, self._uvicorn_task = await start_uvicorn(app, self._sockets)

        https, http = await self.router.start(cfg.listen, cfg.https_port, cfg.http_port)
        self.https_port = https.sockets[0].getsockname()[1]
        self.http_port = http.sockets[0].getsockname()[1]
        await self.dns.start()
        self.dns_port = getattr(self.dns, "port", 0)
        self._servers = [https, http]
        self.meshwatch.start()
        if self.headscale is not None:
            asyncio.create_task(self._check_headscale())
        if self.renewer is not None:
            self.renewer.start()

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
        await self.meshwatch.stop()
        if self.renewer is not None:
            await self.renewer.stop()
        for server in self._servers:
            server.close()
        await self.dns.stop()
        for server in self._servers:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(server.wait_closed(), 2)
        if self._uvicorn is not None:
            self._uvicorn.should_exit = True
            with contextlib.suppress(Exception):
                await self._uvicorn_task
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._uvicorn.shutdown(sockets=self._sockets), 3)
        if self.headscale is not None:
            await self.headscale.aclose()
        self.store.close()
