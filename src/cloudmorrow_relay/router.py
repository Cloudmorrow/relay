"""Ports 443 and 80: deciding where each connection goes.

On 443 we read the ClientHello's server name and nothing more, then:

    <name>.<zone>, public, tunnel up   → a stream to the box; the ClientHello
                                         is the stream's first DATA, and TLS
                                         happens between visitor and box
    the relay host                     → TLS terminated here with the relay's
                                         own certificate; then either a box's
                                         tunnel ("CMTUNNEL/1 …") or the
                                         control API (HTTP)
    the login host                     → TLS terminated here too; Tailscale's
                                         protocol paths go to Headscale, and
                                         everything a browser asks for (the
                                         /register/ page above all) to our
                                         pairing pages
    a name in [[routes]] sni           → passed through to that upstream (the
                                         website, the shop on the same machine)
    anything else                      → closed

On 80 the same, by the `Host` header, with no TLS anywhere: a cloud's
name goes to its box (Caddy answers the ACME HTTP challenge there and
redirects the rest to https), the relay's own names to the control app
(its certificate's challenge, and a redirect).

The control API runs in the same process, on a loopback port, and the
relay hands it the decrypted connection. That keeps the API an ordinary
ASGI app served by uvicorn — testable on its own, with nothing in it that
knows about tunnels — at the price of one local hop. The visitor's real
address rides along in a table keyed by the local port of that hop, which
the app looks up for its rate limits (`Service.client_ip`).

Nothing here logs a byte of anybody's traffic; at most the name asked for.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import ssl
from pathlib import Path

from . import sni
from .conn import Conn, PlainConn, TLSConn, read_at_least, splice
from .tunnel import MAX_LINE, PROTOCOL, Tunnel, serve_visitor

log = logging.getLogger("cloudmorrow_relay.router")

# Paths on the login host that are Tailscale's protocol (or Headscale's
# DERP), as Headscale 0.29 routes them. Everything else there is a browser.
HEADSCALE_PATHS = (
    "/ts2021",
    "/key",
    "/health",
    "/version",
    "/verify",
    "/derp",
    "/bootstrap-dns",
    "/machine/",
)


def is_headscale_path(path: str) -> bool:
    path = path.split("?", 1)[0]
    for prefix in HEADSCALE_PATHS:
        if prefix.endswith("/"):
            if path.startswith(prefix):
                return True
        elif path == prefix or path.startswith(prefix + "/"):
            return True
    return False


def proxy_line(conn: PlainConn) -> bytes:
    """PROXY protocol v1: "PROXY TCP4 <src> <dst> <sport> <dport>\r\n"."""
    src = conn.writer.get_extra_info("peername")
    dst = conn.writer.get_extra_info("sockname")
    if not src or not dst:
        return b"PROXY UNKNOWN\r\n"
    family = "TCP6" if ":" in src[0] else "TCP4"
    return f"PROXY {family} {src[0]} {dst[0]} {src[1]} {dst[1]}\r\n".encode()


class CertStore:
    """The relay's own certificate (for the relay host and the login host),
    read from files and read again on SIGHUP, which is what certbot's or
    lego's renewal hook sends. Until the files exist, the relay's own names
    are refused on 443 and port 80 serves the ACME challenge that gets them.
    """

    def __init__(self, cert: Path | None, key: Path | None):
        self.cert = cert
        self.key = key
        self.context: ssl.SSLContext | None = None
        self.reload()

    def reload(self) -> bool:
        if self.cert is None or self.key is None:
            return False
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.options |= ssl.OP_NO_RENEGOTIATION
            ctx.load_cert_chain(self.cert, self.key)
            # Our own names speak HTTP/1.1 only: the tunnel and uvicorn both
            # want it, and Tailscale's control protocol is an HTTP/1.1
            # upgrade.
            ctx.set_alpn_protocols(["http/1.1"])
        except (OSError, ssl.SSLError) as exc:
            log.warning("could not load the relay's certificate (%s): %s", self.cert, exc)
            return False
        self.context = ctx
        log.info("loaded the relay's certificate from %s", self.cert)
        return True


class Router:
    def __init__(self, svc):
        self.svc = svc
        self.cfg = svc.cfg
        self.limits = svc.cfg.limits
        self._pending = asyncio.Semaphore(self.limits.max_pending_connections)
        self._tasks: set[asyncio.Task] = set()
        self.sni_routes = {name: r for r in self.cfg.routes for name in r.sni}
        self.host_routes = {name: r for r in self.cfg.routes for name in r.host}

    # --- helpers -------------------------------------------------------------

    def _cloud_for_host(self, host: str | None):
        """The cloud whose public name this is, if its tunnel can take it."""
        zone = self.cfg.zone
        if not host or not host.endswith("." + zone):
            return None, None
        label = host[: -len(zone) - 1]
        if "." in label:
            return None, None
        cloud = self.svc.store.cloud_by_name(label)
        if cloud is None or not cloud.public:
            return None, None
        return cloud, self.svc.registry.get(cloud.id)

    async def _forward(self, conn: Conn, host: str, port: int, prefix: bytes, remote: str, plain: bool) -> None:
        """Hand a connection to a local HTTP upstream (the control app or
        Headscale), starting with the bytes already read.
        """
        try:
            reader, writer = await asyncio.open_connection(host, port)
        except OSError:
            await conn.close()
            return
        local_port = writer.get_extra_info("sockname")[1]
        self.svc.peers[local_port] = (remote.rsplit(":", 1)[0].strip("[]"), plain)
        upstream = PlainConn(reader, writer)
        try:
            await upstream.write(prefix)
            await splice(conn, upstream)
        finally:
            self.svc.peers.pop(local_port, None)

    async def _passthrough(self, conn: PlainConn, route, prefix: bytes) -> None:
        """A static route: the connection goes to its upstream as it came,
        like a cloud's does to its box, optionally announced with a PROXY
        protocol line so the upstream knows who is really calling.
        """
        try:
            reader, writer = await asyncio.open_connection(*route.upstream)
        except OSError:
            await conn.close()
            return
        upstream = PlainConn(reader, writer)
        if route.proxy_protocol:
            prefix = proxy_line(conn) + prefix
        await upstream.write(prefix)
        await splice(conn, upstream)

    async def _control(self, conn: Conn, prefix: bytes, remote: str, plain: bool) -> None:
        await self._forward(conn, "127.0.0.1", self.svc.control_port, prefix, remote, plain)

    async def _login_host(self, conn: Conn, remote: str, plain: bool) -> None:
        head = await sni.with_deadline(sni.peek_http_head(conn, self.limits.peek_max_bytes), self.limits.peek_timeout)
        if head is None:
            await conn.close()
            return
        hs = self.svc.headscale_upstream
        if hs is not None and is_headscale_path(head.path):
            await self._forward(conn, hs[0], hs[1], sni.one_request_only(head.raw), remote, plain)
        else:
            await self._control(conn, sni.one_request_only(head.raw), remote, plain)

    # --- port 443 --------------------------------------------------------------

    async def handle_https(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        conn = PlainConn(reader, writer)
        remote = conn.peer
        try:
            async with self._pending:
                peeked = await sni.with_deadline(
                    sni.peek_client_hello(conn, self.limits.peek_max_bytes), self.limits.peek_timeout
                )
            if peeked is None or peeked[0] is None:
                await conn.close()
                return
            name, hello = peeked
            if name in (self.cfg.relay_host, self.cfg.login_host):
                await self._own_tls(conn, name, hello, remote)
                return
            if name in self.sni_routes:
                await self._passthrough(conn, self.sni_routes[name], hello)
                return
            cloud, tunnel = self._cloud_for_host(name)
            if tunnel is None:
                await conn.close()
                return
            await serve_visitor(tunnel, conn, 443, remote, hello)
        except (ConnectionError, OSError, ssl.SSLError, TimeoutError):
            await conn.close()

    async def _own_tls(self, conn: PlainConn, name: str, hello: bytes, remote: str) -> None:
        ctx = self.svc.certs.context
        if ctx is None:
            await conn.close()
            return
        conn.unread(hello)
        tls = TLSConn(conn, ctx)
        try:
            await tls.handshake(self.limits.handshake_timeout)
        except (ConnectionError, OSError, ssl.SSLError, TimeoutError):
            await conn.close()
            return
        if name == self.cfg.login_host:
            await self._login_host(tls, remote, plain=False)
            return
        try:
            async with asyncio.timeout(self.limits.peek_timeout):
                first = await read_at_least(tls, len(PROTOCOL) + 1, MAX_LINE)
        except TimeoutError:
            await tls.close()
            return
        if first.startswith(PROTOCOL.encode() + b" "):
            tls.unread(first)
            await self._tunnel(tls, conn.peer_ip)
        else:
            await self._control(tls, first, remote, plain=False)

    # --- the tunnel handshake ------------------------------------------------------

    async def _tunnel(self, tls: TLSConn, ip: str) -> None:
        svc = self.svc
        if svc.bad_auth.blocked(ip):
            with contextlib.suppress(Exception):
                await tls.write(b"NO too many failed attempts, wait a minute\n")
            await tls.close()
            return
        try:
            async with asyncio.timeout(self.limits.handshake_timeout):
                line = b""
                while b"\n" not in line and len(line) < MAX_LINE:
                    chunk = await tls.read(MAX_LINE - len(line))
                    if not chunk:
                        break
                    line += chunk
        except TimeoutError:
            await tls.close()
            return
        head, sep, rest = line.partition(b"\n")
        parts = head.rstrip(b"\r").decode("ascii", "replace").split(" ")
        if not sep or len(parts) != 3 or parts[0] != PROTOCOL:
            await self._refuse(tls, "not a cmtunnel/1 handshake")
            return
        cloud = svc.store.check_token(parts[1], parts[2])
        if cloud is None:
            svc.bad_auth.hit(ip)
            await self._refuse(tls, "unknown cloud or wrong token")
            return
        if not cloud.public:
            await self._refuse(tls, "public access is off for this cloud")
            return
        if rest:
            # Frames may follow the line in the same packet only after OK,
            # and the box has not seen OK yet: anything here is a mistake.
            await self._refuse(tls, "frames before OK")
            return
        tunnel = Tunnel(
            tls, cloud.id, cloud.name,
            ping_after=self.limits.ping_after, dead_after=self.limits.dead_after,
        )
        await tls.write(f"OK {self.cfg.public_host(cloud.name)}\n".encode())
        await svc.registry.attach(tunnel)
        log.info("tunnel up for %s", cloud.name)
        try:
            await tunnel.run()
        finally:
            svc.registry.detach(tunnel)
            log.info("tunnel down for %s", tunnel.name)

    @staticmethod
    async def _refuse(tls: TLSConn, reason: str) -> None:
        with contextlib.suppress(Exception):
            await tls.write(f"NO {reason}\n".encode())
        await tls.close()

    # --- port 80 -----------------------------------------------------------------

    async def handle_http(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        conn = PlainConn(reader, writer)
        remote = conn.peer
        try:
            async with self._pending:
                head = await sni.with_deadline(
                    sni.peek_http_head(conn, self.limits.peek_max_bytes), self.limits.peek_timeout
                )
            if head is None or head.host is None:
                await conn.close()
                return
            if head.host == self.cfg.relay_host:
                await self._control(conn, head.raw, remote, plain=True)
                return
            if head.host == self.cfg.login_host:
                conn.unread(head.raw)
                await self._login_host(conn, remote, plain=True)
                return
            if head.host in self.host_routes:
                await self._passthrough(conn, self.host_routes[head.host], head.raw)
                return
            cloud, tunnel = self._cloud_for_host(head.host)
            if tunnel is None:
                await conn.close()
                return
            await serve_visitor(tunnel, conn, 80, remote, head.raw)
        except (ConnectionError, OSError):
            await conn.close()

    # --- listening ------------------------------------------------------------------

    async def start(self, hosts: list[str], https_port: int, http_port: int):
        https = await asyncio.start_server(self.handle_https, hosts, https_port, reuse_address=True)
        http = await asyncio.start_server(self.handle_http, hosts, http_port, reuse_address=True)
        return https, http
