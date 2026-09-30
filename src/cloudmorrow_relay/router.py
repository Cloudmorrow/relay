"""Ports 443 and 80: deciding where each connection goes.

On 443 we read the ClientHello's server name and nothing more, then:

    the relay host             → TLS terminated here with the relay's own
                                 certificate; the control API (HTTP)
    the login host             → TLS terminated here too; Tailscale's
                                 protocol paths go to Headscale, and
                                 everything a browser asks for (the
                                 /register/ page above all) to our pairing
                                 pages
    a name in [[routes]] sni   → passed through to that upstream (the
                                 website, the shop on the same machine)
    <name>.<zone> of a linked  → passed through, unread, over the mesh to
      cloud that is public       port 8443 of the cloud's box, after a
                                 PROXY protocol v2 header with the
                                 visitor's address (meshdial.py)
    <name>.<zone> otherwise    → TLS terminated here with the wildcard
                                 certificate; the offline page (or "There
                                 is no cloud here.")
    anything else              → closed

A cloud's name gets the offline page when the box has no mesh address,
does not take the connection within three seconds, or its owner turned
"Reachable from anywhere" off. The choice is made before a single byte is
answered, and a connection the relay ended TLS on is never forwarded to a
box: from there on it only ever reaches the offline page. The wildcard
certificate would let the relay do otherwise; this is the code that
doesn't.

On 80 the same, by the `Host` header, with no TLS anywhere: the relay's
own names go to the control app (its certificate's challenge, and a
redirect), a route's names to their upstream, and `<name>.<zone>` gets a
redirect to https, written here.

The control API and the offline page run in the same process, on two
loopback ports of one uvicorn, and the relay hands them the decrypted
connection. That keeps them ordinary ASGI apps — testable on their own —
at the price of one local hop. The visitor's real address (and the name
it asked for) rides along in a table keyed by the local port of that hop,
which the apps look up (`Service.client_ip`, `Service.entry_name`).

Nothing here logs a byte of anybody's traffic; at most the name asked for.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
from pathlib import Path

from . import meshdial, sni
from .conn import Conn, PlainConn, TLSConn, splice

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
    """The relay's own certificate (for the relay host, the login host and
    `*.<zone>`, which may all be the one wildcard), read from files and read again on SIGHUP, which is what certbot's or
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
            # Our own names speak HTTP/1.1 only: uvicorn wants it, and
            # Tailscale's control protocol is an HTTP/1.1 upgrade.
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
        # cloud id → until when its box is not tried again (it did not answer)
        self._unreachable: dict[str, float] = {}

    # --- helpers -------------------------------------------------------------

    async def _forward(self, conn: Conn, host: str, port: int, prefix: bytes, remote: str, plain: bool, name: str) -> None:
        """Hand a connection to a local HTTP upstream (the control app, the
        offline page or Headscale), starting with the bytes already read.
        """
        try:
            reader, writer = await asyncio.open_connection(host, port)
        except OSError:
            await conn.close()
            return
        local_port = writer.get_extra_info("sockname")[1]
        self.svc.peers[local_port] = (remote.rsplit(":", 1)[0].strip("[]"), plain, name)
        upstream = PlainConn(reader, writer)
        try:
            await upstream.write(prefix)
            await splice(conn, upstream)
        finally:
            self.svc.peers.pop(local_port, None)

    async def _passthrough(self, conn: PlainConn, route, prefix: bytes) -> None:
        """A static route: the connection goes to its upstream as it came,
        optionally announced with a PROXY protocol line so the upstream
        knows who is really calling.
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

    async def _control(self, conn: Conn, prefix: bytes, remote: str, plain: bool, name: str) -> None:
        await self._forward(conn, "127.0.0.1", self.svc.control_port, prefix, remote, plain, name)

    async def _login_host(self, conn: Conn, remote: str, plain: bool) -> None:
        head = await sni.with_deadline(sni.peek_http_head(conn, self.limits.peek_max_bytes), self.limits.peek_timeout)
        if head is None:
            await conn.close()
            return
        hs = self.svc.headscale_upstream
        name = self.cfg.login_host
        if hs is not None and is_headscale_path(head.path):
            await self._forward(conn, hs[0], hs[1], sni.one_request_only(head.raw), remote, plain, name)
        else:
            await self._control(conn, sni.one_request_only(head.raw), remote, plain, name)

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
            if name in self.sni_routes:
                await self._passthrough(conn, self.sni_routes[name], hello)
                return
            label = self.cfg.cloud_label(name)
            if label and await self._to_box(conn, label, hello):
                return
            if name in (self.cfg.relay_host, self.cfg.login_host) or label:
                await self._own_tls(conn, name, hello, remote)
                return
            await conn.close()
        except (ConnectionError, OSError, ssl.SSLError, TimeoutError):
            await conn.close()

    async def _to_box(self, conn: PlainConn, label: str, hello: bytes) -> bool:
        """Pass a visitor to a cloud's box, unread. False, with nothing
        sent either way, when the name is no cloud's, the cloud is not
        public, or its box cannot be reached: then the offline page.
        """
        cloud = self.svc.store.cloud_by_name(label)
        if cloud is None or not cloud.public:
            return False
        address = cloud.mesh_address or cloud.mesh_address6
        loop = asyncio.get_running_loop()
        if address is None or self._unreachable.get(cloud.id, 0) > loop.time():
            return False
        try:
            box = await meshdial.dial(self.cfg, address)
        except (OSError, TimeoutError, ValueError) as exc:
            # The name, never the visitor.
            log.debug("the box of %s did not answer: %s", label, exc or type(exc).__name__)
            self._unreachable[cloud.id] = loop.time() + self.limits.box_retry_after
            return False
        self._unreachable.pop(cloud.id, None)
        src = conn.writer.get_extra_info("peername")
        dst = conn.writer.get_extra_info("sockname")
        try:
            await box.write(meshdial.proxy_v2_header(src, dst) + hello)
        except (ConnectionError, OSError):
            await box.close()
            raise
        await splice(conn, box)
        return True

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
        elif name == self.cfg.relay_host:
            await self._control(tls, b"", remote, plain=False, name=name)
        else:
            await self._forward(tls, "127.0.0.1", self.svc.landing_port, b"", remote, False, name)

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
                await self._control(conn, head.raw, remote, plain=True, name=head.host)
                return
            if head.host == self.cfg.login_host:
                conn.unread(head.raw)
                await self._login_host(conn, remote, plain=True)
                return
            if head.host in self.host_routes:
                await self._passthrough(conn, self.host_routes[head.host], head.raw)
                return
            if self.cfg.cloud_label(head.host):
                await self._to_https(conn, head)
                return
            await conn.close()
        except (ConnectionError, OSError):
            await conn.close()

    async def _to_https(self, conn: PlainConn, head: sni.HttpHead) -> None:
        """A cloud's name over plain http: straight to https, the path kept."""
        path = head.path if head.path.startswith("/") else "/"
        # A path with a line break in it cannot get here (the head parser
        # refuses those), but a Location header is no place to find out.
        if any(c in path for c in "\r\n"):
            path = "/"
        location = f"{self.cfg.public_url(self.cfg.cloud_label(head.host))}{path}"
        await conn.write(
            b"HTTP/1.1 308 Permanent Redirect\r\n"
            + f"Location: {location}\r\n".encode("latin-1", "replace")
            + b"Content-Length: 0\r\nConnection: close\r\n\r\n"
        )
        await conn.close()

    # --- listening ------------------------------------------------------------------

    async def start(self, hosts: list[str], https_port: int, http_port: int):
        https = await asyncio.start_server(self.handle_https, hosts, https_port, reuse_address=True)
        http = await asyncio.start_server(self.handle_http, hosts, http_port, reuse_address=True)
        return https, http
