"""Where a connection wants to go, read from its first bytes.

On 443 that is the server name (SNI) in the TLS ClientHello, which the
client sends in the clear before anything is encrypted. On 80 it is the
`Host` header of the first HTTP request. In both cases we read, never
answer, and hand the bytes on as they were.

These bytes come from anybody on the internet, before we know anything
about them, so the parsing assumes they are hostile: every length is
checked against what is actually there, the total read is capped, and the
caller puts a deadline on the whole peek so a client that sends one byte a
minute is dropped rather than held (the slow-loris guard). A malformed
hello gives "no name", which closes the connection; it never raises.
"""

from __future__ import annotations

import asyncio
import re

from .conn import Conn

RECORD_HANDSHAKE = 22
HANDSHAKE_CLIENT_HELLO = 1
EXT_SERVER_NAME = 0
# A TLS record carries at most 2^14 bytes of plaintext; a ClientHello with
# a post-quantum key share is a couple of kilobytes, well under one record,
# but the protocol lets it be split across records, so we reassemble.
MAX_RECORD = 16384 + 256

_HOST_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,62})(\.[a-z0-9_]([a-z0-9_-]{0,62}))*$")


def clean_host(value: str | bytes) -> str | None:
    """A host name as we compare them: ASCII, lower case, no trailing dot,
    no port. None for anything that is not a plausible DNS name.
    """
    if isinstance(value, bytes):
        try:
            value = value.decode("ascii")
        except UnicodeDecodeError:
            return None
    value = value.strip().lower().rstrip(".")
    if not value or len(value) > 253 or not _HOST_RE.match(value):
        return None
    return value


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise ValueError("truncated")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def u24(self) -> int:
        return int.from_bytes(self.take(3), "big")

    def vector(self, length_bytes: int) -> bytes:
        n = int.from_bytes(self.take(length_bytes), "big")
        return self.take(n)


def parse_client_hello(message: bytes) -> str | None:
    """The server name from a ClientHello handshake message (header
    included), or None.
    """
    try:
        r = _Reader(message)
        if r.u8() != HANDSHAKE_CLIENT_HELLO:
            return None
        body = _Reader(r.take(r.u24()))
        body.take(2)  # legacy_version
        body.take(32)  # random
        body.vector(1)  # session id
        body.vector(2)  # cipher suites
        body.vector(1)  # compression methods
        if body.pos == len(body.data):
            return None  # no extensions at all
        extensions = _Reader(body.vector(2))
        while extensions.pos < len(extensions.data):
            ext_type = extensions.u16()
            ext = _Reader(extensions.vector(2))
            if ext_type != EXT_SERVER_NAME:
                continue
            names = _Reader(ext.vector(2))
            while names.pos < len(names.data):
                name_type = names.u8()
                name = names.vector(2)
                if name_type == 0:  # host_name
                    return clean_host(name)
            return None
        return None
    except ValueError:
        return None


async def _fill(conn: Conn, buf: bytearray, n: int, cap: int) -> bool:
    """Read until `buf` holds `n` bytes. False if the stream ended first or
    `n` is past the cap.
    """
    if n > cap:
        return False
    while len(buf) < n:
        chunk = await conn.read(n - len(buf))
        if not chunk:
            return False
        buf += chunk
    return True


async def peek_client_hello(conn: Conn, cap: int) -> tuple[str | None, bytes]:
    """Read TLS records until the whole ClientHello is in, and return the
    server name in it together with every byte read. The bytes are what
    gets passed on; the caller must not lose them.
    """
    raw = bytearray()
    message = bytearray()
    needed: int | None = None
    pos = 0
    while needed is None or len(message) < needed:
        if not await _fill(conn, raw, pos + 5, cap):
            return None, bytes(raw)
        ctype, major = raw[pos], raw[pos + 1]
        length = int.from_bytes(raw[pos + 3 : pos + 5], "big")
        if ctype != RECORD_HANDSHAKE or major != 3 or length == 0 or length > MAX_RECORD:
            return None, bytes(raw)
        if not await _fill(conn, raw, pos + 5 + length, cap):
            return None, bytes(raw)
        message += raw[pos + 5 : pos + 5 + length]
        pos += 5 + length
        if needed is None and len(message) >= 4:
            needed = 4 + int.from_bytes(message[1:4], "big")
            if 4 + needed > cap:
                return None, bytes(raw)
    return parse_client_hello(bytes(message[:needed])), bytes(raw)


class HttpHead:
    def __init__(self, method: str, path: str, host: str | None, raw: bytes):
        self.method = method
        self.path = path
        self.host = host
        self.raw = raw


async def peek_http_head(conn: Conn, cap: int) -> HttpHead | None:
    """Read the head of the first HTTP/1.x request (up to the blank line)
    and pick out the method, the path and the Host. None if it is not one.
    """
    raw = bytearray()
    # Only CRLF line ends, as HTTP/1.1 says: a head we cannot cut exactly
    # where the server will is a head we cannot vouch for.
    while b"\r\n\r\n" not in raw:
        if len(raw) >= cap:
            return None
        chunk = await conn.read(cap - len(raw))
        if not chunk:
            return None
        raw += chunk
    return parse_http_head(bytes(raw))


def parse_http_head(raw: bytes) -> HttpHead | None:
    cut = raw.find(b"\r\n\r\n")
    if cut < 0:
        return None
    lines = raw[:cut].decode("latin-1").split("\r\n")
    if any("\n" in line or "\r" in line for line in lines):
        return None
    parts = lines[0].split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
        return None
    method, target = parts[0], parts[1]
    if not method.isalpha() or not method.isupper():
        return None
    hosts = []
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if not sep:
            return None
        if name.strip().lower() == "host":
            hosts.append(value.strip())
    host = None
    if len(hosts) == 1:
        value = hosts[0]
        # Strip a port, taking care with IPv6 literals ("[::1]:80").
        if value.startswith("["):
            value = value.split("]")[0] + "]"
        else:
            value = value.split(":")[0]
        host = clean_host(value)
    path = target
    if target.startswith(("http://", "https://")):
        # Absolute form, as a proxy would send it: the path starts after
        # the authority.
        rest = target.split("://", 1)[1]
        path = "/" + rest.split("/", 1)[1] if "/" in rest else "/"
    return HttpHead(method, path, host, raw)


def one_request_only(raw: bytes) -> bytes:
    """The same request head, asking the server to close the connection
    after answering it.

    The relay picks an upstream by the first request on a connection;
    without this, a client could send a harmless first request and then
    anything it liked on the same connection. An upgrade (Tailscale's
    /ts2021, DERP) is left alone: after it there are no more requests,
    only the upgraded stream.
    """
    cut = raw.find(b"\r\n\r\n")
    if cut < 0:
        return raw
    lines = raw[:cut].split(b"\r\n")
    names = [line.split(b":", 1)[0].strip().lower() for line in lines[1:]]
    if b"upgrade" in names:
        return raw
    kept = [lines[0]] + [
        line for line, name in zip(lines[1:], names)
        if name not in (b"connection", b"keep-alive", b"proxy-connection")
    ]
    return b"\r\n".join(kept + [b"Connection: close"]) + raw[cut:]


async def with_deadline(coro, timeout: float):
    """Run a peek with a deadline: None, as for garbage, when it runs out."""
    try:
        async with asyncio.timeout(timeout):
            return await coro
    except TimeoutError:
        return None
