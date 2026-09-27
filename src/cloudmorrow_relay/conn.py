"""Byte streams the relay reads from and writes to.

The relay has to look at the first bytes of a connection before it knows
what the connection is (the TLS ClientHello, the HTTP request line), and
then either hand those same bytes on untouched or start TLS over them. So
every stream here can have bytes pushed back into it (`unread`).

TLS for the relay's own names is done by hand with `ssl.SSLObject` over
memory buffers, not by asyncio's `start_tls`: the ClientHello has already
been read to look at its SNI, and `start_tls` has no way to be given bytes
that were read before it started. With memory buffers, those bytes are
simply the first thing fed in.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl

CHUNK = 64 * 1024


class Conn:
    """A byte stream: `read` returns b"" at the end."""

    def __init__(self) -> None:
        self._pending = b""

    def unread(self, data: bytes) -> None:
        self._pending = data + self._pending

    async def read(self, n: int = CHUNK) -> bytes:
        if self._pending:
            data, self._pending = self._pending[:n], self._pending[n:]
            return data
        return await self._read(n)

    async def _read(self, n: int) -> bytes:  # pragma: no cover - abstract
        raise NotImplementedError

    async def write(self, data: bytes) -> None:  # pragma: no cover - abstract
        raise NotImplementedError

    async def write_eof(self) -> None:
        pass

    async def close(self) -> None:  # pragma: no cover - abstract
        raise NotImplementedError


class PlainConn(Conn):
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        super().__init__()
        self.reader = reader
        self.writer = writer

    @property
    def peer(self) -> str:
        # "ip:port", with an IPv6 address in brackets ("[2001:db8::1]:443")
        # so the port can be told from the address.
        peer = self.writer.get_extra_info("peername")
        if not peer:
            return "?"
        host = f"[{peer[0]}]" if ":" in peer[0] else peer[0]
        return f"{host}:{peer[1]}"

    @property
    def peer_ip(self) -> str:
        peer = self.writer.get_extra_info("peername")
        return peer[0] if peer else "?"

    async def _read(self, n: int) -> bytes:
        try:
            return await self.reader.read(n)
        except (ConnectionError, OSError):
            return b""

    async def write(self, data: bytes) -> None:
        self.writer.write(data)
        await self.writer.drain()

    async def write_eof(self) -> None:
        with contextlib.suppress(OSError, RuntimeError):
            if self.writer.can_write_eof() and not self.writer.is_closing():
                self.writer.write_eof()

    async def close(self) -> None:
        self.writer.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(self.writer.wait_closed(), 5)


class TLSConn(Conn):
    """Server-side TLS over another Conn, terminated here."""

    def __init__(self, raw: Conn, context: ssl.SSLContext):
        super().__init__()
        self.raw = raw
        self._in = ssl.MemoryBIO()
        self._out = ssl.MemoryBIO()
        self._ssl = context.wrap_bio(self._in, self._out, server_side=True)

    async def handshake(self, timeout: float) -> None:
        async with asyncio.timeout(timeout):
            while True:
                try:
                    self._ssl.do_handshake()
                    break
                except ssl.SSLWantReadError:
                    await self._flush()
                    if not await self._fill():
                        raise ConnectionError("closed during the TLS handshake")
            await self._flush()

    async def _fill(self) -> bool:
        data = await self.raw.read(CHUNK)
        if not data:
            self._in.write_eof()
            return False
        self._in.write(data)
        return True

    async def _flush(self) -> None:
        # Taking everything out of the buffer in one go, and writing it in
        # one call, keeps records in order even when a reader and a writer
        # task both flush.
        data = self._out.read()
        if data:
            await self.raw.write(data)

    async def _read(self, n: int) -> bytes:
        while True:
            try:
                data = self._ssl.read(n)
            except ssl.SSLWantReadError:
                await self._flush()
                if not await self._fill():
                    # The peer closed without close_notify: an ordinary end
                    # for most clients, not an attack worth telling apart.
                    return b""
                continue
            except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
                return b""
            except ssl.SSLError:
                return b""
            # A read can produce bytes to send (TLS 1.3 key updates).
            await self._flush()
            return data

    async def write(self, data: bytes) -> None:
        self._ssl.write(data)
        await self._flush()

    async def close(self) -> None:
        with contextlib.suppress(Exception):
            self._ssl.unwrap()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(self._flush(), 1)
        await self.raw.close()


async def read_at_least(conn: Conn, n: int, limit: int) -> bytes:
    """Read until at least `n` bytes (or a newline) have arrived, or the
    stream ends; at most `limit`. The caller puts a timeout around it.
    """
    data = b""
    while len(data) < n and b"\n" not in data:
        chunk = await conn.read(limit - len(data))
        if not chunk:
            break
        data += chunk
    return data


async def splice(client: Conn, upstream: Conn, linger: float = 30.0) -> None:
    """Copy both ways until the upstream is done.

    When the client stops sending, the upstream is told (a half close) and
    has `linger` seconds to finish its answer. When the upstream stops, the
    connection is over: the client is closed.
    """

    async def up() -> None:
        while data := await client.read(CHUNK):
            await upstream.write(data)
        await upstream.write_eof()

    async def down() -> None:
        while data := await upstream.read(CHUNK):
            await client.write(data)

    up_task = asyncio.create_task(up())
    down_task = asyncio.create_task(down())
    try:
        done, _ = await asyncio.wait({up_task, down_task}, return_when=asyncio.FIRST_COMPLETED)
        if down_task not in done:
            await asyncio.wait({down_task}, timeout=linger)
    finally:
        for task in (up_task, down_task):
            task.cancel()
        for task in (up_task, down_task):
            with contextlib.suppress(BaseException):
                await task
        await upstream.close()
        await client.close()
