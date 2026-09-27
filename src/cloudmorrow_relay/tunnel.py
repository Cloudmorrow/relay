"""cmtunnel/1: many visitors' connections over one connection from a box.

A box behind a home router cannot be reached, but it can reach out. So it
opens one TLS connection to the relay and keeps it; every visitor who
arrives for its name becomes a *stream* inside that connection. The relay
opens streams, the box answers each by connecting to its own Caddy, and
both copy bytes. The relay never sees inside a stream: a visitor's TLS goes
through it end to end to the box.

The wire format (HOSTING.md, "The tunnel"):

    handshake   box -> relay   "CMTUNNEL/1 <cloud_id> <token>\\n"
                relay -> box   "OK <name>.<zone>\\n"  or  "NO <reason>\\n"
    frames      9-byte header: type (1), stream (4, BE), length (4, BE)

Each stream has a window each way, 256 KiB to begin with: a side may have
at most that many bytes of DATA in flight that the other has not yet
handed on, and the other side returns credit with WINDOW as it does. So a
slow visitor slows the box down on that one stream, and never fills the
relay's memory or stalls the other streams.

Things the contract leaves open are decided here and written down in the
README's "Protocol notes": stream 0 is the connection itself (PING/PONG),
unknown frame types are skipped, a frame longer than 64 KiB ends the
connection, and a CLOSE from the box ends the visitor's connection.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import struct
import time
from collections import deque
from typing import Callable

from .conn import CHUNK, Conn

log = logging.getLogger("cloudmorrow_relay.tunnel")

PROTOCOL = "CMTUNNEL/1"
OPEN, DATA, CLOSE, WINDOW, PING, PONG = 1, 2, 3, 4, 5, 6
HEADER = struct.Struct(">BII")
MAX_DATA = 64 * 1024
INITIAL_WINDOW = 256 * 1024
MAX_FRAME = MAX_DATA
MAX_LINE = 512


class ProtocolError(Exception):
    pass


def frame(ftype: int, stream: int, payload: bytes = b"") -> bytes:
    return HEADER.pack(ftype, stream, len(payload)) + payload


class Stream:
    """One visitor's connection, as the relay side of the tunnel sees it."""

    def __init__(self, tunnel: "Tunnel", stream_id: int):
        self.tunnel = tunnel
        self.id = stream_id
        self.send_window = INITIAL_WINDOW
        self._window_changed = asyncio.Event()
        # What the box sent that the visitor has not taken yet. Never more
        # than INITIAL_WINDOW bytes: the box would be breaking the protocol.
        self._inbox: deque[bytes] = deque()
        self._inbox_bytes = 0
        self._inbox_changed = asyncio.Event()
        self.remote_closed = False  # the box sent CLOSE
        self.local_closed = False  # we sent CLOSE
        self.dead = False  # the tunnel went away

    # --- from the box ----------------------------------------------------

    def _on_data(self, payload: bytes) -> None:
        if self.remote_closed:
            raise ProtocolError(f"DATA after CLOSE on stream {self.id}")
        if self._inbox_bytes + len(payload) > INITIAL_WINDOW:
            raise ProtocolError(f"the box overran the window on stream {self.id}")
        self._inbox.append(payload)
        self._inbox_bytes += len(payload)
        self._inbox_changed.set()

    def _on_window(self, credit: int) -> None:
        self.send_window += credit
        if self.send_window > 2**31:
            raise ProtocolError(f"window overflow on stream {self.id}")
        self._window_changed.set()

    def _on_close(self) -> None:
        self.remote_closed = True
        self._inbox_changed.set()

    def _on_dead(self) -> None:
        self.dead = True
        self._inbox_changed.set()
        self._window_changed.set()

    # --- for the relay's side --------------------------------------------

    async def recv(self) -> bytes:
        """The next bytes from the box, or b"" when it is done."""
        while not self._inbox:
            if self.remote_closed or self.dead:
                return b""
            self._inbox_changed.clear()
            await self._inbox_changed.wait()
        return self._inbox.popleft()

    async def consumed(self, n: int) -> None:
        """Tell the box that `n` more bytes were handed to the visitor."""
        self._inbox_bytes -= n
        if not self.dead and not self.remote_closed:
            await self.tunnel.send(WINDOW, self.id, n.to_bytes(4, "big"))

    async def send(self, data: bytes) -> None:
        view = memoryview(data)
        while view:
            while self.send_window <= 0:
                if self.dead or self.remote_closed:
                    raise ConnectionError("stream closed")
                self._window_changed.clear()
                await self._window_changed.wait()
            if self.dead or self.remote_closed:
                raise ConnectionError("stream closed")
            n = min(len(view), MAX_DATA, self.send_window)
            self.send_window -= n
            await self.tunnel.send(DATA, self.id, bytes(view[:n]))
            self.tunnel.bytes_in += n
            view = view[n:]

    async def close(self) -> None:
        if not self.local_closed:
            self.local_closed = True
            if not self.dead:
                with contextlib.suppress(ConnectionError):
                    await self.tunnel.send(CLOSE, self.id)
        self.tunnel._maybe_forget(self)


class Tunnel:
    """The relay's end of one box's connection."""

    def __init__(
        self,
        conn: Conn,
        cloud_id: str,
        name: str,
        *,
        ping_after: float = 25.0,
        dead_after: float = 60.0,
    ):
        self.conn = conn
        self.cloud_id = cloud_id
        self.name = name
        self.ping_after = ping_after
        self.dead_after = dead_after
        self.connected_since = time.time()
        self.bytes_in = 0  # visitors -> box
        self.bytes_out = 0  # box -> visitors
        self.streams: dict[int, Stream] = {}
        self._next_id = 1
        self._write_lock = asyncio.Lock()
        self._last_rx = time.monotonic()
        self._pinged = False
        self._closed = asyncio.Event()

    @property
    def closed(self) -> bool:
        return self._closed.is_set()

    async def send(self, ftype: int, stream: int, payload: bytes = b"") -> None:
        if self.closed:
            raise ConnectionError("tunnel closed")
        async with self._write_lock:
            await self.conn.write(frame(ftype, stream, payload))

    async def open_stream(self, port: int, remote: str) -> Stream:
        # Stream ids count up from 1 and skip any still in use after a
        # wrap-around; 0 is the connection itself.
        while self._next_id in self.streams or self._next_id == 0:
            self._next_id = (self._next_id + 1) & 0xFFFFFFFF
        stream = Stream(self, self._next_id)
        self._next_id = (self._next_id + 1) & 0xFFFFFFFF
        self.streams[stream.id] = stream
        await self.send(OPEN, stream.id, json.dumps({"port": port, "remote": remote}).encode())
        return stream

    def _maybe_forget(self, stream: Stream) -> None:
        if stream.local_closed and (stream.remote_closed or stream.dead):
            self.streams.pop(stream.id, None)

    async def _read_exactly(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = await self.conn.read(n - len(buf))
            if not chunk:
                raise ConnectionError("tunnel closed")
            buf += chunk
        return bytes(buf)

    async def run(self) -> None:
        """Read frames until the box goes away (or breaks the protocol)."""
        keepalive = asyncio.create_task(self._keepalive())
        try:
            while True:
                ftype, sid, length = HEADER.unpack(await self._read_exactly(HEADER.size))
                if length > MAX_FRAME:
                    raise ProtocolError(f"a frame of {length} bytes")
                payload = await self._read_exactly(length) if length else b""
                self._last_rx = time.monotonic()
                self._pinged = False
                self._dispatch(ftype, sid, payload)
        except (ConnectionError, OSError, asyncio.IncompleteReadError):
            pass
        except ProtocolError as exc:
            log.warning("tunnel for %s broke the protocol: %s", self.name, exc)
        finally:
            keepalive.cancel()
            await self.close()

    def _dispatch(self, ftype: int, sid: int, payload: bytes) -> None:
        if ftype == DATA:
            if len(payload) > MAX_DATA:
                raise ProtocolError("DATA over 64 KiB")
            stream = self.streams.get(sid)
            # DATA for a stream we already forgot is late, not wrong: the
            # visitor went away while it was on the wire.
            if stream is not None:
                stream._on_data(payload)
                self.bytes_out += len(payload)
        elif ftype == WINDOW:
            if len(payload) != 4:
                raise ProtocolError("WINDOW needs 4 bytes")
            stream = self.streams.get(sid)
            if stream is not None:
                stream._on_window(int.from_bytes(payload, "big"))
        elif ftype == CLOSE:
            stream = self.streams.get(sid)
            if stream is not None:
                stream._on_close()
                self._maybe_forget(stream)
        elif ftype == PING:
            if len(payload) != 8:
                raise ProtocolError("PING needs 8 bytes")
            asyncio.create_task(self._send_quietly(PONG, payload))
        elif ftype == PONG:
            pass
        elif ftype == OPEN:
            raise ProtocolError("only the relay opens streams")
        # Any other type is from a later version of the protocol: skipped.

    async def _send_quietly(self, ftype: int, payload: bytes) -> None:
        # PING and PONG go out on their own task, so a write stuck behind
        # a box that stopped reading never holds up the reader or the
        # keepalive clock that will end it.
        with contextlib.suppress(ConnectionError, OSError):
            await self.send(ftype, 0, payload)

    async def _keepalive(self) -> None:
        tick = min(self.ping_after, 5.0) / 2
        try:
            while not self.closed:
                await asyncio.sleep(tick)
                idle = time.monotonic() - self._last_rx
                if idle >= self.dead_after:
                    log.info("tunnel for %s silent for %ds, dropping it", self.name, idle)
                    await self.close()
                    return
                if idle >= self.ping_after and not self._pinged:
                    self._pinged = True
                    asyncio.create_task(self._send_quietly(PING, os.urandom(8)))
        except (ConnectionError, OSError):
            await self.close()

    async def close(self) -> None:
        if self.closed:
            return
        self._closed.set()
        for stream in list(self.streams.values()):
            stream._on_dead()
        self.streams.clear()
        await self.conn.close()

    async def wait_closed(self) -> None:
        await self._closed.wait()


async def serve_visitor(
    tunnel: Tunnel, visitor: Conn, port: int, remote: str, first: bytes
) -> None:
    """Carry one visitor's connection over the tunnel, starting with the
    bytes the router already read to find out where it was going.
    """
    try:
        stream = await tunnel.open_stream(port, remote)
    except ConnectionError:
        await visitor.close()
        return

    async def up() -> None:
        try:
            if first:
                await stream.send(first)
            while data := await visitor.read(CHUNK):
                await stream.send(data)
        except (ConnectionError, OSError):
            pass
        await stream.close()

    async def down() -> None:
        while data := await stream.recv():
            await visitor.write(data)
            await stream.consumed(len(data))

    up_task = asyncio.create_task(up())
    try:
        with contextlib.suppress(ConnectionError, OSError):
            await down()
    finally:
        # The box is done (CLOSE) or gone: the visitor's connection ends.
        # Whatever it was still sending has nowhere to go.
        up_task.cancel()
        with contextlib.suppress(BaseException):
            await up_task
        await stream.close()
        await visitor.close()


class Registry:
    """The tunnels that are up, one per cloud. A box that reconnects while
    the relay still holds its old connection wins: the old one is closed,
    since the box would not have dialled again if it still trusted it.
    """

    def __init__(self, on_bytes: Callable[[str, int, int], None] | None = None):
        self.tunnels: dict[str, Tunnel] = {}
        self._on_bytes = on_bytes
        self._flushed: dict[int, tuple[int, int]] = {}

    def get(self, cloud_id: str) -> Tunnel | None:
        tunnel = self.tunnels.get(cloud_id)
        return tunnel if tunnel is not None and not tunnel.closed else None

    async def attach(self, tunnel: Tunnel) -> None:
        old = self.tunnels.get(tunnel.cloud_id)
        self.tunnels[tunnel.cloud_id] = tunnel
        if old is not None:
            await old.close()
            self.flush(old)

    def detach(self, tunnel: Tunnel) -> None:
        if self.tunnels.get(tunnel.cloud_id) is tunnel:
            del self.tunnels[tunnel.cloud_id]
        self.flush(tunnel)
        self._flushed.pop(id(tunnel), None)

    async def drop(self, cloud_id: str) -> None:
        tunnel = self.tunnels.pop(cloud_id, None)
        if tunnel is not None:
            await tunnel.close()
            self.flush(tunnel)

    def flush(self, tunnel: Tunnel) -> None:
        """Hand the byte counts since the last flush to the store."""
        done_in, done_out = self._flushed.get(id(tunnel), (0, 0))
        if self._on_bytes:
            self._on_bytes(tunnel.cloud_id, tunnel.bytes_in - done_in, tunnel.bytes_out - done_out)
        self._flushed[id(tunnel)] = (tunnel.bytes_in, tunnel.bytes_out)

    def flush_all(self) -> None:
        for tunnel in list(self.tunnels.values()):
            self.flush(tunnel)
