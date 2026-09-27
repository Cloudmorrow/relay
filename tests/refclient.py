"""A reference cmtunnel/1 client: the box's side, for testing the relay.

This is not the box's client (that lives in the core). It is written from
the contract alone, separately from the relay's own tunnel.py, so the two
do not share a misreading. It answers OPEN by connecting to a local
upstream per port, keeps its windows honestly, answers PING, and can be
told to misbehave (stop answering pings, overrun a window, open a stream)
so the relay's defences can be tested.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import ssl
import struct
from collections import deque

HEADER = struct.Struct(">BII")
OPEN, DATA, CLOSE, WINDOW, PING, PONG = 1, 2, 3, 4, 5, 6
MAX_DATA = 64 * 1024
WINDOW_SIZE = 256 * 1024


class Refused(Exception):
    pass


class BoxStream:
    def __init__(self, box: "RefBox", sid: int, info: dict):
        self.box = box
        self.id = sid
        self.info = info
        self.send_window = WINDOW_SIZE
        self.window_event = asyncio.Event()
        self.inbox: deque[bytes] = deque()
        self.inbox_event = asyncio.Event()
        self.relay_closed = False
        self.task: asyncio.Task | None = None

    async def run(self, upstream: tuple[str, int] | None) -> None:
        try:
            if upstream is None:
                raise OSError("no upstream for this port")
            reader, writer = await asyncio.open_connection(*upstream)
        except OSError:
            await self.box.send(CLOSE, self.id)
            self.box.streams.pop(self.id, None)
            return

        async def to_relay():
            while True:
                while self.send_window <= 0:
                    self.window_event.clear()
                    await self.window_event.wait()
                data = await reader.read(min(MAX_DATA, self.send_window))
                if not data:
                    break
                self.send_window -= len(data)
                await self.box.send(DATA, self.id, data)
            await self.box.send(CLOSE, self.id)

        async def to_upstream():
            while True:
                while not self.inbox:
                    if self.relay_closed:
                        with contextlib.suppress(OSError):
                            if writer.can_write_eof():
                                writer.write_eof()
                        return
                    self.inbox_event.clear()
                    await self.inbox_event.wait()
                data = self.inbox.popleft()
                writer.write(data)
                await writer.drain()
                if self.box.give_credit:
                    await self.box.send(WINDOW, self.id, len(data).to_bytes(4, "big"))

        up = asyncio.create_task(to_upstream())
        try:
            await to_relay()
            # Our side is done; give the relay's side a moment to finish.
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(asyncio.shield(up), 5)
        except (ConnectionError, OSError):
            pass
        finally:
            up.cancel()
            writer.close()
            self.box.streams.pop(self.id, None)


class RefBox:
    def __init__(
        self,
        port: int,
        ca: str,
        cloud_id: str,
        token: str,
        upstreams: dict[int, tuple[str, int]],
        relay_host: str = "relay.cm.test",
    ):
        self.port = port
        self.ca = ca
        self.cloud_id = cloud_id
        self.token = token
        self.upstreams = upstreams
        self.relay_host = relay_host
        self.streams: dict[int, BoxStream] = {}
        self.opens: list[dict] = []
        self.pings_seen = 0
        self.answer_pings = True
        self.give_credit = True
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self.task: asyncio.Task | None = None
        self.hostname: str | None = None
        self.closed = asyncio.Event()

    async def connect(self, line: bytes | None = None) -> str:
        ctx = ssl.create_default_context(cafile=self.ca)
        self.reader, self.writer = await asyncio.open_connection(
            "127.0.0.1", self.port, ssl=ctx, server_hostname=self.relay_host
        )
        self.writer.write(line or f"CMTUNNEL/1 {self.cloud_id} {self.token}\n".encode())
        await self.writer.drain()
        answer = (await self.reader.readline()).decode().strip()
        if not answer.startswith("OK "):
            self.writer.close()
            raise Refused(answer)
        self.hostname = answer[3:]
        self.task = asyncio.create_task(self._run())
        return self.hostname

    async def send(self, ftype: int, sid: int, payload: bytes = b"") -> None:
        self.writer.write(HEADER.pack(ftype, sid, len(payload)) + payload)
        await self.writer.drain()

    async def _run(self) -> None:
        try:
            while True:
                ftype, sid, length = HEADER.unpack(await self.reader.readexactly(HEADER.size))
                payload = await self.reader.readexactly(length) if length else b""
                if ftype == OPEN:
                    info = json.loads(payload)
                    self.opens.append(info)
                    stream = BoxStream(self, sid, info)
                    self.streams[sid] = stream
                    stream.task = asyncio.create_task(stream.run(self.upstreams.get(info["port"])))
                elif ftype == DATA:
                    stream = self.streams.get(sid)
                    if stream:
                        stream.inbox.append(payload)
                        stream.inbox_event.set()
                elif ftype == WINDOW:
                    stream = self.streams.get(sid)
                    if stream:
                        stream.send_window += int.from_bytes(payload, "big")
                        stream.window_event.set()
                elif ftype == CLOSE:
                    stream = self.streams.get(sid)
                    if stream:
                        stream.relay_closed = True
                        stream.inbox_event.set()
                elif ftype == PING:
                    self.pings_seen += 1
                    if self.answer_pings:
                        await self.send(PONG, 0, payload)
        except (asyncio.IncompleteReadError, ConnectionError, OSError, ssl.SSLError):
            pass
        finally:
            self.closed.set()

    async def drop(self) -> None:
        """Vanish, the way a box does when its network goes."""
        if self.task:
            self.task.cancel()
        if self.writer:
            self.writer.transport.abort()
        for stream in list(self.streams.values()):
            if stream.task:
                stream.task.cancel()
        self.closed.set()

    async def close(self) -> None:
        await self.drop()
