"""Reading the name out of hostile first bytes."""

from __future__ import annotations

import asyncio
import random
import ssl

import pytest

from cloudmorrow_relay import sni
from cloudmorrow_relay.conn import Conn


def client_hello(server_name: str | None) -> bytes:
    """A real ClientHello, from Python's own TLS client."""
    ctx = ssl.create_default_context()
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(incoming, outgoing, server_hostname=server_name) if server_name else None
    if obj is None:
        ctx.check_hostname = False
        obj = ctx.wrap_bio(incoming, outgoing)
    with pytest.raises(ssl.SSLWantReadError):
        obj.do_handshake()
    return outgoing.read()


class Bytes(Conn):
    """A Conn over fixed bytes, handed out in pieces of `step`."""

    def __init__(self, data: bytes, step: int = 1 << 20, stall: bool = False):
        super().__init__()
        self.data = data
        self.step = step
        self.stall = stall

    async def _read(self, n: int) -> bytes:
        if not self.data:
            if self.stall:
                await asyncio.sleep(3600)
            return b""
        out, self.data = self.data[: min(n, self.step)], self.data[min(n, self.step):]
        return out


async def test_reads_the_name_and_keeps_the_bytes():
    hello = client_hello("Larsens.Cloudmorrow.com")
    name, raw = await sni.peek_client_hello(Bytes(hello + b"after"), 16384)
    assert name == "larsens.cloudmorrow.com"
    assert raw == hello  # nothing past the hello was read


async def test_one_byte_at_a_time():
    hello = client_hello("a.example")
    name, raw = await sni.peek_client_hello(Bytes(hello, step=1), 16384)
    assert name == "a.example" and raw == hello


async def test_hello_split_across_records():
    hello = client_hello("split.example")
    body = hello[5:]
    records = b""
    for i in range(0, len(body), 100):
        part = body[i : i + 100]
        records += bytes([22, 3, 1]) + len(part).to_bytes(2, "big") + part
    name, raw = await sni.peek_client_hello(Bytes(records), 16384)
    assert name == "split.example" and raw == records


async def test_no_server_name():
    name, _ = await sni.peek_client_hello(Bytes(client_hello(None)), 16384)
    assert name is None


async def test_cap_is_respected():
    hello = client_hello("capped.example")
    name, raw = await sni.peek_client_hello(Bytes(hello), 100)
    assert name is None and len(raw) <= 100


async def test_a_silent_client_times_out():
    result = await sni.with_deadline(sni.peek_client_hello(Bytes(b"\x16\x03", stall=True), 16384), 0.2)
    assert result is None


@pytest.mark.parametrize(
    "data",
    [b"", b"\x16", b"\x17\x03\x03\x00\x05hello", b"\x16\x03\x01\x00\x00", b"\x16\x03\x01\xff\xff" + b"a" * 100,
     b"GET / HTTP/1.1\r\n\r\n", b"\x16\x02\x00\x00\x05aaaaa"],
)
async def test_garbage_is_no_name(data):
    name, _ = await sni.peek_client_hello(Bytes(data), 16384)
    assert name is None


async def test_fuzzed_hellos_never_raise():
    rng = random.Random(1234)
    hello = client_hello("fuzz.example")
    for _ in range(3000):
        mutated = bytearray(hello)
        for _ in range(rng.randint(1, 12)):
            op = rng.random()
            pos = rng.randrange(len(mutated))
            if op < 0.6:
                mutated[pos] = rng.randrange(256)
            elif op < 0.8:
                del mutated[pos : pos + rng.randint(1, 40)]
            else:
                mutated[pos:pos] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 40)))
        name, _ = await sni.peek_client_hello(Bytes(bytes(mutated)), 16384)
        assert name is None or isinstance(name, str)
        # And the parser alone, on the message without record framing.
        result = sni.parse_client_hello(bytes(mutated[5:]))
        assert result is None or isinstance(result, str)
    for _ in range(2000):
        blob = bytes(rng.randrange(256) for _ in range(rng.randint(0, 600)))
        result = sni.parse_client_hello(blob)
        assert result is None or isinstance(result, str)


def test_clean_host():
    assert sni.clean_host("Example.COM.") == "example.com"
    assert sni.clean_host(b"\xff\xfe") is None
    assert sni.clean_host("a b") is None
    assert sni.clean_host("a" * 300) is None
    assert sni.clean_host("") is None


async def test_http_head():
    head = await sni.peek_http_head(Bytes(b"GET /x?y HTTP/1.1\r\nHost: Larsens.CM.test:80\r\nA: b\r\n\r\nbody"), 8192)
    assert (head.method, head.path, head.host) == ("GET", "/x?y", "larsens.cm.test")
    assert head.raw.endswith(b"body")  # everything read is kept, to pass on


@pytest.mark.parametrize(
    "data",
    [b"GET / HTTP/1.1\r\n\r\n", b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", b"GET /\r\n\r\n",
     b"\x00\x01\x02\r\n\r\n", b"get / HTTP/1.1\r\nHost: a\r\n\r\n"],
)
async def test_http_head_without_one_host(data):
    head = await sni.peek_http_head(Bytes(data), 8192)
    assert head is None or head.host is None


async def test_http_head_is_capped():
    assert await sni.peek_http_head(Bytes(b"GET / HTTP/1.1\r\nX: " + b"a" * 10000), 8192) is None
