"""Visitors from anywhere, passed through to the cloud's box unread.

The box here is a listener on loopback standing in for the box's Caddy on
8443: it reads the PROXY protocol v2 header, then ends TLS with the box's
own certificate and says what it was asked. The fake Headscale is told
the box's mesh address is 127.0.0.1, and `box_port` points at the
listener. When the relay cannot pass a visitor through, it serves the
offline page itself, and the box must not see a byte.
"""

from __future__ import annotations

import asyncio
import ipaddress
import ssl

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from cloudmorrow_relay.conn import PlainConn, TLSConn
from cloudmorrow_relay.meshdial import PROXY_V2_SIGNATURE
from conftest import ZONE, auth, join, loopback_client, visit

ACCOUNT = "acct_0123456789abcdef01234567"


async def read_exactly(conn, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = await conn.read(n - len(data))
        if not chunk:
            raise ConnectionError("closed")
        data += chunk
    return data


class Box:
    """The box's 8443: PROXY v2, then TLS that ends here."""

    def __init__(self, ca):
        cert = ca.box
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert.cert, cert.key)
        self.cert = x509.load_pem_x509_certificate(cert.cert.read_bytes()).public_bytes(Encoding.DER)
        self.headers: list[tuple] = []
        self.connections = 0
        self.server = None
        self.port = 0

    async def handle(self, reader, writer):
        self.connections += 1
        raw = PlainConn(reader, writer)
        try:
            head = await read_exactly(raw, 16)
            assert head[:12] == PROXY_V2_SIGNATURE
            body = await read_exactly(raw, int.from_bytes(head[14:16], "big"))
            if head[12:14] == b"\x21\x11":
                src, dst = ipaddress.ip_address(body[0:4]), ipaddress.ip_address(body[4:8])
                sport, dport = int.from_bytes(body[8:10], "big"), int.from_bytes(body[10:12], "big")
                self.headers.append((str(src), sport, str(dst), dport))
            else:
                self.headers.append(head[12:14])
            tls = TLSConn(raw, self.ctx)
            await tls.handshake(5)
            request = b""
            while b"\r\n\r\n" not in request:
                chunk = await tls.read()
                if not chunk:
                    return
                request += chunk
            line = request.split(b"\r\n", 1)[0]
            body = b"box: " + line
            await tls.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(body), body))
            await tls.close()
        except (ConnectionError, ssl.SSLError, AssertionError, TimeoutError):
            await raw.close()

    async def start(self, port: int = 0):
        self.server = await asyncio.start_server(self.handle, "127.0.0.1", port)
        self.port = self.server.sockets[0].getsockname()[1]

    async def stop(self):
        self.server.close()
        await self.server.wait_closed()


@pytest.fixture
async def box(ca):
    b = Box(ca)
    await b.start()
    yield b
    if b.server.is_serving():
        await b.stop()


@pytest.fixture
def extra_config(box):
    return {"box_port": box.port}


@pytest.fixture
async def linked(svc, api, link_box):
    """A cloud whose box has joined the mesh, at 127.0.0.1 as far as the
    relay knows.
    """

    async def make(name: str = "larsens", address: str = "127.0.0.1") -> dict:
        cloud = await link_box(name, ACCOUNT)
        key = (await api.post("/v1/clouds/me/mesh/keys", headers=auth(cloud["token"]))).json()
        node = await join(svc, api, key["key"])
        cloud["node"] = node["id"]
        await move(svc, cloud, address)
        return cloud

    return make


async def move(svc, cloud: dict, address: str) -> None:
    svc.fake.nodes[cloud["node"]]["ipAddresses"] = [address]
    await svc.meshwatch.refresh()
    assert svc.store.cloud(cloud["cloud_id"]).mesh_address == address


async def get(svc, name: str, path: str = "/"):
    async with loopback_client(svc.ca.path, f"https://{name}.{ZONE}:{svc.https_port}") as client:
        return await client.get(path)


async def test_a_visitor_goes_through_to_the_box(svc, box, linked):
    await linked("larsens")
    reader, writer = await visit(svc, f"larsens.{ZONE}")
    # The certificate the visitor checked is the box's own, not the relay's.
    assert writer.get_extra_info("ssl_object").getpeercert(binary_form=True) == box.cert
    writer.write(f"GET /files/a-note HTTP/1.1\r\nHost: larsens.{ZONE}\r\n\r\n".encode())
    answer = await asyncio.wait_for(reader.read(), 5)
    assert answer.endswith(b"box: GET /files/a-note HTTP/1.1")
    # The PROXY header carried the visitor's own address and port, and
    # the relay's address and port it came in on.
    visitor = writer.get_extra_info("sockname")
    assert box.headers == [("127.0.0.1", visitor[1], "127.0.0.1", svc.https_port)]
    writer.close()


async def test_every_request_goes_through(svc, box, linked):
    await linked("larsens")
    resp = await get(svc, "larsens", "/install.sh")
    assert resp.status_code == 200 and resp.text == "box: GET /install.sh HTTP/1.1"
    assert box.connections == 1


async def test_the_box_does_not_answer(svc, box, linked):
    """The box's address refuses the connection: the offline page, served
    by the relay with its own certificate, and the box sees nothing. The
    relay then leaves the box alone for a while rather than make every
    connection wait.
    """
    cloud = await linked("larsens", address="127.0.0.2")  # nothing listens there
    reader, writer = await visit(svc, f"larsens.{ZONE}")
    assert writer.get_extra_info("ssl_object").getpeercert(binary_form=True) != box.cert
    writer.close()
    resp = await get(svc, "larsens")
    assert resp.status_code == 503 and "This cloud can&#x27;t be reached right now." in resp.text
    assert box.connections == 0

    await move(svc, cloud, "127.0.0.1")
    assert (await get(svc, "larsens")).status_code == 503  # not tried again yet
    assert box.connections == 0
    svc.router._unreachable.clear()  # the wait is over
    assert (await get(svc, "larsens")).text == "box: GET / HTTP/1.1"


async def test_the_box_is_away(svc, box, linked):
    """Headscale has an address for the box, and nothing answers there."""
    await linked("larsens")
    await box.stop()
    resp = await get(svc, "larsens")
    assert resp.status_code == 503 and "reached right now" in resp.text


async def test_off_the_internet_nothing_goes_through(svc, box, linked, api):
    cloud = await linked("larsens")
    resp = await api.patch("/v1/clouds/me", json={"public": False}, headers=auth(cloud["token"]))
    assert resp.json()["public"] is False
    resp = await get(svc, "larsens")
    assert resp.status_code == 503 and "This cloud opens at home and on its own devices." in resp.text
    assert box.connections == 0
    await api.patch("/v1/clouds/me", json={"public": True}, headers=auth(cloud["token"]))
    assert (await get(svc, "larsens")).text == "box: GET / HTTP/1.1"


async def test_no_box_on_the_mesh_yet(svc, box, link_box):
    await link_box("larsens", ACCOUNT)
    assert (await get(svc, "larsens")).status_code == 503
    assert box.connections == 0


async def test_a_name_with_no_cloud(svc, box):
    resp = await get(svc, "nobody")
    assert resp.status_code == 404 and "There is no cloud here." in resp.text
    assert box.connections == 0


class Socks5:
    """A SOCKS5 proxy like tailscaled's (no authentication, CONNECT only),
    or one that never answers.
    """

    def __init__(self, silent: bool = False):
        self.silent = silent
        self.asked: list[tuple[str, int]] = []

    async def handle(self, reader, writer):
        try:
            assert await reader.readexactly(3) == b"\x05\x01\x00"
            if self.silent:
                await asyncio.sleep(30)
                return
            writer.write(b"\x05\x00")
            head = await reader.readexactly(4)
            assert head[:3] == b"\x05\x01\x00"
            size = 4 if head[3] == 1 else 16
            host = str(ipaddress.ip_address(await reader.readexactly(size)))
            port = int.from_bytes(await reader.readexactly(2), "big")
            self.asked.append((host, port))
            try:
                up_r, up_w = await asyncio.open_connection(host, port)
            except OSError:
                writer.write(b"\x05\x05\x00\x01" + bytes(6))  # connection refused
                return
            writer.write(b"\x05\x00\x00\x01" + bytes(4) + bytes(2))

            async def pipe(r, w):
                while data := await r.read(65536):
                    w.write(data)
                    await w.drain()
                w.close()

            await asyncio.gather(pipe(reader, up_w), pipe(up_r, writer), return_exceptions=True)
        except (asyncio.IncompleteReadError, ConnectionError, AssertionError):
            pass
        finally:
            writer.close()


@pytest.fixture
async def socks():
    proxy = Socks5()
    server = await asyncio.start_server(proxy.handle, "127.0.0.1", 0)
    proxy.port = server.sockets[0].getsockname()[1]
    yield proxy
    server.close()


class TestThroughSocks5:
    @pytest.fixture
    def extra_config(self, box, socks):
        return {"box_port": box.port, "mesh_dial": f"socks5://127.0.0.1:{socks.port}"}

    async def test_through_a_userspace_tailscaled(self, svc, box, socks, linked):
        await linked("larsens")
        resp = await get(svc, "larsens", "/")
        assert resp.status_code == 200 and resp.text == "box: GET / HTTP/1.1"
        assert socks.asked == [("127.0.0.1", box.port)]
        assert box.headers[0][0] == "127.0.0.1" and box.headers[0][3] == svc.https_port

    async def test_the_proxy_cannot_reach_the_box(self, svc, box, socks, linked):
        await linked("larsens", address="127.0.0.2")
        resp = await get(svc, "larsens")
        assert resp.status_code == 503 and socks.asked == [("127.0.0.2", box.port)]


class TestNoAnswerInTime:
    @pytest.fixture
    async def silent(self):
        proxy = Socks5(silent=True)
        server = await asyncio.start_server(proxy.handle, "127.0.0.1", 0)
        proxy.port = server.sockets[0].getsockname()[1]
        yield proxy
        server.close()

    @pytest.fixture
    def limits(self, limits):
        return limits | {"box_connect_timeout": 0.5}

    @pytest.fixture
    def extra_config(self, box, silent):
        return {"box_port": box.port, "mesh_dial": f"socks5://127.0.0.1:{silent.port}"}

    async def test_the_offline_page_after_the_timeout(self, svc, box, linked):
        await linked("larsens")
        loop = asyncio.get_running_loop()
        started = loop.time()
        resp = await get(svc, "larsens")
        took = loop.time() - started
        assert resp.status_code == 503 and "reached right now" in resp.text
        assert 0.4 < took < 3
        assert box.connections == 0
