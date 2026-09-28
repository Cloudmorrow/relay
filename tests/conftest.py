"""The relay, for real, on loopback.

Every test that needs it gets a whole Service (relay, control API, DNS)
on ports the kernel picks, with a throwaway CA, a fake Headscale on its
own port, and a "box": the reference tunnel client plus two upstreams
standing in for the box's Caddy (TLS with the box's own certificate on
443, plain HTTP on 80).

Names are under `cm.test`. Nothing resolves them; clients connect to
127.0.0.1 and send the name as SNI or Host, which is all the relay sees.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import ssl
import sys
from pathlib import Path

import httpcore
import httpx
import pytest

sys.path.insert(0, str(Path(__file__).parent))

from cloudmorrow_relay.config import from_dict  # noqa: E402
from cloudmorrow_relay.devcerts import DevCA  # noqa: E402
from cloudmorrow_relay.fakeheadscale import FakeHeadscale  # noqa: E402
from cloudmorrow_relay.service import Service, start_uvicorn  # noqa: E402
from refclient import RefBox  # noqa: E402

ZONE = "cm.test"
RELAY = f"relay.{ZONE}"
MESH = f"mesh.{ZONE}"
HS_KEY = "test-headscale-key"


@pytest.fixture(scope="session")
def ca(tmp_path_factory):
    folder = tmp_path_factory.mktemp("ca")
    authority = DevCA(folder)
    authority.relay = authority.issue("relay", [RELAY, MESH])
    authority.box = authority.issue("box", [f"*.{ZONE}"])
    return authority


class Loopback(httpcore.AsyncNetworkBackend):
    """Every name is 127.0.0.1; the name still goes out as SNI and Host."""

    def __init__(self):
        self._inner = httpcore.AnyIOBackend()

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        return await self._inner.connect_tcp("127.0.0.1", port, timeout, local_address, socket_options)

    async def connect_unix_socket(self, *args, **kwargs):  # pragma: no cover
        raise NotImplementedError

    async def sleep(self, seconds):
        await self._inner.sleep(seconds)


def loopback_client(ca_path: Path, base_url: str, **kwargs) -> httpx.AsyncClient:
    ctx = ssl.create_default_context(cafile=str(ca_path))
    transport = httpx.AsyncHTTPTransport(verify=ctx)
    transport._pool = httpcore.AsyncConnectionPool(ssl_context=ctx, network_backend=Loopback())
    return httpx.AsyncClient(transport=transport, base_url=base_url, timeout=10, **kwargs)


@pytest.fixture
async def fake_hs():
    fake = FakeHeadscale(HS_KEY)
    server, task = await start_uvicorn(fake.app, host="127.0.0.1", port=0)
    fake.port = server.servers[0].sockets[0].getsockname()[1]
    yield fake
    server.should_exit = True
    await task


@pytest.fixture
def limits():
    """Tests override single limits by asking for this and changing it
    before `svc` is built.
    """
    return {
        "enrol_per_hour": 100,
        "pair_codes_per_hour": 100,
        "pair_attempts_per_10min": 100,
        "mesh_keys_per_hour": 100,
        "bad_auth_per_minute": 100,
        "peek_timeout": 2.0,
        "handshake_timeout": 2.0,
    }


@pytest.fixture
def extra_config():
    """Tests add or replace config sections by asking for this."""
    return {}


def _merge(base: dict, extra: dict) -> dict:
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge(base[key], value)
        else:
            base[key] = value
    return base


@pytest.fixture
async def svc(tmp_path, ca, fake_hs, limits, extra_config):
    webroot = tmp_path / "acme"
    cfg = from_dict(_merge({
        "zone": ZONE,
        "relay_host": RELAY,
        "login_host": MESH,
        "state_dir": str(tmp_path / "state"),
        "public_ipv4": "203.0.113.7",
        "public_ipv6": "2001:db8::7",
        "listen": {"addresses": ["127.0.0.1"], "https_port": 0, "http_port": 0, "dns_port": 0},
        "tls": {"cert": str(ca.relay.cert), "key": str(ca.relay.key), "acme_webroot": str(webroot)},
        "headscale": {
            "url": f"http://127.0.0.1:{fake_hs.port}",
            "api_key": HS_KEY,
            "extra_records_path": str(tmp_path / "extra-records.json"),
        },
        "dns": {
            "nameservers": [{"name": f"ns1.{ZONE}", "ipv4": "203.0.113.7"}],
            "records": [
                {"name": "@", "type": "A", "value": "198.51.100.1"},
                {"name": "www", "type": "CNAME", "value": f"{ZONE}."},
                {"name": "@", "type": "MX", "value": f"10 mail.{ZONE}."},
            ],
        },
        "limits": limits,
    }, extra_config))
    service = Service(cfg)
    await service.start()
    service.fake = fake_hs
    service.ca = ca
    yield service
    await service.stop()


@pytest.fixture
async def api(svc):
    async with loopback_client(svc.ca.path, f"https://{RELAY}:{svc.https_port}") as client:
        yield client


@pytest.fixture
async def enrol(api):
    async def claim(name: str = "larsens") -> dict:
        resp = await api.post("/v1/clouds", json={"name": name})
        assert resp.status_code == 201, resp.text
        return resp.json()

    return claim


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# --- the box's upstreams ---------------------------------------------------


async def _upstream_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """A stand-in for the box's Caddy, speaking a little test protocol:
    ECHO, SEND <n>, SINK <n>, or an HTTP request.
    """
    try:
        line = await reader.readline()
        if line.startswith(b"ECHO"):
            writer.write(b"READY\n")
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
        elif line.startswith(b"SEND "):
            n = int(line.split()[1])
            block = bytes(range(256)) * 256
            sent = 0
            while sent < n:
                chunk = block[: min(len(block), n - sent)]
                writer.write(chunk)
                await writer.drain()
                sent += len(chunk)
        elif line.startswith(b"SINK "):
            n = int(line.split()[1])
            digest = hashlib.sha256()
            total = 0
            while total < n and (data := await reader.read(min(65536, n - total))):
                digest.update(data)
                total += len(data)
            writer.write(f"{total} {digest.hexdigest()}\n".encode())
            await writer.drain()
        elif b"HTTP/1." in line:
            head = [line]
            while (h := await reader.readline()) not in (b"\r\n", b"\n", b""):
                head.append(h)
            host = next((h.split(b":", 1)[1].strip() for h in head if h.lower().startswith(b"host:")), b"")
            path = line.split(b" ")[1]
            body = b"box saw host=" + host + b" path=" + path
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode()
                + b"\r\nConnection: close\r\n\r\n" + body
            )
            await writer.drain()
    except (ConnectionError, OSError, ssl.SSLError):
        pass
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


@pytest.fixture
async def upstreams(ca):
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(ca.box.cert, ca.box.key)
    tls = await asyncio.start_server(_upstream_handler, "127.0.0.1", 0, ssl=ctx)
    plain = await asyncio.start_server(_upstream_handler, "127.0.0.1", 0)
    ports = {443: ("127.0.0.1", tls.sockets[0].getsockname()[1]), 80: ("127.0.0.1", plain.sockets[0].getsockname()[1])}
    yield ports
    tls.close()
    plain.close()


@pytest.fixture
async def box(svc, enrol, upstreams):
    """A claimed cloud with its tunnel up."""
    cloud = await enrol("larsens")
    ref = RefBox(svc.https_port, str(svc.ca.path), cloud["cloud_id"], cloud["token"], upstreams, RELAY)
    await ref.connect()
    for _ in range(100):
        if svc.registry.get(cloud["cloud_id"]):
            break
        await asyncio.sleep(0.01)
    ref.cloud = cloud
    yield ref
    await ref.close()


async def visit(svc, name: str, *, ca_path=None, verify: bool = True):
    """A visitor's TLS connection to `name` through the relay."""
    ctx = ssl.create_default_context(cafile=str(ca_path or svc.ca.path))
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return await asyncio.open_connection("127.0.0.1", svc.https_port, ssl=ctx, server_hostname=name)
