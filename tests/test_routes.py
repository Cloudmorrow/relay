"""Static routes: the website on the same machine, passed through untouched."""

from __future__ import annotations

import asyncio
import ssl

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from conftest import RELAY, visit


@pytest.fixture
async def website(ca):
    """A stand-in for the local Caddy: TLS with its own certificate on one
    port, plain HTTP on another; both say what they saw first.
    """
    site = ca.issue("website", ["cloudmorrow.com", "www.cloudmorrow.com"])
    seen: list[bytes] = []

    async def handler(reader, writer):
        line = await reader.readline()
        seen.append(line)
        if line.startswith(b"PROXY "):
            line = await reader.readline()
        while (await reader.readline()) not in (b"\r\n", b""):
            pass
        body = b"website: " + line.strip()
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(body), body))
        await writer.drain()
        writer.close()

    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(site.cert, site.key)
    tls = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=ctx)
    plain = await asyncio.start_server(handler, "127.0.0.1", 0)
    info = {
        "tls": tls.sockets[0].getsockname()[1],
        "plain": plain.sockets[0].getsockname()[1],
        "cert": x509.load_pem_x509_certificate(site.cert.read_bytes()).public_bytes(Encoding.DER),
        "seen": seen,
    }
    yield info
    tls.close()
    plain.close()


@pytest.fixture
def extra_config(website):
    return {"routes": [
        {"sni": ["cloudmorrow.com", "www.cloudmorrow.com"], "upstream": f"127.0.0.1:{website['tls']}"},
        {"host": ["cloudmorrow.com", "www.cloudmorrow.com"], "upstream": f"127.0.0.1:{website['plain']}", "proxy_protocol": True},
    ]}


async def test_website_tls_passes_through(svc, website):
    reader, writer = await visit(svc, "www.cloudmorrow.com")
    assert writer.get_extra_info("ssl_object").getpeercert(binary_form=True) == website["cert"]
    writer.write(b"GET /shop HTTP/1.1\r\nHost: www.cloudmorrow.com\r\n\r\n")
    assert (await asyncio.wait_for(reader.read(), 5)).endswith(b"website: GET /shop HTTP/1.1")
    assert website["seen"][-1].startswith(b"GET")  # no PROXY line on this route


async def test_website_port_80_with_proxy_protocol(svc, website):
    reader, writer = await asyncio.open_connection("127.0.0.1", svc.http_port)
    writer.write(b"GET / HTTP/1.1\r\nHost: cloudmorrow.com\r\n\r\n")
    assert (await asyncio.wait_for(reader.read(), 5)).endswith(b"website: GET / HTTP/1.1")
    proxy = website["seen"][-1].decode().split()
    assert proxy[:2] == ["PROXY", "TCP4"] and proxy[2] == "127.0.0.1" and proxy[5] == str(svc.http_port)


async def test_the_relays_own_names_are_still_its_own(svc, api, website):
    reader, writer = await visit(svc, RELAY)
    assert writer.get_extra_info("ssl_object").getpeercert(binary_form=True) != website["cert"]
    writer.close()
    assert (await api.post("/v1/clouds", json={"name": "larsens"})).status_code == 201


async def test_route_down_closes(svc, website, extra_config):
    svc.router.sni_routes["cloudmorrow.com"].upstream = ("127.0.0.1", 1)
    with pytest.raises((ssl.SSLError, ConnectionError, OSError)):
        await visit(svc, "cloudmorrow.com", verify=False)
