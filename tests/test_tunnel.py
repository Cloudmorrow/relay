"""End to end: visitors through the relay, over a tunnel, to a box."""

from __future__ import annotations

import asyncio
import hashlib
import ssl
import struct

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from conftest import RELAY, ZONE, auth, visit
from refclient import CLOSE, DATA, HEADER, OPEN, RefBox, Refused


def _box_cert_der(ca) -> bytes:
    # The file is the leaf followed by the CA; load_pem takes the first.
    return x509.load_pem_x509_certificate(ca.box.cert.read_bytes()).public_bytes(Encoding.DER)


async def test_handshake_names_the_cloud(box):
    assert box.hostname == f"larsens.{ZONE}"


async def test_visitor_gets_the_boxs_own_certificate(svc, box):
    reader, writer = await visit(svc, f"larsens.{ZONE}")
    ssl_obj = writer.get_extra_info("ssl_object")
    # The certificate the visitor verified is the box's, not the relay's:
    # TLS went through the relay untouched.
    assert ssl_obj.getpeercert(binary_form=True) == _box_cert_der(svc.ca)
    writer.write(b"ECHO\n")
    assert await reader.readline() == b"READY\n"
    writer.write(b"hello box")
    assert await reader.readexactly(9) == b"hello box"
    writer.close()
    assert box.opens[0]["port"] == 443
    assert box.opens[0]["remote"].startswith("127.0.0.1:")


async def test_relay_host_is_the_relays_own_certificate(svc):
    reader, writer = await visit(svc, RELAY)
    cert = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
    assert cert != _box_cert_der(svc.ca)
    writer.close()


async def test_port_80_routes_by_host(svc, box):
    reader, writer = await asyncio.open_connection("127.0.0.1", svc.http_port)
    writer.write(f"GET /.well-known/acme-challenge/abc HTTP/1.1\r\nHost: Larsens.{ZONE}:80\r\n\r\n".encode())
    body = await asyncio.wait_for(reader.read(), 5)
    assert b"200 OK" in body
    assert body.endswith(f"box saw host=Larsens.{ZONE}:80 path=/.well-known/acme-challenge/abc".encode())
    assert box.opens[-1]["port"] == 80


async def test_large_download_respects_windows(svc, box):
    size = 12 * 1024 * 1024
    reader, writer = await visit(svc, f"larsens.{ZONE}")
    writer.write(f"SEND {size}\n".encode())
    await writer.drain()
    tunnel = svc.registry.get(box.cloud["cloud_id"])
    # A visitor that does not read: the box may fill the window and no
    # more, so the relay holds at most 256 KiB for this stream.
    await asyncio.sleep(0.5)
    buffered = max((s._inbox_bytes for s in tunnel.streams.values()), default=0)
    assert 0 < buffered <= 256 * 1024
    got = 0
    digest = hashlib.sha256()
    while got < size:
        chunk = await asyncio.wait_for(reader.read(1 << 20), 10)
        assert chunk
        digest.update(chunk)
        got += len(chunk)
    block = bytes(range(256)) * 256
    expected = hashlib.sha256(block * (size // len(block))).hexdigest()
    assert digest.hexdigest() == expected
    assert tunnel.bytes_out >= size
    writer.close()


async def test_large_upload(svc, box):
    size = 6 * 1024 * 1024 + 17
    payload = bytes((i * 7) % 251 for i in range(size))
    reader, writer = await visit(svc, f"larsens.{ZONE}")
    writer.write(f"SINK {size}\n".encode())
    writer.write(payload)
    await writer.drain()
    answer = await asyncio.wait_for(reader.readline(), 20)
    assert answer.decode().split() == [str(size), hashlib.sha256(payload).hexdigest()]
    assert svc.registry.get(box.cloud["cloud_id"]).bytes_in >= size
    writer.close()


async def test_many_streams_at_once(svc, box):
    async def one(i: int):
        reader, writer = await visit(svc, f"larsens.{ZONE}")
        writer.write(b"ECHO\n")
        assert await reader.readline() == b"READY\n"
        message = f"stream {i} ".encode() * 1000
        writer.write(message)
        assert await asyncio.wait_for(reader.readexactly(len(message)), 10) == message
        writer.close()

    await asyncio.gather(*(one(i) for i in range(25)))


async def test_box_closing_ends_the_visit(svc, box):
    reader, writer = await asyncio.open_connection("127.0.0.1", svc.http_port)
    writer.write(f"GET / HTTP/1.1\r\nHost: larsens.{ZONE}\r\n\r\n".encode())
    data = await asyncio.wait_for(reader.read(), 5)  # read() to EOF: the relay closed
    assert data.endswith(b"path=/")


async def test_unknown_names_are_closed(svc, box):
    for name in (f"nobody.{ZONE}", "example.com", f"a.larsens.{ZONE}"):
        with pytest.raises((ssl.SSLError, ConnectionError, OSError)):
            await visit(svc, name, verify=False)
    reader, writer = await asyncio.open_connection("127.0.0.1", svc.http_port)
    writer.write(f"GET / HTTP/1.1\r\nHost: nobody.{ZONE}\r\n\r\n".encode())
    assert await asyncio.wait_for(reader.read(), 5) == b""


async def test_garbage_and_slow_clients_are_dropped(svc, limits):
    reader, writer = await asyncio.open_connection("127.0.0.1", svc.https_port)
    writer.write(b"GET / HTTP/1.1\r\n\r\n")
    assert await asyncio.wait_for(reader.read(), 5) == b""
    # One byte of a record header, then nothing: gone after the peek timeout.
    reader, writer = await asyncio.open_connection("127.0.0.1", svc.https_port)
    writer.write(b"\x16")
    started = asyncio.get_running_loop().time()
    assert await asyncio.wait_for(reader.read(), 10) == b""
    assert asyncio.get_running_loop().time() - started < limits["peek_timeout"] + 2


async def test_name_without_a_tunnel_is_closed(svc, enrol):
    await enrol("quiet")
    with pytest.raises((ssl.SSLError, ConnectionError, OSError)):
        await visit(svc, f"quiet.{ZONE}", verify=False)


async def test_bad_credentials_are_refused(svc, enrol, upstreams):
    cloud = await enrol("larsens")
    wrong = RefBox(svc.https_port, str(svc.ca.path), cloud["cloud_id"], "cmr_wrong", upstreams, RELAY)
    with pytest.raises(Refused, match="NO unknown cloud or wrong token"):
        await wrong.connect()
    stranger = RefBox(svc.https_port, str(svc.ca.path), "0000000000000000", cloud["token"], upstreams, RELAY)
    with pytest.raises(Refused, match="^NO "):
        await stranger.connect()
    garbled = RefBox(svc.https_port, str(svc.ca.path), cloud["cloud_id"], cloud["token"], upstreams, RELAY)
    with pytest.raises(Refused, match="NO not a cmtunnel/1 handshake"):
        await garbled.connect(b"CMTUNNEL/1 just-two\n")


async def test_private_cloud_is_refused(svc, api, enrol, upstreams):
    cloud = await enrol("larsens")
    resp = await api.patch("/v1/clouds/me", json={"public": False}, headers=auth(cloud["token"]))
    assert resp.status_code == 200
    ref = RefBox(svc.https_port, str(svc.ca.path), cloud["cloud_id"], cloud["token"], upstreams, RELAY)
    with pytest.raises(Refused, match="public access is off"):
        await ref.connect()


async def test_turning_public_off_drops_the_tunnel(svc, api, box):
    resp = await api.patch("/v1/clouds/me", json={"public": False}, headers=auth(box.cloud["token"]))
    assert resp.status_code == 200
    await asyncio.wait_for(box.closed.wait(), 5)
    assert svc.registry.get(box.cloud["cloud_id"]) is None


async def test_reconnect_after_the_box_drops(svc, box, upstreams):
    await box.drop()
    cloud_id = box.cloud["cloud_id"]
    for _ in range(200):
        if svc.registry.get(cloud_id) is None:
            break
        await asyncio.sleep(0.02)
    assert svc.registry.get(cloud_id) is None
    with pytest.raises((ssl.SSLError, ConnectionError, OSError)):
        await visit(svc, f"larsens.{ZONE}", verify=False)

    again = RefBox(svc.https_port, str(svc.ca.path), cloud_id, box.cloud["token"], upstreams, RELAY)
    await again.connect()
    reader, writer = await visit(svc, f"larsens.{ZONE}")
    writer.write(b"ECHO\n")
    assert await reader.readline() == b"READY\n"
    writer.close()
    await again.close()


async def test_a_second_tunnel_replaces_the_first(svc, box, upstreams):
    second = RefBox(svc.https_port, str(svc.ca.path), box.cloud["cloud_id"], box.cloud["token"], upstreams, RELAY)
    await second.connect()
    await asyncio.wait_for(box.closed.wait(), 5)
    reader, writer = await visit(svc, f"larsens.{ZONE}")
    writer.write(b"ECHO\n")
    assert await reader.readline() == b"READY\n"
    assert second.opens and not box.opens
    writer.close()
    await second.close()


@pytest.fixture
def quick_pings(limits):
    limits["ping_after"] = 0.3
    limits["dead_after"] = 1.2


async def test_pings_keep_a_quiet_tunnel(quick_pings, svc, box):
    await asyncio.sleep(2.0)
    assert box.pings_seen >= 1
    assert svc.registry.get(box.cloud["cloud_id"]) is not None


async def test_a_silent_box_is_dropped(quick_pings, svc, box):
    box.answer_pings = False
    await asyncio.wait_for(box.closed.wait(), 5)
    assert svc.registry.get(box.cloud["cloud_id"]) is None


async def test_box_opening_a_stream_breaks_the_tunnel(svc, box):
    await box.send(OPEN, 99, b'{"port": 443}')
    await asyncio.wait_for(box.closed.wait(), 5)


async def test_oversized_frame_breaks_the_tunnel(svc, box):
    box.writer.write(HEADER.pack(DATA, 1, 1 << 20))
    await box.writer.drain()
    await asyncio.wait_for(box.closed.wait(), 5)


async def test_overrunning_the_window_breaks_the_tunnel(svc, box):
    # A visitor that stops reading, and a box that ignores its window:
    # once the relay holds more than 256 KiB for the stream (past what the
    # kernel's socket buffers soak up), it ends the tunnel.
    reader, writer = await visit(svc, f"larsens.{ZONE}")
    writer.write(b"ECHO\n")
    assert await reader.readline() == b"READY\n"
    writer.transport.pause_reading()
    sid = next(iter(box.streams))
    chunk = b"x" * 65536
    for _ in range(256):  # 16 MiB with no credit
        if box.closed.is_set():
            break
        try:
            await box.send(DATA, sid, chunk)
        except (ConnectionError, OSError):
            break
    await asyncio.wait_for(box.closed.wait(), 5)
    writer.close()


async def test_unknown_frame_types_are_skipped(svc, box):
    await box.send(42, 0, b"from the future")
    await box.send(CLOSE, 12345)  # a stream the relay never opened
    reader, writer = await visit(svc, f"larsens.{ZONE}")
    writer.write(b"ECHO\n")
    assert await reader.readline() == b"READY\n"
    writer.close()


async def test_bytes_are_counted(svc, api, box):
    reader, writer = await visit(svc, f"larsens.{ZONE}")
    writer.write(b"ECHO\n")
    assert await reader.readline() == b"READY\n"
    writer.close()
    resp = await api.get("/v1/clouds/me", headers=auth(box.cloud["token"]))
    record = resp.json()
    assert record["tunnel"]["connected"] is True
    assert record["tunnel"]["connected_since"]
    assert record["bytes_in"] > 0 and record["bytes_out"] > 0


def test_header_layout():
    # The contract's 9 bytes: type, stream (BE), length (BE).
    assert HEADER.size == 9
    assert HEADER.pack(2, 1, 5) == b"\x02\x00\x00\x00\x01\x00\x00\x00\x05"
    assert struct.calcsize(">BII") == 9


async def test_certificate_reload(svc):
    """SIGHUP's work: new files, new connections get the new certificate,
    and a missing file keeps the old one rather than going dark.
    """
    before = await visit(svc, RELAY)
    old = before[1].get_extra_info("ssl_object").getpeercert(binary_form=True)
    fresh = svc.ca.issue("relay-renewed", [RELAY])
    svc.certs.cert, svc.certs.key = fresh.cert, fresh.key
    svc.reload_certs()
    after = await visit(svc, RELAY)
    new = after[1].get_extra_info("ssl_object").getpeercert(binary_form=True)
    assert new != old
    svc.certs.cert = fresh.cert.with_name("missing.pem")
    assert svc.certs.reload() is False
    still = await visit(svc, RELAY)
    assert still[1].get_extra_info("ssl_object").getpeercert(binary_form=True) == new
    for _, writer in (before, after, still):
        writer.close()
