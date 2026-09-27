"""The zone's authoritative DNS, asked over UDP and TCP."""

from __future__ import annotations

import asyncio
import socket

import pytest
from dnslib import QTYPE, RCODE, DNSRecord

from conftest import MESH, RELAY, ZONE, auth


async def ask(svc, name: str, qtype: str = "A", tcp: bool = False) -> DNSRecord:
    query = DNSRecord.question(name, qtype)
    data = await asyncio.to_thread(query.send, "127.0.0.1", svc.dns_port, tcp=tcp, timeout=3)
    return DNSRecord.parse(data)


def answers(reply: DNSRecord) -> list[str]:
    return sorted(str(rr.rdata) for rr in reply.rr)


@pytest.mark.parametrize("tcp", [False, True])
async def test_relay_names(svc, tcp):
    for host in (RELAY, MESH, f"ns1.{ZONE}"):
        reply = await ask(svc, host, "A", tcp)
        assert reply.header.aa == 1 and answers(reply) == ["203.0.113.7"]
    assert answers(await ask(svc, RELAY, "AAAA", tcp)) == ["2001:db8::7"]


async def test_apex_and_static_records(svc):
    assert answers(await ask(svc, ZONE, "A")) == ["198.51.100.1"]
    assert answers(await ask(svc, ZONE, "NS")) == [f"ns1.{ZONE}."]
    assert answers(await ask(svc, ZONE, "MX")) == [f"10 mail.{ZONE}."]
    soa = await ask(svc, ZONE, "SOA")
    assert soa.rr[0].rtype == QTYPE.SOA
    www = await ask(svc, f"www.{ZONE}", "A")
    assert www.rr[0].rtype == QTYPE.CNAME


async def test_public_cloud_points_at_the_relay(svc, enrol):
    await enrol("larsens")
    assert answers(await ask(svc, f"larsens.{ZONE}")) == ["203.0.113.7"]
    assert answers(await ask(svc, f"LarSens.{ZONE}", "AAAA")) == ["2001:db8::7"]


async def test_private_cloud_points_at_its_mesh_address(svc, api, enrol):
    cloud = await enrol("larsens")
    h = auth(cloud["token"])
    key = (await api.post("/v1/clouds/me/mesh/keys", headers=h)).json()
    node = (await api.post(f"http://127.0.0.1:{svc.fake.port}/fake/join", json={"key": key["key"]})).json()["node"]
    await api.put("/v1/clouds/me/mesh/address", json={"address": node["ipAddresses"][0]}, headers=h)
    # Public on: still the relay for everybody (the mesh has its own record).
    assert answers(await ask(svc, f"larsens.{ZONE}")) == ["203.0.113.7"]
    await api.patch("/v1/clouds/me", json={"public": False}, headers=h)
    assert answers(await ask(svc, f"larsens.{ZONE}")) == [node["ipAddresses"][0]]
    empty = await ask(svc, f"larsens.{ZONE}", "AAAA")
    assert empty.header.rcode == RCODE.NOERROR and not empty.rr and empty.auth


async def test_private_without_a_mesh_address_has_no_address(svc, api, enrol):
    cloud = await enrol("larsens")
    await api.patch("/v1/clouds/me", json={"public": False}, headers=auth(cloud["token"]))
    reply = await ask(svc, f"larsens.{ZONE}")
    assert reply.header.rcode == RCODE.NOERROR and not reply.rr


async def test_acme_update_is_visible_in_dns(svc, api, enrol):
    cloud = await enrol("larsens")
    reg = (await api.post("/v1/acme-dns/register", headers=auth(cloud["token"]))).json()
    creds = {"X-Api-User": reg["username"], "X-Api-Key": reg["password"]}
    name = f"_acme-challenge.larsens.{ZONE}"
    assert not (await ask(svc, name, "TXT")).rr
    txt = "x" * 20 + "Y" * 23
    await api.post("/v1/acme-dns/update", json={"subdomain": reg["subdomain"], "txt": txt}, headers=creds)
    reply = await ask(svc, name, "TXT")
    assert answers(reply) == [f'"{txt}"']
    assert (await ask(svc, name, "TXT", tcp=True)).rr


async def test_unknown_names_and_other_zones(svc):
    reply = await ask(svc, f"nobody.{ZONE}")
    assert reply.header.rcode == RCODE.NXDOMAIN and reply.auth[0].rtype == QTYPE.SOA
    assert (await ask(svc, f"a.b.{ZONE}")).header.rcode == RCODE.NXDOMAIN
    assert (await ask(svc, f"_acme-challenge.nobody.{ZONE}", "TXT")).header.rcode == RCODE.NXDOMAIN
    other = await ask(svc, "example.com")
    assert other.header.rcode == RCODE.REFUSED and not other.rr


async def test_garbage_gets_no_answer(svc):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.5)
    sock.sendto(b"\x00\x01garbage", ("127.0.0.1", svc.dns_port))
    with pytest.raises(socket.timeout):
        sock.recvfrom(512)
    sock.close()
    # And the server is still there.
    assert (await ask(svc, RELAY)).rr
