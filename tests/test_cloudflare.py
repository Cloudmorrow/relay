"""The Cloudflare DNS backend, against a fake Cloudflare API."""

from __future__ import annotations

import asyncio

import pytest

from cloudmorrow_relay.cloudflare import CloudflareDns
from cloudmorrow_relay.dnsbackend import DnsError
from cloudmorrow_relay.service import start_uvicorn
from conftest import ZONE, auth, join
from fakecloudflare import FakeCloudflare

TOKEN = "cf-test-token"
TAG = "cloudmorrow-relay"


@pytest.fixture
async def fake_cf(monkeypatch):
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", TOKEN)
    fake = FakeCloudflare(TOKEN, ZONE)
    # What the zone has before the relay ever runs: the wildcard, the apex,
    # and somebody's hand-made TXT at a cloud's challenge name.
    fake.add("A", f"*.{ZONE}", "178.105.27.139")
    fake.add("A", ZONE, "178.105.27.139")
    fake.add("TXT", f"_acme-challenge.larsens.{ZONE}", '"made by hand"')
    server, task = await start_uvicorn(fake.app, host="127.0.0.1", port=0)
    fake.port = server.servers[0].sockets[0].getsockname()[1]
    yield fake
    server.should_exit = True
    await task


@pytest.fixture
def extra_config(fake_cf):
    return {"dns": {"backend": "cloudflare", "cloudflare_api_url": f"http://127.0.0.1:{fake_cf.port}/client/v4"}}


def ours(fake: FakeCloudflare) -> set[tuple[str, str, str]]:
    return {(r["type"], r["name"], r["content"]) for r in fake.records.values() if r["comment"] == TAG}


async def acme_creds(api, token: str) -> dict:
    reg = (await api.post("/v1/acme-dns/register", headers=auth(token))).json()
    return {"X-Api-User": reg["username"], "X-Api-Key": reg["password"], "subdomain": reg["subdomain"]}


async def post_txt(api, creds: dict, txt: str):
    headers = {k: v for k, v in creds.items() if k != "subdomain"}
    return await api.post("/v1/acme-dns/update", json={"subdomain": creds["subdomain"], "txt": txt}, headers=headers)


async def test_no_dns_server_is_started(svc, fake_cf):
    assert svc.dns_port == 0
    assert isinstance(svc.dns, CloudflareDns)


async def test_a_cloud_needs_no_records(svc, enrol, fake_cf):
    await enrol("larsens")
    assert ours(fake_cf) == set()


async def test_acme_values_go_to_cloudflare(svc, api, enrol, fake_cf):
    cloud = await enrol("larsens")
    creds = await acme_creds(api, cloud["token"])
    for c in "abc":
        resp = await post_txt(api, creds, c * 43)
        assert resp.status_code == 200
    host = f"larsens.{ZONE}"
    assert ours(fake_cf) == {
        ("TXT", f"_acme-challenge.{host}", '"' + "c" * 43 + '"'),
        ("TXT", f"_acme-challenge.{host}", '"' + "b" * 43 + '"'),
        # The TXT hides the wildcard from <name>; this says what it would.
        ("A", host, "203.0.113.7"),
        ("AAAA", host, "2001:db8::7"),
    }
    # The hand-made record is still there, untouched.
    assert [r["content"] for r in fake_cf.find(f"_acme-challenge.{host}") if r["comment"] != TAG] == ['"made by hand"']


async def test_the_mesh_address_is_never_published(svc, api, enrol, fake_cf):
    cloud = await enrol("larsens")
    key = (await api.post("/v1/clouds/me/mesh/keys", headers=auth(cloud["token"]))).json()
    await join(svc, api, key["key"])
    await svc.meshwatch.refresh()
    assert svc.store.cloud(cloud["cloud_id"]).mesh_address
    await svc.dns.sync_all()
    assert ours(fake_cf) == set()


async def test_a_rename_moves_the_records(svc, api, admin, link_box, fake_cf):
    cloud = await link_box("larsens")
    creds = {"X-Api-User": cloud["acme_dns"]["username"], "X-Api-Key": cloud["acme_dns"]["password"],
             "subdomain": cloud["acme_dns"]["subdomain"]}
    await post_txt(api, creds, "r" * 43)
    resp = await admin.patch(f"/admin/v1/clouds/{cloud['cloud_id']}", json={"account": cloud["account"], "name": "jensens"})
    assert resp.status_code == 200
    names = {n for _, n, _ in ours(fake_cf)}
    assert names == {f"jensens.{ZONE}", f"_acme-challenge.jensens.{ZONE}"}


async def test_deleting_a_cloud_removes_its_records(svc, api, enrol, fake_cf):
    cloud = await enrol("larsens")
    creds = await acme_creds(api, cloud["token"])
    await post_txt(api, creds, "x" * 43)
    assert ours(fake_cf)
    assert (await api.delete("/v1/clouds/me", headers=auth(cloud["token"]))).status_code == 204
    assert ours(fake_cf) == set()
    assert len(fake_cf.records) == 3  # the three that were not ours


async def test_cloudflare_down_fails_the_acme_update(svc, api, enrol, fake_cf):
    cloud = await enrol("larsens")
    creds = await acme_creds(api, cloud["token"])
    fake_cf.fail = True
    resp = await post_txt(api, creds, "y" * 43)
    assert resp.status_code == 502
    assert "DNS provider" in resp.json()["detail"]
    fake_cf.fail = False
    await svc.dns.sync_all()
    assert ("TXT", f"_acme-challenge.larsens.{ZONE}", '"' + "y" * 43 + '"') in ours(fake_cf)


async def test_sync_removes_stale_records_and_adds_missing(svc, api, enrol, fake_cf):
    cloud = await enrol("larsens")
    creds = await acme_creds(api, cloud["token"])
    await post_txt(api, creds, "z" * 43)
    # A record we made for a cloud that is gone, and one of ours deleted
    # behind our back; neither touches the untagged ones.
    fake_cf.add("A", f"gone.{ZONE}", "100.64.0.9", TAG)
    for rec in list(fake_cf.records.values()):
        if rec["type"] == "AAAA" and rec["comment"] == TAG:
            del fake_cf.records[rec["id"]]
    await svc.dns.sync_all()
    names = {n for _, n, _ in ours(fake_cf)}
    assert f"gone.{ZONE}" not in names
    assert ("AAAA", f"larsens.{ZONE}", "2001:db8::7") in ours(fake_cf)
    assert len([r for r in fake_cf.records.values() if r["comment"] != TAG]) == 3


async def test_the_sync_runs_at_start(svc, fake_cf):
    for _ in range(100):
        if ("GET", f"/client/v4/zones/{fake_cf.zone_id}/dns_records") in fake_cf.calls:
            break
        await asyncio.sleep(0.02)
    assert ("GET", "/client/v4/zones") in fake_cf.calls


def test_the_token_is_required(tmp_path, monkeypatch):
    from cloudmorrow_relay.config import from_dict
    from cloudmorrow_relay.store import Store

    monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)
    cfg = from_dict({"zone": ZONE, "state_dir": str(tmp_path), "dns": {"backend": "cloudflare"}})
    with pytest.raises(DnsError, match="CLOUDFLARE_API_TOKEN"):
        CloudflareDns(cfg, Store(cfg.db_path))
