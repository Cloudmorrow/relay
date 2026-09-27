"""The control API over the relay's own TLS, as a box calls it."""

from __future__ import annotations

import asyncio
import json

import pytest

from conftest import MESH, RELAY, ZONE, auth


async def test_claim_a_name(api, svc):
    resp = await api.post("/v1/clouds", json={"name": "  Larsens "})
    assert resp.status_code == 201
    body = resp.json()
    assert set(body) == {"cloud_id", "token", "name", "zone", "public_host", "relay_host", "login_server"}
    assert body["name"] == "larsens"
    assert body["zone"] == ZONE
    assert body["public_host"] == f"larsens.{ZONE}"
    assert body["relay_host"] == RELAY
    assert body["login_server"] == f"https://{MESH}:{svc.cfg.https_port}" or body["login_server"].startswith(f"https://{MESH}")
    # Only the hash is kept.
    row = svc.store._one("SELECT token_hash FROM clouds WHERE id = ?", body["cloud_id"])
    assert body["token"] not in row["token_hash"]


@pytest.mark.parametrize(
    "name, problem",
    [
        ("ab", "3 to 40"),
        ("a" * 41, "3 to 40"),
        ("-abc", "starts and ends"),
        ("abc-", "starts and ends"),
        ("ab_c", "a-z, 0-9"),
        ("ab.c", "a-z, 0-9"),
        ("xn--abc", "two hyphens"),
        ("www", "reserved"),
        ("relay", "reserved"),
        ("mesh", "reserved"),
        ("ns1", "reserved"),
        ("api", "reserved"),
        ("mail", "reserved"),
        ("blåbær", "a-z, 0-9"),
    ],
)
async def test_name_rules(api, name, problem):
    resp = await api.post("/v1/clouds", json={"name": name})
    assert resp.status_code == 422
    assert problem in resp.json()["detail"]


async def test_fullwidth_letters_fold(api):
    resp = await api.post("/v1/clouds", json={"name": "ＬＡＲＳＥＮＳ"})
    assert resp.status_code == 201 and resp.json()["name"] == "larsens"


async def test_taken(api, enrol):
    await enrol("larsens")
    resp = await api.post("/v1/clouds", json={"name": "LARSENS"})
    assert resp.status_code == 409
    assert resp.json() == {"detail": "The name larsens is taken."}


async def test_errors_are_sentences(api):
    resp = await api.post("/v1/clouds", content=b"{not json", headers={"content-type": "application/json"})
    assert resp.status_code == 422
    assert isinstance(resp.json()["detail"], str)
    resp = await api.post("/v1/clouds", json={})
    assert resp.status_code == 422 and isinstance(resp.json()["detail"], str)
    resp = await api.get("/v1/nothing")
    assert resp.status_code == 404 and resp.json() == {"detail": "There is nothing here."}


async def test_token_required(api, enrol):
    await enrol()
    for headers in ({}, auth("cmr_nope"), {"Authorization": "Basic abc"}):
        resp = await api.get("/v1/clouds/me", headers=headers)
        assert resp.status_code == 401
        assert resp.json() == {"detail": "A valid token is required."}


async def test_record(api, enrol):
    cloud = await enrol()
    resp = await api.get("/v1/clouds/me", headers=auth(cloud["token"]))
    assert resp.status_code == 200
    rec = resp.json()
    assert rec["name"] == "larsens" and rec["public"] is True
    assert rec["tunnel"] == {"connected": False, "connected_since": None}
    assert rec["bytes_in"] == 0 and rec["mesh_address"] is None and rec["devices"] == []


async def test_rename(api, enrol):
    one = await enrol("larsens")
    await enrol("hansens")
    h = auth(one["token"])
    assert (await api.patch("/v1/clouds/me", json={"name": "hansens"}, headers=h)).status_code == 409
    assert (await api.patch("/v1/clouds/me", json={"name": "www"}, headers=h)).status_code == 422
    resp = await api.patch("/v1/clouds/me", json={"name": "Jensens"}, headers=h)
    assert resp.status_code == 200 and resp.json()["name"] == "jensens"
    # The old name is free again.
    assert (await api.post("/v1/clouds", json={"name": "larsens"})).status_code == 201


async def test_give_the_name_back(api, enrol, svc):
    cloud = await enrol()
    h = auth(cloud["token"])
    key = await api.post("/v1/clouds/me/mesh/keys", json={"for": "the box"}, headers=h)
    assert key.status_code == 201
    await api.post(f"http://127.0.0.1:{svc.fake.port}/fake/join", json={"key": key.json()["key"]})
    assert svc.fake.nodes
    resp = await api.delete("/v1/clouds/me", headers=h)
    assert resp.status_code == 204 and resp.content == b""
    assert (await api.get("/v1/clouds/me", headers=h)).status_code == 401
    assert not svc.fake.nodes and not svc.fake.users
    assert (await api.post("/v1/clouds", json={"name": "larsens"})).status_code == 201


async def test_delete_keeps_the_cloud_if_headscale_is_down(api, enrol, svc):
    cloud = await enrol()
    h = auth(cloud["token"])
    await api.post("/v1/clouds/me/mesh/keys", headers=h)  # makes the user
    svc.fake.api_key = "rotated"  # Headscale now refuses us
    resp = await api.delete("/v1/clouds/me", headers=h)
    assert resp.status_code == 502
    assert (await api.get("/v1/clouds/me", headers=h)).status_code == 200


@pytest.fixture
def one_enrolment(limits):
    limits["enrol_per_hour"] = 2


async def test_enrolment_is_rate_limited(one_enrolment, api):
    assert (await api.post("/v1/clouds", json={"name": "one1"})).status_code == 201
    assert (await api.post("/v1/clouds", json={"name": "two2"})).status_code == 201
    resp = await api.post("/v1/clouds", json={"name": "three"})
    assert resp.status_code == 429 and "Try again later" in resp.json()["detail"]


@pytest.fixture
def few_failures(limits):
    limits["bad_auth_per_minute"] = 3


async def test_guessing_tokens_is_rate_limited(few_failures, api):
    codes = [(await api.get("/v1/clouds/me", headers=auth(f"cmr_{i}"))).status_code for i in range(5)]
    assert codes == [401, 401, 401, 429, 429]


async def test_body_cap(api):
    big = json.dumps({"name": "a" * 40000})
    resp = await api.post("/v1/clouds", content=big, headers={"content-type": "application/json"})
    assert resp.status_code == 413
    assert resp.json() == {"detail": "The request body is too large."}

    async def chunks():
        for _ in range(40):
            yield b" " * 1024

    resp = await api.post("/v1/clouds", content=chunks(), headers={"content-type": "application/json"})
    assert resp.status_code == 413


async def test_mesh_key(api, enrol, svc):
    cloud = await enrol()
    resp = await api.post("/v1/clouds/me/mesh/keys", json={"for": "the box", "expires_in": 600}, headers=auth(cloud["token"]))
    assert resp.status_code == 201
    body = resp.json()
    assert set(body) == {"key", "login_server", "expires_at"}
    assert body["login_server"].startswith(f"https://{MESH}")
    user = svc.fake.user_by_name(f"cloud-{cloud['cloud_id']}")
    key = next(iter(svc.fake.keys.values()))
    assert key["user"] == user and key["reusable"] is False and key["ephemeral"] is False
    bad = await api.post("/v1/clouds/me/mesh/keys", json={"expires_in": 5}, headers=auth(cloud["token"]))
    assert bad.status_code == 422


async def test_devices(api, enrol, svc):
    one, two = await enrol("larsens"), await enrol("hansens")
    k1 = (await api.post("/v1/clouds/me/mesh/keys", json={"for": "Jimmi's laptop"}, headers=auth(one["token"]))).json()
    k2 = (await api.post("/v1/clouds/me/mesh/keys", headers=auth(two["token"]))).json()
    n1 = (await api.post(f"http://127.0.0.1:{svc.fake.port}/fake/join", json={"key": k1["key"], "hostname": "laptop"})).json()["node"]
    n2 = (await api.post(f"http://127.0.0.1:{svc.fake.port}/fake/join", json={"key": k2["key"]})).json()["node"]

    resp = await api.get("/v1/clouds/me/mesh/devices", headers=auth(one["token"]))
    assert resp.status_code == 200
    devices = resp.json()["devices"]
    assert [d["id"] for d in devices] == [n1["id"]]
    assert devices[0]["label"] == "Jimmi's laptop" and devices[0]["name"] == "laptop"
    assert devices[0]["addresses"] == n1["ipAddresses"]

    # Another cloud's device is not ours to remove.
    resp = await api.delete(f"/v1/clouds/me/mesh/devices/{n2['id']}", headers=auth(one["token"]))
    assert resp.status_code == 404
    assert n2["id"] in svc.fake.nodes
    resp = await api.delete(f"/v1/clouds/me/mesh/devices/{n1['id']}", headers=auth(one["token"]))
    assert resp.status_code == 204
    assert n1["id"] not in svc.fake.nodes


async def test_mesh_address(api, enrol, svc):
    cloud = await enrol()
    h = auth(cloud["token"])
    key = (await api.post("/v1/clouds/me/mesh/keys", headers=h)).json()
    node = (await api.post(f"http://127.0.0.1:{svc.fake.port}/fake/join", json={"key": key["key"]})).json()["node"]
    for bad in ("not an ip", "8.8.8.8", "100.64.99.99"):
        resp = await api.put("/v1/clouds/me/mesh/address", json={"address": bad}, headers=h)
        assert resp.status_code == 422, bad
    address = node["ipAddresses"][0]
    resp = await api.put("/v1/clouds/me/mesh/address", json={"address": address}, headers=h)
    assert resp.status_code == 200 and resp.json() == {"address": address}
    records = json.loads(svc.cfg.extra_records_path.read_text())
    assert records == [{"name": f"larsens.{ZONE}", "type": "A", "value": address}]
    # A rename moves the record with it.
    await api.patch("/v1/clouds/me", json={"name": "jensens"}, headers=h)
    assert json.loads(svc.cfg.extra_records_path.read_text())[0]["name"] == f"jensens.{ZONE}"
    resp = await api.put("/v1/clouds/me/mesh/address", json={"address": None}, headers=h)
    assert resp.json() == {"address": None}
    assert json.loads(svc.cfg.extra_records_path.read_text()) == []


async def test_pair_code(api, enrol):
    cloud = await enrol()
    resp = await api.post("/v1/clouds/me/mesh/pair", json={"for": "Anna's phone"}, headers=auth(cloud["token"]))
    assert resp.status_code == 201
    body = resp.json()
    assert set(body) == {"code", "expires_at", "login_server"}
    assert len(body["code"]) == 6 and body["code"].isalnum() and body["code"].isupper()


async def test_acme_dns(api, enrol, svc):
    cloud = await enrol()
    resp = await api.post("/v1/acme-dns/register", headers=auth(cloud["token"]))
    assert resp.status_code == 201
    reg = resp.json()
    assert reg["fulldomain"] == f"_acme-challenge.larsens.{ZONE}"
    assert reg["server_url"].endswith("/v1/acme-dns")
    creds = {"X-Api-User": reg["username"], "X-Api-Key": reg["password"]}
    txt = "a" * 43
    resp = await api.post("/v1/acme-dns/update", json={"subdomain": reg["subdomain"], "txt": txt}, headers=creds)
    assert resp.status_code == 200 and resp.json() == {"txt": txt}
    assert svc.store.acme_txt(cloud["cloud_id"]) == [txt]

    wrong = {"X-Api-User": reg["username"], "X-Api-Key": "nope"}
    assert (await api.post("/v1/acme-dns/update", json={"subdomain": reg["subdomain"], "txt": txt}, headers=wrong)).status_code == 401
    assert (await api.post("/v1/acme-dns/update", json={"subdomain": "other", "txt": txt}, headers=creds)).status_code == 401
    assert (await api.post("/v1/acme-dns/update", json={"subdomain": reg["subdomain"], "txt": "short"}, headers=creds)).status_code == 400
    # Registering again replaces the credentials.
    again = (await api.post("/v1/acme-dns/register", headers=auth(cloud["token"]))).json()
    assert (await api.post("/v1/acme-dns/update", json={"subdomain": reg["subdomain"], "txt": txt}, headers=creds)).status_code == 401
    assert again["username"] != reg["username"]


async def test_acme_dns_keeps_two_values(api, enrol, svc):
    cloud = await enrol()
    reg = (await api.post("/v1/acme-dns/register", headers=auth(cloud["token"]))).json()
    creds = {"X-Api-User": reg["username"], "X-Api-Key": reg["password"]}
    for c in "abc":
        await api.post("/v1/acme-dns/update", json={"subdomain": reg["subdomain"], "txt": c * 43}, headers=creds)
    assert svc.store.acme_txt(cloud["cloud_id"]) == ["c" * 43, "b" * 43]


async def test_port_80_on_the_relay_host(svc):
    webroot = svc.cfg.acme_webroot / ".well-known" / "acme-challenge"
    webroot.mkdir(parents=True)
    (webroot / "tok_en-1").write_text("tok_en-1.thumbprint")

    async def get(path: str) -> bytes:
        reader, writer = await asyncio.open_connection("127.0.0.1", svc.http_port)
        writer.write(f"GET {path} HTTP/1.1\r\nHost: {RELAY}\r\nConnection: close\r\n\r\n".encode())
        data = await asyncio.wait_for(reader.read(), 5)
        writer.close()
        return data

    ok = await get("/.well-known/acme-challenge/tok_en-1")
    assert b" 200 " in ok.split(b"\r\n")[0] and ok.endswith(b"tok_en-1.thumbprint")
    assert b" 404 " in (await get("/.well-known/acme-challenge/missing")).split(b"\r\n")[0]
    moved = await get("/v1/clouds/me")
    assert b" 308 " in moved.split(b"\r\n")[0]
    assert f"location: https://{RELAY}".encode() in moved.lower()


async def test_mesh_not_configured(tmp_path, ca, enrol, api, svc):
    svc.headscale, saved = None, svc.headscale
    try:
        cloud = await enrol()
        resp = await api.post("/v1/clouds/me/mesh/keys", headers=auth(cloud["token"]))
        assert resp.status_code == 503
        assert resp.json()["detail"] == "Private access is not set up on this relay."
    finally:
        svc.headscale = saved
