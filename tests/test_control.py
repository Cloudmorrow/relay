"""The control API over the relay's own TLS, as a box calls it."""

from __future__ import annotations

import asyncio
import json

import pytest

from conftest import MESH, RELAY, ZONE, auth, join


async def test_claim_a_name(api, svc):
    resp = await api.post("/v1/clouds", json={"name": "  Larsens "})
    assert resp.status_code == 201
    body = resp.json()
    # The same as a linked box collects.
    assert set(body) == {"cloud_id", "token", "name", "zone", "login_server", "acme_dns"}
    assert body["name"] == "larsens"
    assert body["zone"] == ZONE
    assert body["login_server"].startswith(f"https://{MESH}")
    assert body["acme_dns"]["fulldomain"] == f"_acme-challenge.larsens.{ZONE}"
    # Only the hash is kept.
    row = svc.store._one("SELECT token_hash FROM clouds WHERE id = ?", body["cloud_id"])
    assert body["token"] not in row["token_hash"]
    assert (await api.get("/v1/clouds/me", headers=auth(body["token"]))).status_code == 200


@pytest.fixture
def closed(extra_config):
    extra_config["open_claims"] = False


async def test_claims_are_off_by_default(closed, api):
    resp = await api.post("/v1/clouds", json={"name": "larsens"})
    assert resp.status_code == 403
    assert "linking" in resp.json()["detail"]


def test_open_claims_default():
    from cloudmorrow_relay.config import from_dict

    assert from_dict({"zone": "a.test"}).open_claims is False


@pytest.mark.parametrize(
    "name, problem",
    [
        ("abc", "5 to 40"),
        ("abcd", "5 to 40"),
        ("a" * 41, "5 to 40"),
        ("www", "5 to 40"),
        ("-abcd", "starts and ends"),
        ("abcd-", "starts and ends"),
        ("ab_cd", "a-z, 0-9"),
        ("ab.cd", "a-z, 0-9"),
        ("xn--abc", "two hyphens"),
        ("relay", "reserved"),
        ("admin", "reserved"),
        ("login", "reserved"),
        ("cloudmorrow", "reserved"),
        ("headscale", "reserved"),
        ("blåbær", "a-z, 0-9"),
    ],
)
async def test_name_rules(api, name, problem):
    resp = await api.post("/v1/clouds", json={"name": name})
    assert resp.status_code == 422
    assert problem in resp.json()["detail"]


async def test_five_and_forty_are_fine(api):
    for name in ("abcde", "a" * 40, "a-b-c", "12345"):
        assert (await api.post("/v1/clouds", json={"name": name})).status_code == 201, name


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


async def test_record(api, enrol, svc):
    cloud = await enrol()
    resp = await api.get("/v1/clouds/me", headers=auth(cloud["token"]))
    assert resp.status_code == 200
    assert resp.json() == {
        "cloud_id": cloud["cloud_id"], "name": "larsens", "zone": ZONE,
        "mesh_address": None, "login_server": svc.cfg.login_server,
    }


async def test_record_has_the_boxs_mesh_address(api, enrol, svc):
    cloud = await enrol()
    h = auth(cloud["token"])
    key = (await api.post("/v1/clouds/me/mesh/keys", headers=h)).json()
    node = await join(svc, api, key["key"])
    await svc.meshwatch.refresh()
    assert (await api.get("/v1/clouds/me", headers=h)).json()["mesh_address"] == node["ipAddresses"][0]


async def test_renaming_is_not_the_boxs(api, enrol):
    cloud = await enrol()
    resp = await api.patch("/v1/clouds/me", json={"name": "jensens"}, headers=auth(cloud["token"]))
    assert resp.status_code == 405


async def test_give_the_name_back(api, enrol, svc):
    cloud = await enrol()
    h = auth(cloud["token"])
    key = await api.post("/v1/clouds/me/mesh/keys", headers=h)
    assert key.status_code == 201
    await join(svc, api, key.json()["key"])
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
    assert (await api.post("/v1/clouds", json={"name": "one11"})).status_code == 201
    assert (await api.post("/v1/clouds", json={"name": "two22"})).status_code == 201
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
    h = auth(cloud["token"])
    # An older box's label is taken and dropped.
    resp = await api.post("/v1/clouds/me/mesh/keys", json={"for": "the box", "expires_in": 600}, headers=h)
    assert resp.status_code == 201
    body = resp.json()
    assert set(body) == {"key", "login_server", "expires_at", "node_hint"}
    assert body["login_server"].startswith(f"https://{MESH}")
    assert body["node_hint"] == "cloud"  # no box on the mesh yet
    user = svc.fake.user_by_name(f"cloud-{cloud['cloud_id']}")
    key = next(iter(svc.fake.keys.values()))
    assert key["user"] == user and key["reusable"] is False and key["ephemeral"] is False
    assert "the box" not in open(svc.cfg.db_path, "rb").read().decode("latin-1")
    bad = await api.post("/v1/clouds/me/mesh/keys", json={"expires_in": 5}, headers=h)
    assert bad.status_code == 422
    await join(svc, api, body["key"])
    again = (await api.post("/v1/clouds/me/mesh/keys", headers=h)).json()
    assert again["node_hint"] is None  # the box is there: this is for a device


async def test_devices(api, enrol, svc):
    one, two = await enrol("larsens"), await enrol("hansens")
    k1 = (await api.post("/v1/clouds/me/mesh/keys", headers=auth(one["token"]))).json()
    k2 = (await api.post("/v1/clouds/me/mesh/keys", headers=auth(two["token"]))).json()
    n1 = await join(svc, api, k1["key"], "jimmis-laptop")
    n2 = await join(svc, api, k2["key"])

    resp = await api.get("/v1/clouds/me/mesh/devices", headers=auth(one["token"]))
    assert resp.status_code == 200
    devices = resp.json()["devices"]
    # No names: the box keeps its own labels, joined by id.
    assert devices == [{"id": n1["id"], "address": n1["ipAddresses"][0], "online": True, "last_seen": n1["lastSeen"]}]
    assert "jimmis-laptop" not in resp.text

    # Another cloud's device is not ours to remove.
    resp = await api.delete(f"/v1/clouds/me/mesh/devices/{n2['id']}", headers=auth(one["token"]))
    assert resp.status_code == 404
    assert n2["id"] in svc.fake.nodes
    resp = await api.delete(f"/v1/clouds/me/mesh/devices/{n1['id']}", headers=auth(one["token"]))
    assert resp.status_code == 204
    assert n1["id"] not in svc.fake.nodes


async def test_mesh_address_is_a_no_op(api, enrol, svc):
    cloud = await enrol()
    h = auth(cloud["token"])
    resp = await api.put("/v1/clouds/me/mesh/address", json={"address": "100.64.0.9"}, headers=h)
    assert resp.status_code == 200 and resp.json() == {"address": "100.64.0.9"}
    # Nothing is taken from the box: the address comes from Headscale.
    assert svc.store.cloud(cloud["cloud_id"]).mesh_address is None


async def test_invite(api, enrol):
    cloud = await enrol()
    for path in ("/v1/clouds/me/mesh/invites", "/v1/clouds/me/mesh/pair"):
        resp = await api.post(path, json={"for": "Anna's phone"}, headers=auth(cloud["token"]))
        assert resp.status_code == 201
        body = resp.json()
        assert set(body) == {"code", "expires_at", "login_server"}
        assert len(body["code"]) == 6 and body["code"].isalnum() and body["code"].isupper()


async def invite(api, token: str) -> str:
    return (await api.post("/v1/clouds/me/mesh/invites", headers=auth(token))).json()["code"]


async def test_redeem_an_invite(api, enrol, svc):
    await enrol("hansens")
    cloud = await enrol("larsens")
    code = await invite(api, cloud["token"])
    # No token; typed the way people type.
    resp = await api.post("/v1/invites/redeem", json={"name": "Larsens", "code": f"{code[:3].lower()}-{code[3:]}"})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert set(body) == {"key", "login_server", "expires_at"}
    key = next(k for k in svc.fake.keys.values() if k["key"] == body["key"])
    assert key["user"]["name"] == f"cloud-{cloud['cloud_id']}" and key["reusable"] is False
    # Once.
    again = await api.post("/v1/invites/redeem", json={"name": "larsens", "code": code})
    assert again.status_code == 404
    assert again.json() == {"detail": "That invite did not work. Invites work once, for ten minutes."}


async def test_an_invite_works_for_its_own_cloud_only(api, enrol):
    await enrol("hansens")
    cloud = await enrol("larsens")
    code = await invite(api, cloud["token"])
    for name in ("hansens", "nobody", ""):
        assert (await api.post("/v1/invites/redeem", json={"name": name, "code": code})).status_code == 404
    # The wrong tries did not use it up.
    assert (await api.post("/v1/invites/redeem", json={"name": "larsens", "code": code})).status_code == 201


async def test_redeem_gives_the_code_back_if_headscale_is_down(api, enrol, svc):
    cloud = await enrol()
    code = await invite(api, cloud["token"])
    svc.fake.api_key = "rotated"
    assert (await api.post("/v1/invites/redeem", json={"name": "larsens", "code": code})).status_code == 502
    svc.fake.api_key = "test-headscale-key"
    assert (await api.post("/v1/invites/redeem", json={"name": "larsens", "code": code})).status_code == 201


@pytest.fixture
def three_redeems(limits):
    limits["pair_attempts_per_10min"] = 3


async def test_redeeming_is_rate_limited(three_redeems, api, enrol):
    cloud = await enrol()
    statuses = [
        (await api.post("/v1/invites/redeem", json={"name": "larsens", "code": "ZZZZZZ"})).status_code
        for _ in range(4)
    ]
    assert statuses == [404, 404, 404, 429]
    code = await invite(api, cloud["token"])
    assert (await api.post("/v1/invites/redeem", json={"name": "larsens", "code": code})).status_code == 429


@pytest.fixture
def two_redeems_per_name(limits):
    limits["redeems_per_name_10min"] = 2


async def test_redeeming_is_rate_limited_per_name(two_redeems_per_name, api, enrol, svc):
    await enrol()
    ips = iter(["192.0.2.1", "192.0.2.2", "192.0.2.3"])
    svc.client_ip = lambda request: next(ips)  # three addresses, one name
    statuses = [
        (await api.post("/v1/invites/redeem", json={"name": "larsens", "code": "ZZZZZZ"})).status_code
        for _ in range(3)
    ]
    assert statuses == [404, 404, 429]


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
        assert resp.json()["detail"] == "The mesh is not set up on this relay."
    finally:
        svc.headscale = saved
