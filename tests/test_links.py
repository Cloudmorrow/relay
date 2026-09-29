"""Linking a box, as the box and the website each see it."""

from __future__ import annotations

import time

import pytest

from cloudmorrow_relay import links
from conftest import MESH, ZONE, auth


async def test_the_whole_link(api, admin, svc):
    start = await api.post("/v1/links")
    assert start.status_code == 201
    body = start.json()
    assert set(body) == {"code", "poll", "url", "expires_at", "interval"}
    assert body["url"] == "https://cloudmorrow.com/link"
    assert body["interval"] == 5
    code = body["code"]
    assert len(code) == 9 and code[4] == "-"
    assert all(c in links.ALPHABET for c in code.replace("-", ""))

    # Until the website approves: 202, again and again.
    for _ in range(2):
        waiting = await api.post("/v1/links/poll", json={"poll": body["poll"]})
        assert waiting.status_code == 202 and isinstance(waiting.json()["detail"], str)

    approve = await admin.post(f"/admin/v1/links/{code}/approve", json={"account": "acct_1", "name": "Larsens"})
    assert approve.status_code == 201

    got = await api.post("/v1/links/poll", json={"poll": body["poll"]})
    assert got.status_code == 200
    linked = got.json()
    assert set(linked) == {"cloud_id", "token", "name", "zone", "login_server", "acme_dns"}
    assert (linked["name"], linked["zone"]) == ("larsens", ZONE)
    assert linked["login_server"].startswith(f"https://{MESH}")
    assert set(linked["acme_dns"]) == {"username", "password", "subdomain", "fulldomain", "allowfrom", "server_url"}
    assert linked["acme_dns"]["fulldomain"] == f"_acme-challenge.larsens.{ZONE}"
    cloud = svc.store.cloud(linked["cloud_id"])
    assert cloud.account == "acct_1"

    # The token works, and the acme-dns credentials with it.
    me = await api.get("/v1/clouds/me", headers=auth(linked["token"]))
    assert me.status_code == 200 and me.json()["name"] == "larsens"
    acme = linked["acme_dns"]
    resp = await api.post(
        "/v1/acme-dns/update", json={"subdomain": acme["subdomain"], "txt": "q" * 43},
        headers={"X-Api-User": acme["username"], "X-Api-Key": acme["password"]},
    )
    assert resp.status_code == 200

    # Once.
    again = await api.post("/v1/links/poll", json={"poll": body["poll"]})
    assert again.status_code == 410


async def test_nothing_that_works_as_a_token_waits_in_the_database(api, admin, svc):
    start = (await api.post("/v1/links")).json()
    await admin.post(f"/admin/v1/links/{start['code']}/approve", json={"account": "acct_1", "name": "larsens"})
    cloud = svc.store.cloud_by_name("larsens")
    placeholder = cloud.token_hash
    linked = (await api.post("/v1/links/poll", json={"poll": start["poll"]})).json()
    assert svc.store.cloud(cloud.id).token_hash != placeholder
    # Neither the code nor the poll secret is kept as it is.
    raw = open(svc.cfg.db_path, "rb").read() + open(str(svc.cfg.db_path) + "-wal", "rb").read()
    for secret in (start["poll"], start["code"], start["code"].replace("-", ""), linked["token"]):
        assert secret.encode() not in raw


async def test_refused_and_expired(api, admin, svc):
    one = (await api.post("/v1/links")).json()
    assert (await admin.post(f"/admin/v1/links/{one['code']}/refuse")).status_code == 204
    assert (await api.post("/v1/links/poll", json={"poll": one["poll"]})).status_code == 410

    two = (await api.post("/v1/links")).json()
    svc.store._exec("UPDATE links SET expires_at = ?", time.time() - 1)
    gone = await api.post("/v1/links/poll", json={"poll": two["poll"]})
    assert gone.status_code == 410 and "Ask for a new one" in gone.json()["detail"]
    resp = await admin.post(f"/admin/v1/links/{two['code']}/approve", json={"account": "a", "name": "larsens"})
    assert resp.status_code == 410
    assert svc.store.cloud_by_name("larsens") is None

    assert (await api.post("/v1/links/poll", json={"poll": "nonsense"})).status_code == 410
    assert (await api.post("/v1/links/poll", json={})).status_code == 422


async def test_an_approval_late_in_the_codes_life_can_still_be_collected(api, admin, svc):
    start = (await api.post("/v1/links")).json()
    await admin.post(f"/admin/v1/links/{start['code']}/approve", json={"account": "a", "name": "larsens"})
    # The code itself runs out right after the approval; the box polls late.
    svc.store._exec("UPDATE links SET expires_at = ?", time.time() - 1)
    assert (await api.post("/v1/links/poll", json={"poll": start["poll"]})).status_code == 200


@pytest.fixture
def two_links(limits):
    limits["links_per_hour"] = 2


async def test_link_codes_are_rate_limited(two_links, api):
    statuses = [(await api.post("/v1/links")).status_code for _ in range(3)]
    assert statuses == [201, 201, 429]


def test_codes():
    code = links.new_code()
    assert len(code) == 8 and links.normalise_code(links.show(code).lower()) == code
    assert links.normalise_code(" kxrt 4829 ") == "KXRT4829"
    assert links.normalise_code("KXRT-4820") is None  # no 0, O, 1, I or L
    assert links.normalise_code("KXRT-O829") is None
    assert links.normalise_code("") is None and links.normalise_code("ABCDEFGHJ") is None
