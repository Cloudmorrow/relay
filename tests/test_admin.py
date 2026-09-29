"""The admin API, as the website calls it."""

from __future__ import annotations

import time

import pytest

from conftest import ADMIN_SECRET, RELAY, auth, join, loopback_client

ACCOUNT = "acct_0123456789abcdef01234567"
OTHER = "acct_fedcba9876543210fedcba98"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
SVG = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><rect width="10" height="10" fill="#5b6cff"/></svg>'


async def test_the_secret_is_required(svc, api):
    for headers in ({}, auth("wrong-secret"), auth(ADMIN_SECRET + "x"), {"Authorization": ADMIN_SECRET}):
        resp = await api.get("/admin/v1/names/larsens", headers=headers)
        assert resp.status_code == 401
        assert resp.json() == {"detail": "A valid admin secret is required."}
    # A box's token is not the admin secret either.
    cloud = (await api.post("/v1/clouds", json={"name": "larsens"})).json()
    assert (await api.get(f"/admin/v1/accounts/{ACCOUNT}/clouds", headers=auth(cloud["token"]))).status_code == 401


@pytest.fixture
def few_failures(limits):
    limits["bad_auth_per_minute"] = 3


async def test_guessing_the_secret_is_rate_limited(few_failures, api):
    codes = [(await api.get("/admin/v1/names/larsens", headers=auth(f"guess-{i}"))).status_code for i in range(5)]
    assert codes == [401, 401, 401, 429, 429]


async def test_no_secret_no_admin_api(svc, monkeypatch):
    svc.admin_secret = None
    async with loopback_client(svc.ca.path, f"https://{RELAY}:{svc.https_port}") as client:
        resp = await client.get("/admin/v1/names/larsens", headers=auth(ADMIN_SECRET))
        assert resp.status_code == 503


async def test_only_on_the_relay_host(svc):
    from conftest import MESH

    async with loopback_client(svc.ca.path, f"https://{MESH}:{svc.https_port}") as client:
        resp = await client.get("/admin/v1/names/larsens", headers=auth(ADMIN_SECRET))
        assert resp.status_code == 404


def test_a_short_secret_is_refused(tmp_path, monkeypatch):
    from cloudmorrow_relay.config import ConfigError, from_dict
    from cloudmorrow_relay.service import Service

    monkeypatch.setenv("RELAY_ADMIN_SECRET", "short")
    with pytest.raises(ConfigError):
        Service(from_dict({"zone": "a.test", "state_dir": str(tmp_path)}))
    monkeypatch.delenv("RELAY_ADMIN_SECRET")
    secret_file = tmp_path / "admin-secret"
    secret_file.write_text("from-a-file-" + "x" * 30 + "\n")
    svc = Service(from_dict({"zone": "a.test", "state_dir": str(tmp_path), "admin": {"secret_file": str(secret_file)}}))
    assert svc.admin_secret == "from-a-file-" + "x" * 30
    svc.store.close()


async def test_names(admin, api):
    await api.post("/v1/clouds", json={"name": "larsens"})
    cases = {
        "hansens": (True, None),
        "Hansens": (True, None),
        "larsens": (False, "The name larsens is taken."),
        "abc": (False, "A name is 5 to 40 characters long."),
        "admin": (False, "The name admin is reserved."),
        "relay": (False, "The name relay is reserved."),
        "-abcde": (False, "A name is made of a-z, 0-9 and hyphens, and starts and ends with a letter or digit."),
        "xn--abcde": (False, "A name cannot have two hyphens in a row."),
    }
    for name, (available, problem) in cases.items():
        resp = await admin.get(f"/admin/v1/names/{name}")
        assert resp.status_code == 200
        assert resp.json() == {"available": available, "problem": problem}, name


async def test_link_status(admin, api, svc):
    start = (await api.post("/v1/links")).json()
    code = start["code"]
    for spelling in (code, code.lower(), code.replace("-", ""), f" {code[:4]} {code[5:]} "):
        resp = await admin.get(f"/admin/v1/links/{spelling}")
        assert resp.status_code == 200, spelling
        assert resp.json() == {"waiting": True, "expires_at": start["expires_at"]}
    assert (await admin.get("/admin/v1/links/ZZZZ-ZZZZ")).status_code == 404
    assert (await admin.get("/admin/v1/links/nonsense")).status_code == 404
    await admin.post(f"/admin/v1/links/{code}/approve", json={"account": ACCOUNT, "name": "larsens"})
    assert (await admin.get(f"/admin/v1/links/{code}")).status_code == 410
    other = (await api.post("/v1/links")).json()
    svc.store._exec("UPDATE links SET expires_at = ?", time.time() - 1)
    assert (await admin.get(f"/admin/v1/links/{other['code']}")).status_code == 410


async def test_approve(admin, api, svc):
    await api.post("/v1/clouds", json={"name": "hansens"})
    start = (await api.post("/v1/links")).json()
    code = start["code"]
    url = f"/admin/v1/links/{code}/approve"
    assert (await admin.post(url, json={"account": ACCOUNT, "name": "abc"})).status_code == 422
    taken = await admin.post(url, json={"account": ACCOUNT, "name": "hansens"})
    assert taken.status_code == 409 and taken.json() == {"detail": "The name hansens is taken."}
    assert (await admin.post(url, json={"account": "", "name": "larsens"})).status_code == 422
    # None of that used the code up.
    resp = await admin.post(url, json={"account": ACCOUNT, "name": "larsens"})
    assert resp.status_code == 201
    row = resp.json()
    assert row["name"] == "larsens" and row["online"] is False and row["has_logo"] is False
    assert row == (await admin.get(f"/admin/v1/accounts/{ACCOUNT}/clouds")).json()[0]
    assert (await admin.post(url, json={"account": ACCOUNT, "name": "jensens"})).status_code == 410
    assert (await admin.post(f"/admin/v1/links/{code}/refuse")).status_code == 410


async def test_an_accounts_clouds(admin, link_box, svc, api):
    one = await link_box("larsens", ACCOUNT)
    await link_box("hansens", OTHER)
    resp = await admin.get(f"/admin/v1/accounts/{ACCOUNT}/clouds")
    assert resp.status_code == 200
    clouds = resp.json()
    assert isinstance(clouds, list) and len(clouds) == 1
    entry = clouds[0]
    assert set(entry) == {
        "cloud_id", "name", "created", "online", "online_since", "state_since", "uptime_30d",
        "show_name", "show_logo", "display_name", "has_logo",
    }
    assert entry["cloud_id"] == one["cloud_id"] and entry["name"] == "larsens"
    assert entry["created"].endswith("Z")
    assert (entry["online"], entry["online_since"], entry["uptime_30d"]) == (False, None, None)
    assert (await admin.get("/admin/v1/accounts/acct_nobody/clouds")).json() == []

    # The box comes online: Headscale says so, the relay notes it.
    key = (await api.post("/v1/clouds/me/mesh/keys", headers=auth(one["token"]))).json()
    await join(svc, api, key["key"])
    await svc.meshwatch.refresh()
    entry = (await admin.get(f"/admin/v1/accounts/{ACCOUNT}/clouds")).json()[0]
    assert entry["online"] is True and entry["online_since"] == entry["state_since"]
    assert entry["uptime_30d"] == 1.0

    # And goes offline: "since" is when that began.
    for node in svc.fake.nodes.values():
        node["online"] = False
    await svc.meshwatch.refresh()
    entry = (await admin.get(f"/admin/v1/accounts/{ACCOUNT}/clouds")).json()[0]
    assert entry["online"] is False and entry["online_since"] == entry["state_since"] is not None
    assert 0 < entry["uptime_30d"] <= 1


async def test_patch(admin, link_box, api, svc):
    one = await link_box("larsens", ACCOUNT)
    await link_box("hansens", OTHER)
    url = f"/admin/v1/clouds/{one['cloud_id']}"
    # Another account's cloud is not there at all.
    assert (await admin.patch(url, json={"account": OTHER, "show_name": True})).status_code == 404
    assert (await admin.patch("/admin/v1/clouds/nothing", json={"account": ACCOUNT})).status_code == 404
    assert (await admin.patch(url, json={"account": ACCOUNT, "name": "hansens"})).status_code == 409
    assert (await admin.patch(url, json={"account": ACCOUNT, "name": "www"})).status_code == 422

    resp = await admin.patch(url, json={
        "account": ACCOUNT, "name": "Jensens", "display_name": "  The   Jensens ", "show_name": True,
    })
    assert resp.status_code == 200
    row = resp.json()
    assert (row["name"], row["display_name"], row["show_name"], row["show_logo"]) == ("jensens", "The Jensens", True, False)
    # The box sees the rename at its next read; the old name is free.
    assert (await api.get("/v1/clouds/me", headers=auth(one["token"]))).json()["name"] == "jensens"
    assert (await admin.get("/admin/v1/names/larsens")).json()["available"] is True
    cleared = await admin.patch(url, json={"account": ACCOUNT, "display_name": ""})
    assert cleared.json()["display_name"] is None


async def test_logo(admin, link_box, svc):
    one = await link_box("larsens", ACCOUNT)
    url = f"/admin/v1/clouds/{one['cloud_id']}/logo"
    assert (await admin.get(url, params={"account": ACCOUNT})).status_code == 404
    resp = await admin.put(url, params={"account": ACCOUNT}, content=PNG, headers={"content-type": "image/png"})
    assert resp.status_code == 204
    got = await admin.get(url, params={"account": ACCOUNT})
    assert got.status_code == 200 and got.content == PNG and got.headers["content-type"] == "image/png"
    assert "sandbox" in got.headers["content-security-policy"]
    assert (await admin.get(url, params={"account": OTHER})).status_code == 404
    rows = (await admin.get(f"/admin/v1/accounts/{ACCOUNT}/clouds")).json()
    assert rows[0]["has_logo"] is True and rows[0]["show_logo"] is False

    ok = await admin.put(url, params={"account": ACCOUNT}, content=SVG, headers={"content-type": "image/svg+xml"})
    assert ok.status_code == 204
    assert (await admin.get(url, params={"account": ACCOUNT})).content == SVG

    assert (await admin.delete(url, params={"account": OTHER})).status_code == 404
    assert (await admin.delete(url, params={"account": ACCOUNT})).status_code == 204
    assert (await admin.get(f"/admin/v1/accounts/{ACCOUNT}/clouds")).json()[0]["has_logo"] is False


@pytest.mark.parametrize("content_type, data, problem", [
    ("image/gif", b"GIF89a", "PNG, SVG or JPEG"),
    ("image/png", b"\xff\xd8\xff not a png", "not a PNG"),
    ("image/jpeg", PNG, "not a JPEG"),
    ("image/png", b"", "empty"),
    ("image/svg+xml", b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>", "<script>"),
    ("image/svg+xml", b"<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'/>", "event handlers"),
    ("image/svg+xml", b"<svg xmlns='http://www.w3.org/2000/svg'><foreignObject/></svg>", "<foreignobject>"),
    ("image/svg+xml", b"<svg xmlns='http://www.w3.org/2000/svg' xmlns:x='http://www.w3.org/1999/xlink'>"
                      b"<image x:href='https://evil.example/a.png'/></svg>", "outside itself"),
    ("image/svg+xml", b"<svg xmlns='http://www.w3.org/2000/svg'><a href='javascript:alert(1)'/></svg>", "outside itself"),
    ("image/svg+xml", b"<svg xmlns='http://www.w3.org/2000/svg'><rect fill='url(https://evil.example/)'/></svg>", "elsewhere"),
    ("image/svg+xml", b"<svg xmlns='http://www.w3.org/2000/svg'><style>@import 'x.css';</style></svg>", "elsewhere"),
    ("image/svg+xml", b"<!DOCTYPE svg [<!ENTITY a 'b'>]><svg xmlns='http://www.w3.org/2000/svg'>&a;</svg>", "DOCTYPE"),
    ("image/svg+xml", b"<svg", "well-formed"),
    ("image/svg+xml", b"<html/>", "not an SVG"),
])
async def test_logo_refusals(admin, link_box, content_type, data, problem):
    one = await link_box("larsens", ACCOUNT)
    resp = await admin.put(
        f"/admin/v1/clouds/{one['cloud_id']}/logo", params={"account": ACCOUNT},
        content=data, headers={"content-type": content_type},
    )
    assert resp.status_code == 422
    assert problem in resp.json()["detail"]


async def test_logo_size(admin, link_box):
    one = await link_box("larsens", ACCOUNT)
    url = f"/admin/v1/clouds/{one['cloud_id']}/logo"
    fits = PNG + b"\x00" * (256 * 1024 - len(PNG))
    ok = await admin.put(url, params={"account": ACCOUNT}, content=fits, headers={"content-type": "image/png"})
    assert ok.status_code == 204
    over = await admin.put(url, params={"account": ACCOUNT}, content=fits + b"\x00", headers={"content-type": "image/png"})
    assert over.status_code == 422 and "256 KiB" in over.json()["detail"]
    far_over = await admin.put(url, params={"account": ACCOUNT}, content=fits * 2, headers={"content-type": "image/png"})
    assert far_over.status_code == 413
    # The bigger cap is the logo's alone.
    big = await admin.patch(f"/admin/v1/clouds/{one['cloud_id']}", json={"account": ACCOUNT, "x": "a" * 40000})
    assert big.status_code == 413


async def test_unlink(admin, link_box, api, svc):
    one = await link_box("larsens", ACCOUNT)
    key = (await api.post("/v1/clouds/me/mesh/keys", headers=auth(one["token"]))).json()
    await join(svc, api, key["key"])
    url = f"/admin/v1/clouds/{one['cloud_id']}"
    assert (await admin.delete(url, params={"account": OTHER})).status_code == 404
    svc.fake.api_key = "rotated"
    assert (await admin.delete(url, params={"account": ACCOUNT})).status_code == 502
    svc.fake.api_key = "test-headscale-key"
    assert (await admin.delete(url, params={"account": ACCOUNT})).status_code == 204
    assert (await api.get("/v1/clouds/me", headers=auth(one["token"]))).status_code == 401
    assert not svc.fake.nodes and not svc.fake.users
    assert (await admin.get(f"/admin/v1/accounts/{ACCOUNT}/clouds")).json() == []
    assert (await admin.get("/admin/v1/names/larsens")).json()["available"] is True
