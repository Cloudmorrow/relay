"""A phone pairs with a code, through the login host, as a browser would."""

from __future__ import annotations

import time

import pytest

from conftest import MESH, ZONE, auth, loopback_client


@pytest.fixture
async def browser(svc):
    async with loopback_client(svc.ca.path, f"https://{MESH}:{svc.https_port}") as client:
        yield client


async def pending(svc, api) -> str:
    """A phone that opened Headscale's register URL and is waiting."""
    return (await api.post(f"http://127.0.0.1:{svc.fake.port}/fake/pending")).json()["auth_id"]


async def code_for(api, token: str, label: str = "Anna's phone") -> str:
    resp = await api.post("/v1/clouds/me/mesh/pair", json={"for": label}, headers=auth(token))
    assert resp.status_code == 201
    return resp.json()["code"]


async def test_the_register_page_is_ours(svc, api, browser):
    auth_id = await pending(svc, api)
    resp = await browser.get(f"/register/{auth_id}")
    assert resp.status_code == 200
    assert "Pair a device" in resp.text and "headscale nodes register" not in resp.text
    assert "default-src 'none'" in resp.headers["content-security-policy"]


async def test_pairing_registers_the_phone_to_the_right_cloud(svc, api, browser, enrol):
    await enrol("hansens")
    cloud = await enrol("larsens")
    code = await code_for(api, cloud["token"])
    auth_id = await pending(svc, api)
    # Typed the way people type: lower case, a space in the middle.
    resp = await browser.post(f"/register/{auth_id}", data={"code": f"{code[:3].lower()} {code[3:]}"})
    assert resp.status_code == 200, resp.text
    assert f"larsens.{ZONE}" in resp.text
    node = next(iter(svc.fake.nodes.values()))
    assert node["user"]["name"] == f"cloud-{cloud['cloud_id']}"
    devices = (await api.get("/v1/clouds/me/mesh/devices", headers=auth(cloud["token"]))).json()["devices"]
    assert devices[0]["label"] == "Anna's phone"

    # A code works once.
    again = await pending(svc, api)
    resp = await browser.post(f"/register/{again}", data={"code": code})
    assert resp.status_code == 400 and "did not work" in resp.text


async def test_wrong_and_expired_codes(svc, api, browser, enrol):
    cloud = await enrol()
    auth_id = await pending(svc, api)
    for wrong in ("", "ABC", "ZZZZZZ", "<script>", "0O1IL0"):
        resp = await browser.post(f"/register/{auth_id}", data={"code": wrong})
        assert resp.status_code == 400
        assert "<script>" not in resp.text
    code = await code_for(api, cloud["token"])
    svc.store._exec("UPDATE pair_codes SET expires_at = ?", time.time() - 1)
    resp = await browser.post(f"/register/{auth_id}", data={"code": code})
    assert resp.status_code == 400
    assert not svc.fake.nodes


async def test_an_unknown_registration_gives_the_code_back(svc, api, browser, enrol):
    cloud = await enrol()
    code = await code_for(api, cloud["token"])
    resp = await browser.post("/register/hsnotpending", data={"code": code})
    assert resp.status_code == 502 and "your code still works" in resp.text
    auth_id = await pending(svc, api)
    resp = await browser.post(f"/register/{auth_id}", data={"code": code})
    assert resp.status_code == 200


async def test_bad_auth_ids(browser):
    resp = await browser.get("/register/../../etc")
    assert resp.status_code in (404,)
    resp = await browser.get("/register/a%20b")
    assert resp.status_code == 404


@pytest.fixture
def three_tries(limits):
    limits["pair_attempts_per_10min"] = 3


async def test_guessing_is_rate_limited(three_tries, svc, api, browser, enrol):
    cloud = await enrol()
    auth_id = await pending(svc, api)
    statuses = [(await browser.post(f"/register/{auth_id}", data={"code": "ZZZZZZ"})).status_code for _ in range(4)]
    assert statuses == [400, 400, 400, 429]
    # Even the right code waits now.
    code = await code_for(api, cloud["token"])
    assert (await browser.post(f"/register/{auth_id}", data={"code": code})).status_code == 429


@pytest.fixture
def two_codes(limits):
    limits["pair_codes_per_hour"] = 2


async def test_codes_per_cloud_are_rate_limited(two_codes, api, enrol):
    cloud = await enrol()
    await code_for(api, cloud["token"])
    await code_for(api, cloud["token"])
    resp = await api.post("/v1/clouds/me/mesh/pair", json={"for": "x"}, headers=auth(cloud["token"]))
    assert resp.status_code == 429


async def test_tailscale_paths_reach_headscale(browser):
    # /key and /health are Tailscale's protocol: they go to Headscale.
    assert (await browser.get("/key")).text == "fake-headscale-noise-key"
    assert (await browser.get("/health")).json() == {"status": "pass"}
    # Headscale's admin API is not exposed through the relay.
    assert (await browser.get("/api/v1/user")).status_code == 404
    # A browser at the root gets our page.
    assert "Cloudmorrow" in (await browser.get("/")).text


async def test_login_host_on_port_80(svc):
    import asyncio

    reader, writer = await asyncio.open_connection("127.0.0.1", svc.http_port)
    writer.write(f"GET /key HTTP/1.1\r\nHost: {MESH}\r\nConnection: close\r\n\r\n".encode())
    assert (await asyncio.wait_for(reader.read(), 5)).endswith(b"fake-headscale-noise-key")
    reader, writer = await asyncio.open_connection("127.0.0.1", svc.http_port)
    writer.write(f"GET /register/abc HTTP/1.1\r\nHost: {MESH}\r\nConnection: close\r\n\r\n".encode())
    data = await asyncio.wait_for(reader.read(), 5)
    assert b" 308 " in data.split(b"\r\n")[0] and f"https://{MESH}".encode() in data
