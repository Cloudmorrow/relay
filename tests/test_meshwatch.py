"""Watching the boxes through Headscale: extra records and uptime."""

from __future__ import annotations

import json
import time

import pytest

from cloudmorrow_relay.meshwatch import WINDOW, status, uptime
from conftest import ZONE, auth, join

DAY = 24 * 3600


def test_uptime_all_the_time():
    now = 1_000 * DAY
    assert uptime([(now - 40 * DAY, True)], now, since=0) == 1.0
    assert uptime([(now - 40 * DAY, False)], now, since=0) == 0.0


def test_uptime_half():
    now = 1_000 * DAY
    changes = [(now - 40 * DAY, True), (now - 15 * DAY, False)]
    assert uptime(changes, now, since=0) == pytest.approx(0.5)


def test_uptime_counts_only_what_it_knows():
    now = 1_000 * DAY
    # Linked ten days ago; online for the last two: 20 %.
    changes = [(now - 10 * DAY, False), (now - 2 * DAY, True)]
    assert uptime(changes, now, since=now - 10 * DAY) == pytest.approx(0.2)
    # The cloud was made before we first looked: from the first look.
    assert uptime([(now - DAY, True)], now, since=now - 20 * DAY) == 1.0
    assert uptime([], now, since=0) is None


def test_uptime_flapping():
    now = 1_000 * DAY
    changes = []
    t = now - WINDOW
    while t < now:
        changes += [(t, True), (t + 3600, False)]
        t += 4 * 3600
    assert uptime(changes, now, since=0) == pytest.approx(0.25, abs=0.01)


def test_changes_are_kept_thirty_one_days(tmp_path):
    from cloudmorrow_relay.store import Store

    store = Store(tmp_path / "relay.sqlite")
    cloud, _ = store.create_cloud("larsens")
    now = time.time()
    store._exec("UPDATE clouds SET created_at = ?", now - 90 * DAY)
    assert store.record_state(cloud.id, True, now - 60 * DAY)
    assert not store.record_state(cloud.id, True, now - 59 * DAY)  # no change, nothing kept
    assert store.record_state(cloud.id, False, now - 40 * DAY)
    assert store.record_state(cloud.id, True, now - 10 * DAY)
    assert store.record_state(cloud.id, False, now - 5 * DAY)
    # The oldest went; the last one before the window stays, to say what
    # the state was when the window opens.
    assert store.state_changes(cloud.id) == [
        (now - 40 * DAY, False), (now - 10 * DAY, True), (now - 5 * DAY, False),
    ]
    shown = status(store, store.cloud(cloud.id), now)
    assert shown["uptime_30d"] == pytest.approx(5 / 30, abs=1e-4)
    assert shown["online"] is False and shown["online_since"] == shown["state_since"]
    store.close()


def records(svc) -> list[dict]:
    return json.loads(svc.cfg.extra_records_path.read_text())


async def test_extra_records_follow_the_box(svc, api, link_box, admin):
    one = await link_box("larsens")
    two = await link_box("hansens")
    h = auth(one["token"])
    # A device of the cloud is not its box.
    key = (await api.post("/v1/clouds/me/mesh/keys", headers=h)).json()
    await join(svc, api, key["key"], "cm-a1b2c3")
    await svc.meshwatch.refresh()
    assert records(svc) == []

    key = (await api.post("/v1/clouds/me/mesh/keys", headers=h)).json()
    box = await join(svc, api, key["key"], "cloud")
    await svc.meshwatch.refresh()
    v4, v6 = box["ipAddresses"]
    assert records(svc) == [
        {"name": f"larsens.{ZONE}", "type": "A", "value": v4},
        {"name": f"larsens.{ZONE}", "type": "AAAA", "value": v6},
    ]
    # A box named `cloud` in another cloud's user is that cloud's.
    other_key = (await api.post("/v1/clouds/me/mesh/keys", headers=auth(two["token"]))).json()
    other = await join(svc, api, other_key["key"], "cloud")
    await svc.meshwatch.refresh()
    assert {r["value"] for r in records(svc) if r["name"] == f"hansens.{ZONE}"} == set(other["ipAddresses"])

    # A rename moves the record at once, before the next round.
    await admin.patch(f"/admin/v1/clouds/{one['cloud_id']}", json={"account": one["account"], "name": "jensens"})
    assert {r["name"] for r in records(svc)} == {f"jensens.{ZONE}", f"hansens.{ZONE}"}

    # The box removed from the mesh: its record goes.
    assert (await api.delete(f"/v1/clouds/me/mesh/devices/{box['id']}", headers=h)).status_code == 204
    await svc.meshwatch.refresh()
    assert {r["name"] for r in records(svc)} == {f"hansens.{ZONE}"}
    assert svc.store.cloud(one["cloud_id"]).mesh_address is None

    # Unlinked: gone too.
    await api.delete("/v1/clouds/me", headers=auth(two["token"]))
    assert records(svc) == []


async def test_the_loop_runs_and_wakes_on_a_poke(svc, api, link_box):
    one = await link_box("larsens")
    key = (await api.post("/v1/clouds/me/mesh/keys", headers=auth(one["token"]))).json()
    await join(svc, api, key["key"])
    # An old box reporting its address only makes the relay look sooner.
    await api.put("/v1/clouds/me/mesh/address", json={"address": "100.64.0.1"}, headers=auth(one["token"]))
    import asyncio

    for _ in range(100):
        if svc.cfg.extra_records_path.exists() and records(svc):
            break
        await asyncio.sleep(0.02)
    assert records(svc)[0]["name"] == f"larsens.{ZONE}"
    assert svc.store.state_changes(one["cloud_id"])[-1][1] is True


async def test_headscale_down_changes_nothing(svc, api, link_box):
    one = await link_box("larsens")
    key = (await api.post("/v1/clouds/me/mesh/keys", headers=auth(one["token"]))).json()
    await join(svc, api, key["key"])
    assert await svc.meshwatch.refresh()
    before = svc.store.state_changes(one["cloud_id"])
    svc.fake.api_key = "rotated"
    assert not await svc.meshwatch.refresh()
    # Not marked offline for Headscale's trouble; the record stays.
    assert svc.store.state_changes(one["cloud_id"]) == before
    assert records(svc)
