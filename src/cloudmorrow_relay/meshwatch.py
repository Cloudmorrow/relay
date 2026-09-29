"""Watching the boxes through Headscale: their addresses and their uptime.

Once a minute (and at once after anything that can change it: a link
collected, a rename, an unlink, an old box reporting its address) the
relay reads every node from Headscale and finds each cloud's box, the node
named `cloud` in the cloud's user. From that it keeps two things:

- the box's mesh addresses, in the database and in Headscale's
  extra-records file: `<name>.<zone>` A and AAAA → the box, so devices on
  the mesh go straight to it;
- whether the box is online, as a list of changes per cloud, from which
  the website's "online since" and "uptime over 30 days" are worked out.

Nothing here asks the box anything: Headscale knows all of it already.
When Headscale does not answer, nothing is changed (the box is not marked
offline for our trouble) and the next round tries again.
"""

from __future__ import annotations

import asyncio
import logging
import time

from .headscale import HeadscaleError, addresses, box_node, write_extra_records
from .store import iso

log = logging.getLogger("cloudmorrow_relay.meshwatch")

WINDOW = 30 * 24 * 3600


def extra_records(cfg, clouds) -> list[dict]:
    """Headscale's extra records for these clouds, in a stable order."""
    records = []
    for cloud in clouds:
        host = cfg.public_host(cloud.name)
        if cloud.mesh_address:
            records.append({"name": host, "type": "A", "value": cloud.mesh_address})
        if cloud.mesh_address6:
            records.append({"name": host, "type": "AAAA", "value": cloud.mesh_address6})
    return sorted(records, key=lambda r: (r["name"], r["type"]))


def uptime(changes: list[tuple[float, bool]], now: float, since: float, window: float = WINDOW) -> float | None:
    """The share of the last `window` seconds the box was online, from its
    state changes (oldest first). The window starts no earlier than
    `since` (the cloud's creation) nor than the first change we saw: time
    we know nothing about does not count either way. None when there is
    nothing to go on.
    """
    if not changes:
        return None
    start = max(now - window, since, changes[0][0])
    if start >= now:
        return None
    online_for = 0.0
    for i, (at, online) in enumerate(changes):
        end = changes[i + 1][0] if i + 1 < len(changes) else now
        lo, hi = max(at, start), min(end, now)
        if online and hi > lo:
            online_for += hi - lo
    return online_for / (now - start)


def status(store, cloud, now: float | None = None) -> dict:
    """What the website shows about a box: online or not, since when (the
    current state, whichever it is: "offline for two days" too), and the
    share of the last thirty days it was online, a fraction from 0 to 1.
    """
    now = time.time() if now is None else now
    changes = store.state_changes(cloud.id)
    since = iso(changes[-1][0]) if changes else None
    share = uptime(changes, now, cloud.created_at)
    return {
        "online": bool(changes) and changes[-1][1],
        "online_since": since,
        "state_since": since,
        "uptime_30d": None if share is None else round(share, 4),
    }


class MeshWatch:
    def __init__(self, svc):
        self.svc = svc
        self._task: asyncio.Task | None = None
        self._wake = asyncio.Event()
        self._written: list[dict] | None = None

    def poke(self) -> None:
        """Look again now rather than at the next minute."""
        self._wake.set()

    def write_records(self) -> None:
        """Rewrite the extra-records file from the database, if it changed."""
        path = self.svc.cfg.extra_records_path
        if path is None:
            return
        records = extra_records(self.svc.cfg, self.svc.store.all_clouds())
        if records == self._written and path.exists():
            return
        try:
            write_extra_records(path, records)
        except OSError as exc:
            log.warning("could not write %s: %s", path, exc)
            return
        self._written = records

    async def refresh(self) -> bool:
        """One round: read the nodes, update addresses and states, write
        the records. False if Headscale did not answer.
        """
        hs = self.svc.headscale
        store = self.svc.store
        if hs is None:
            self.write_records()
            return False
        try:
            nodes = await hs.all_nodes()
        except HeadscaleError as exc:
            log.warning("reading the nodes from Headscale: %s", exc)
            self.write_records()
            return False
        now = time.time()
        for cloud in store.all_clouds():
            node = box_node(nodes, cloud.mesh_user)
            v4, v6 = addresses(node) if node else (None, None)
            if (v4, v6) != (cloud.mesh_address, cloud.mesh_address6):
                store.set_mesh_addresses(cloud.id, v4, v6)
            store.record_state(cloud.id, bool(node and node.get("online")), now)
        self.write_records()
        return True

    async def _loop(self) -> None:
        while True:
            # Cleared before the round, so a poke during it is not lost.
            self._wake.clear()
            try:
                await self.refresh()
            except Exception:  # one bad round must not end the watching
                log.exception("watching the mesh")
            try:
                async with asyncio.timeout(self.svc.cfg.mesh_poll_seconds):
                    await self._wake.wait()
            except TimeoutError:
                pass

    def start(self) -> None:
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
