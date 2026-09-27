"""Talking to Headscale, the coordination server for private access.

Headscale does the hard part (WireGuard keys, the tailnet map, DERP); the
relay only keeps it in step with the clouds. Each cloud is one Headscale
user, named `cloud-<cloud_id>` so a rename never touches Headscale. Keys,
devices and phone registrations are all per user, and the policy that
ships in `deploy/headscale/policy.hujson` (`autogroup:member` may reach
`autogroup:self`) keeps each user's devices to themselves.

Written against Headscale's REST API (`/api/v1`, API key auth) as of 0.29;
0.26 is the oldest it can work with, since that is where pre-auth keys
started taking a user id rather than a name.

The DNS name inside the mesh (`<name>.<zone>` → the box's mesh address)
has no API: Headscale reads extra records from a JSON file and watches it
(`dns.extra_records_path`). The relay rewrites that file whole, atomically,
whenever a cloud's name or mesh address changes. It is one file for the
whole tailnet, so every enrolled device can resolve every cloud's name to
its mesh address; the policy is what keeps them from reaching it.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import tempfile
from pathlib import Path
from typing import Any

import httpx


class HeadscaleError(Exception):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def _iso(when: dt.datetime) -> str:
    return when.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Headscale:
    def __init__(self, url: str, api_key: str, transport: httpx.AsyncBaseTransport | None = None):
        self._http = httpx.AsyncClient(
            base_url=url.rstrip("/") + "/api/v1",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=10.0,
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def _call(self, method: str, path: str, **kwargs: Any) -> dict:
        try:
            resp = await self._http.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise HeadscaleError(f"Headscale did not answer: {exc.__class__.__name__}") from exc
        if resp.status_code >= 400:
            try:
                message = resp.json().get("message") or resp.text
            except ValueError:
                message = resp.text
            raise HeadscaleError(message[:300], resp.status_code)
        if not resp.content:
            return {}
        return resp.json()

    # --- users -------------------------------------------------------------

    async def find_user(self, name: str) -> dict | None:
        data = await self._call("GET", "/user", params={"name": name})
        # Older versions ignore the filter and list everybody.
        for user in data.get("users", []):
            if user.get("name") == name:
                return user
        return None

    async def ensure_user(self, name: str) -> dict:
        user = await self.find_user(name)
        if user is None:
            data = await self._call("POST", "/user", json={"name": name})
            user = data["user"]
        return user

    async def delete_user(self, name: str) -> None:
        """Remove the user with all its devices and keys. Headscale will not
        delete a user who still has nodes, so those go first.
        """
        user = await self.find_user(name)
        if user is None:
            return
        for node in await self.list_nodes(name):
            await self.delete_node(node["id"])
        keys = await self._call("GET", "/preauthkey")
        for key in keys.get("preAuthKeys", []):
            if str((key.get("user") or {}).get("id")) == str(user["id"]):
                await self._call("DELETE", "/preauthkey", params={"id": key["id"]})
        await self._call("DELETE", f"/user/{user['id']}")

    # --- keys and nodes ------------------------------------------------------

    async def create_key(
        self, user_name: str, *, ephemeral: bool, expires_in: int
    ) -> dict:
        """A one-time pre-auth key. Returns Headscale's preAuthKey object."""
        user = await self.ensure_user(user_name)
        expiration = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=expires_in)
        data = await self._call(
            "POST",
            "/preauthkey",
            json={
                "user": str(user["id"]),
                "reusable": False,
                "ephemeral": ephemeral,
                "expiration": _iso(expiration),
                "aclTags": [],
            },
        )
        return data["preAuthKey"]

    async def list_nodes(self, user_name: str) -> list[dict]:
        data = await self._call("GET", "/node", params={"user": user_name})
        # Filter again ourselves: an unknown user must never mean "all".
        return [n for n in data.get("nodes", []) if (n.get("user") or {}).get("name") == user_name]

    async def delete_node(self, node_id: str) -> None:
        await self._call("DELETE", f"/node/{node_id}")

    async def register_node(self, user_name: str, auth_id: str) -> dict:
        """Finish a registration a Tailscale app started, for this user:
        the `<auth_id>` is the last part of the /register/ URL the app
        opened.
        """
        await self.ensure_user(user_name)
        data = await self._call(
            "POST", "/node/register", params={"user": user_name, "key": auth_id}
        )
        return data["node"]

    async def policy(self) -> str:
        data = await self._call("GET", "/policy")
        return data.get("policy", "")


def device(node: dict, labels: dict[tuple[str, str], str]) -> dict:
    """A Headscale node as the control API shows it."""
    key_id = str((node.get("preAuthKey") or {}).get("id") or "")
    node_id = str(node["id"])
    label = labels.get(("node", node_id)) or labels.get(("key", key_id)) or ""
    return {
        "id": node_id,
        "name": node.get("givenName") or node.get("name") or "",
        "label": label,
        "addresses": node.get("ipAddresses", []),
        "online": bool(node.get("online")),
        "last_seen": node.get("lastSeen"),
        "created_at": node.get("createdAt"),
    }


def write_extra_records(path: Path, records: list[dict]) -> None:
    """Replace Headscale's extra records file in one step, so it never
    reads half a file.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".extra-records.")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(records, f, indent=1, sort_keys=True)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
