"""The Headscale client against a real Headscale.

Downloads the release binary from GitHub once (into `.cache/`, or
$CLOUDMORROW_RELAY_CACHE), runs it on loopback with our policy and an
extra-records file, and makes the relay's calls. Skipped when the download
fails (no network) or the platform has no release binary.
"""

from __future__ import annotations

import asyncio
import json
import os
import platform
import secrets
import shutil
import socket
import subprocess
import urllib.request
from pathlib import Path

import pytest

from cloudmorrow_relay.headscale import Headscale, HeadscaleError, device, write_extra_records

pytestmark = pytest.mark.live

VERSION = os.environ.get("HEADSCALE_VERSION", "0.29.4")
ROOT = Path(__file__).resolve().parent.parent
POLICY = ROOT / "deploy" / "headscale" / "policy.hujson"


def _binary() -> Path:
    arch = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine())
    if platform.system() != "Linux" or arch is None:
        pytest.skip("no Headscale release binary for this platform")
    cache = Path(os.environ.get("CLOUDMORROW_RELAY_CACHE", ROOT / ".cache"))
    path = cache / f"headscale_{VERSION}_linux_{arch}"
    if not path.exists():
        cache.mkdir(parents=True, exist_ok=True)
        url = f"https://github.com/juanfont/headscale/releases/download/v{VERSION}/headscale_{VERSION}_linux_{arch}"
        try:
            with urllib.request.urlopen(url, timeout=60) as resp, open(str(path) + ".part", "wb") as f:
                shutil.copyfileobj(resp, f)
        except OSError as exc:
            pytest.skip(f"could not download Headscale: {exc}")
        os.replace(str(path) + ".part", path)
        path.chmod(0o755)
    return path


def _port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
async def headscale(tmp_path):
    binary = _binary()
    port, grpc = _port(), _port()
    extra = tmp_path / "extra-records.json"
    write_extra_records(extra, [])
    # Headscale insists on a DERP map; one region nobody will use.
    derp = tmp_path / "derp.yaml"
    derp.write_text(
        "regions:\n  900:\n    regionid: 900\n    regioncode: test\n    regionname: Test\n"
        "    nodes:\n      - name: 900a\n        regionid: 900\n        hostname: derp.invalid\n"
        "        stunport: -1\n        derpport: 443\n"
    )
    config = tmp_path / "config.yaml"
    config.write_text(f"""
server_url: http://127.0.0.1:{port}
listen_addr: 127.0.0.1:{port}
metrics_listen_addr: ""
grpc_listen_addr: 127.0.0.1:{grpc}
grpc_allow_insecure: false
disable_check_updates: true
noise:
  private_key_path: {tmp_path}/noise_private.key
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
  allocation: sequential
derp:
  server:
    enabled: false
  urls: []
  paths: [{derp}]
  auto_update_enabled: false
database:
  type: sqlite
  sqlite:
    path: {tmp_path}/db.sqlite
log:
  level: warn
policy:
  mode: file
  path: {POLICY}
dns:
  magic_dns: true
  base_domain: mesh.internal
  override_local_dns: false
  nameservers:
    global: []
  extra_records_path: {extra}
unix_socket: {tmp_path}/headscale.sock
unix_socket_permission: "0770"
""")
    proc = subprocess.Popen([binary, "-c", config, "serve"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        for _ in range(100):
            if proc.poll() is not None:
                pytest.fail("headscale exited: " + proc.stdout.read().decode(errors="replace")[-2000:])
            try:
                socket.create_connection(("127.0.0.1", port), 0.2).close()
                if (tmp_path / "headscale.sock").exists():
                    break
            except OSError:
                pass
            await asyncio.sleep(0.1)
        out = subprocess.run(
            [binary, "-c", config, "apikeys", "create", "--expiration", "1h"],
            capture_output=True, text=True, timeout=30, check=True,
        )
        key = out.stdout.strip().splitlines()[-1]
        client = Headscale(f"http://127.0.0.1:{port}", key)
        client.extra = extra
        client.binary, client.config = binary, config
        yield client
        await client.aclose()
    finally:
        proc.terminate()
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()


async def test_users_keys_and_nodes(headscale):
    user = await headscale.ensure_user("cloud-0123456789abcdef")
    assert (await headscale.ensure_user("cloud-0123456789abcdef"))["id"] == user["id"]
    key = await headscale.create_key("cloud-0123456789abcdef", ephemeral=False, expires_in=600)
    assert key["key"] and key["reusable"] is False
    assert str(key["user"]["id"]) == str(user["id"])
    assert await headscale.list_nodes("cloud-0123456789abcdef") == []
    # A registration id nobody started is refused, not accepted.
    with pytest.raises(HeadscaleError) as err:
        await headscale.register_node("cloud-0123456789abcdef", "hsnotpending1234567890")
    assert err.value.status and 400 <= err.value.status < 600
    await headscale.delete_user("cloud-0123456789abcdef")
    assert await headscale.find_user("cloud-0123456789abcdef") is None


async def test_a_phone_registration_lands_in_the_right_user(headscale):
    """What the pairing page does, against the real thing. Headscale's debug
    call stands in for the Tailscale app: it leaves a registration waiting
    under an auth id, as the app's /register/<auth_id> would.
    """
    await headscale.ensure_user("cloud-aaaaaaaaaaaaaaaa")
    await headscale.ensure_user("cloud-bbbbbbbbbbbbbbbb")
    auth_id = "hskey-authreq-" + secrets.token_urlsafe(18)
    await headscale._call("POST", "/debug/node", json={"user": "cloud-bbbbbbbbbbbbbbbb", "key": auth_id, "name": "phone"})
    node = await headscale.register_node("cloud-aaaaaaaaaaaaaaaa", auth_id)
    assert node["user"]["name"] == "cloud-aaaaaaaaaaaaaaaa"
    nodes = await headscale.list_nodes("cloud-aaaaaaaaaaaaaaaa")
    assert [n["id"] for n in nodes] == [node["id"]]
    assert await headscale.list_nodes("cloud-bbbbbbbbbbbbbbbb") == []
    assert device(nodes[0], {("node", str(node["id"])): "Anna's phone"})["label"] == "Anna's phone"
    # Giving the name back takes the devices with it.
    await headscale.delete_user("cloud-aaaaaaaaaaaaaaaa")
    assert await headscale.find_user("cloud-aaaaaaaaaaaaaaaa") is None


async def test_the_policy_keeps_users_apart(headscale):
    policy = await headscale.policy()
    assert "autogroup:self" in policy


async def test_extra_records_are_taken(headscale):
    # Headscale watches the file; a rewrite must not upset it.
    write_extra_records(headscale.extra, [{"name": "larsens.cm.test", "type": "A", "value": "100.64.0.5"}])
    await asyncio.sleep(0.5)
    assert json.loads(headscale.extra.read_text())[0]["value"] == "100.64.0.5"
    assert await headscale.find_user("nobody") is None  # still answering
