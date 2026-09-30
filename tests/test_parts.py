"""Smaller parts on their own: config, limits, the Headscale client against
the fake, the request-head rewrite, and the `dev` command as the lead runs it.
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import signal
import ssl
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

from cloudmorrow_relay import sni
from dnslib import QTYPE

from cloudmorrow_relay.dnsserver import Authority
from cloudmorrow_relay.config import ConfigError, from_dict, load
from cloudmorrow_relay.fakeheadscale import FakeHeadscale
from cloudmorrow_relay.headscale import Headscale, HeadscaleError, write_extra_records
from cloudmorrow_relay.limits import RateLimiter

ROOT = Path(__file__).resolve().parent.parent


def test_example_config_loads():
    cfg = load(ROOT / "deploy" / "relay.example.toml")
    assert cfg.zone == "cloudmorrow.com"
    assert cfg.login_server == "https://mesh.cloudmorrow.com"
    assert cfg.control_url == "https://relay.cloudmorrow.com"
    reserved = cfg.reserved()
    assert {"relay", "mesh", "ns1", "ns2", "www"} <= reserved
    # Its static records parse, and the zone answers for them.
    authority = Authority(cfg, store=None)
    assert authority.records("www.cloudmorrow.com")[0].rtype == QTYPE.CNAME


def test_config_errors():
    with pytest.raises(ConfigError):
        from_dict({})
    with pytest.raises(ConfigError):
        from_dict({"zone": "a.test", "relay_host": "relay.other.test"})
    with pytest.raises(ConfigError):
        from_dict({"zone": "a.test", "public_ipv4": "::1"})
    with pytest.raises(ConfigError):
        from_dict({"zone": "a.test", "tls": {"cert": "x.pem"}})
    for dial in ("tailscale", "socks5://", "socks5://127.0.0.1", "socks5://:1055", "http://127.0.0.1:1055"):
        with pytest.raises(ConfigError):
            from_dict({"zone": "a.test", "mesh_dial": dial})
    with pytest.raises(ConfigError):
        from_dict({"zone": "a.test", "relay_addresses": ["relay.a.test"]})


def test_rate_limiter():
    limiter = RateLimiter(2, 60, max_keys=3)
    assert limiter.allow("a") and limiter.allow("a") and not limiter.allow("a")
    assert limiter.blocked("a") and not limiter.blocked("b")
    for key in "bcde":
        limiter.allow(key)
    assert len(limiter._hits) == 3  # bounded: the oldest keys went


def test_one_request_only():
    raw = b"GET /key HTTP/1.1\r\nHost: m\r\nConnection: keep-alive\r\nKeep-Alive: 5\r\n\r\nGET /api/v1/user HTTP/1.1\r\n"
    out = sni.one_request_only(raw)
    head, rest = out.split(b"\r\n\r\n", 1)
    assert head.endswith(b"Connection: close") and b"keep-alive" not in head.lower()
    assert rest == b"GET /api/v1/user HTTP/1.1\r\n"
    upgrade = b"POST /ts2021 HTTP/1.1\r\nHost: m\r\nConnection: Upgrade\r\nUpgrade: tailscale-control-protocol\r\n\r\n"
    assert sni.one_request_only(upgrade) == upgrade


async def test_headscale_client_against_the_fake():
    fake = FakeHeadscale("k")
    hs = Headscale("http://hs", "k", transport=httpx.ASGITransport(app=fake.app))
    one = await hs.ensure_user("cloud-1")
    assert (await hs.ensure_user("cloud-1"))["id"] == one["id"]
    key = await hs.create_key("cloud-1", ephemeral=True, expires_in=60)
    assert key["ephemeral"] and key["user"]["name"] == "cloud-1"
    fake._node(fake.user_by_name("cloud-1"), "box", key)
    await hs.ensure_user("cloud-2")
    fake._node(fake.user_by_name("cloud-2"), "other", None)
    assert [n["name"] for n in await hs.list_nodes("cloud-1")] == ["box"]
    assert await hs.list_nodes("nobody") == []
    await hs.delete_user("cloud-1")
    assert await hs.find_user("cloud-1") is None
    assert [n["name"] for n in fake.nodes.values()] == ["other"]
    await hs.aclose()
    wrong = Headscale("http://hs", "wrong", transport=httpx.ASGITransport(app=fake.app))
    with pytest.raises(HeadscaleError) as err:
        await wrong.ensure_user("x")
    assert err.value.status == 401
    await wrong.aclose()


def test_extra_records_file(tmp_path):
    path = tmp_path / "hs" / "extra.json"
    write_extra_records(path, [{"name": "a.test", "type": "A", "value": "100.64.0.1"}])
    assert json.loads(path.read_text()) == [{"name": "a.test", "type": "A", "value": "100.64.0.1"}]
    assert [p.name for p in path.parent.iterdir()] == ["extra.json"]  # no temp files left


def test_dev_command(tmp_path):
    """`cloudmorrow-relay dev` starts, prints where to point the core, and
    links a box against its own CA the way the website would, then shows
    the cloud's offline page (no box is on its fake mesh).
    """
    base = random.randint(20, 50) * 1000 + random.randint(0, 400)
    proc = subprocess.Popen(
        [sys.executable, "-m", "cloudmorrow_relay", "dev", "--dir", str(tmp_path), "--port-base", str(base)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        out = ""
        while "Ctrl-C stops it." not in out:
            line = proc.stdout.readline()
            if not line:
                pytest.fail("dev exited:\n" + out)
            out += line
        assert f'access_control = "https://relay.cm.localhost:{base + 443}"' in out
        ctx = ssl.create_default_context(cafile=str(tmp_path / "tls" / "ca.pem"))
        # Connect to 127.0.0.1 whatever *.localhost resolves to here; the
        # name still goes out as SNI.
        transport = httpx.HTTPTransport(verify=ctx)
        with httpx.Client(transport=transport, timeout=10) as client:
            import httpcore

            class Loop(httpcore.NetworkBackend):
                def __init__(self):
                    self.inner = httpcore.SyncBackend()

                def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
                    return self.inner.connect_tcp("127.0.0.1", port, timeout, local_address, socket_options)

            transport._pool = httpcore.ConnectionPool(ssl_context=ctx, network_backend=Loop())
            relay = f"https://relay.cm.localhost:{base + 443}"
            secret = out.split("Authorization: Bearer ", 1)[1].split(")", 1)[0]
            start = client.post(f"{relay}/v1/links").json()
            approved = client.post(
                f"{relay}/admin/v1/links/{start['code']}/approve",
                json={"account": "acct_dev", "name": "larsens"}, headers={"Authorization": f"Bearer {secret}"},
            )
            assert approved.status_code == 201, approved.text
            resp = client.post(f"{relay}/v1/links/poll", json={"poll": start["poll"]})
            assert resp.status_code == 200
            assert resp.json()["login_server"] == f"https://mesh.cm.localhost:{base + 443}"
            token = resp.json()["token"]
            key = client.post(f"{relay}/v1/clouds/me/mesh/keys", headers={"Authorization": f"Bearer {token}"})
            assert key.status_code == 201  # the fake Headscale is behind it
            # In dev mode a name can also be claimed at once.
            assert client.post(f"{relay}/v1/clouds", json={"name": "hansens"}).status_code == 201
            page = client.get(f"https://larsens.cm.localhost:{base + 443}/")
            # No box on a fake mesh: the offline page.
            assert page.status_code == 503 and "A Cloudmorrow cloud" in page.text
    finally:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()
    assert proc.returncode == 0


def test_new_settings(tmp_path):
    cfg = from_dict({
        "zone": "a.test", "open_claims": True, "link_url": "https://example.com/link",
        "admin": {"secret_env": "X_SECRET", "secret_file": "secret.txt"},
        "landing": {"releases_url": "https://example.com/r"},
        "headscale": {"poll_seconds": 5},
        "mesh_dial": "socks5://127.0.0.1:1055", "relay_addresses": ["100.64.0.9", "fd7a:115c:a1e0:0::9"],
    }, base=tmp_path)
    assert cfg.open_claims and cfg.link_url == "https://example.com/link"
    assert cfg.admin_secret_env == "X_SECRET" and cfg.admin_secret_file == tmp_path / "secret.txt"
    assert cfg.releases_url == "https://example.com/r"
    assert cfg.mesh_socks5 == ("127.0.0.1", 1055) and cfg.box_port == 8443
    assert cfg.relay_addresses == ["100.64.0.9", "fd7a:115c:a1e0::9"]
    plain = from_dict({"zone": "a.test"})
    assert (plain.mesh_dial, plain.mesh_socks5, plain.relay_addresses) == ("direct", None, [])
    assert plain.limits.box_connect_timeout == 3.0
    assert cfg.mesh_poll_seconds == 5
    assert cfg.cloud_label("larsens.a.test") == "larsens"
    for host in ("relay.a.test", "mesh.a.test", "a.larsens.a.test", "a.test", "larsens.b.test", None):
        assert cfg.cloud_label(host) is None


def test_an_old_database_is_brought_up_to_date(tmp_path):
    """A relay that ran the public tunnel: its clouds stay, what they no
    longer need goes.
    """
    import sqlite3

    from cloudmorrow_relay.store import Store

    db = sqlite3.connect(tmp_path / "relay.sqlite")
    db.executescript("""
        CREATE TABLE clouds (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, token_hash TEXT NOT NULL UNIQUE,
            public INTEGER NOT NULL DEFAULT 1, mesh_address TEXT, bytes_in INTEGER NOT NULL DEFAULT 0,
            bytes_out INTEGER NOT NULL DEFAULT 0, acme_user TEXT UNIQUE, acme_key_hash TEXT,
            acme_subdomain TEXT UNIQUE, created_at REAL NOT NULL);
        CREATE TABLE labels (kind TEXT, ref TEXT, cloud_id TEXT, label TEXT, PRIMARY KEY (kind, ref));
        CREATE TABLE pair_codes (code_hash TEXT PRIMARY KEY, cloud_id TEXT, label TEXT, expires_at REAL, used_at REAL);
        INSERT INTO clouds (id, name, token_hash, created_at) VALUES ('c1', 'larsens', 'h', 1.0);
        INSERT INTO labels VALUES ('node', '1', 'c1', 'Jimmi''s laptop');
    """)
    db.commit()
    db.close()
    store = Store(tmp_path / "relay.sqlite")
    cloud = store.cloud("c1")
    assert cloud.name == "larsens" and cloud.account is None and cloud.show_name is False
    columns = {r["name"] for r in store._all("PRAGMA table_info(clouds)")}
    assert not {"bytes_in", "bytes_out"} & columns
    # The tunnel's switch is pass-through's switch: it stays, as it was.
    assert cloud.public is True
    tables = {r["name"] for r in store._all("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert "labels" not in tables and "pair_codes" not in tables and "links" in tables
    store.set_public("c1", False)
    store.close()
    again = Store(tmp_path / "relay.sqlite")  # and again, with nothing left to do
    assert again.cloud("c1").public is False
    again.close()


def test_a_database_from_before_pass_through_gets_public(tmp_path):
    """The last release before pass-through had no `public`: every
    cloud gets it, on, and keeps what the box sets it to across restarts.
    """
    import sqlite3

    from cloudmorrow_relay.store import Store

    db = sqlite3.connect(tmp_path / "relay.sqlite")
    db.executescript("""
        CREATE TABLE clouds (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, token_hash TEXT NOT NULL UNIQUE,
            account TEXT, mesh_address TEXT, mesh_address6 TEXT, acme_user TEXT UNIQUE, acme_key_hash TEXT,
            acme_subdomain TEXT UNIQUE, display_name TEXT, show_name INTEGER NOT NULL DEFAULT 0,
            show_logo INTEGER NOT NULL DEFAULT 0, created_at REAL NOT NULL);
        INSERT INTO clouds (id, name, token_hash, created_at) VALUES ('c1', 'larsens', 'h', 1.0);
        INSERT INTO clouds (id, name, token_hash, created_at) VALUES ('c2', 'hansens', 'i', 1.0);
    """)
    db.commit()
    db.close()
    store = Store(tmp_path / "relay.sqlite")
    assert [c.public for c in store.all_clouds()] == [True, True]
    store.set_public("c1", False)
    store.close()
    store = Store(tmp_path / "relay.sqlite")
    assert (store.cloud("c1").public, store.cloud("c2").public) == (False, True)
    store.close()


def test_proxy_v2_header():
    from cloudmorrow_relay.meshdial import PROXY_V2_SIGNATURE, proxy_v2_header

    v4 = proxy_v2_header(("198.51.100.7", 50123), ("178.105.27.139", 443))
    assert v4 == (
        PROXY_V2_SIGNATURE + b"\x21\x11\x00\x0c"
        + bytes([198, 51, 100, 7]) + bytes([178, 105, 27, 139]) + (50123).to_bytes(2, "big") + (443).to_bytes(2, "big")
    )
    assert len(PROXY_V2_SIGNATURE) == 12
    v6 = proxy_v2_header(("2001:db8::7", 40000, 0, 0), ("2001:db8::1", 443, 0, 0))
    assert v6[12:16] == b"\x21\x21\x00\x24" and len(v6) == 16 + 36
    assert v6[16:32] == bytes.fromhex("20010db8000000000000000000000007")
    # An IPv4 visitor on a dual-stack socket is written as IPv4.
    mapped = proxy_v2_header(("::ffff:198.51.100.7", 50123, 0, 0), ("::ffff:178.105.27.139", 443, 0, 0))
    assert mapped == v4
    # What it cannot say, it does not guess: LOCAL, no addresses.
    for src, dst in ((None, None), (("198.51.100.7", 1), ("2001:db8::1", 443)), (("?", 1), ("1.2.3.4", 2))):
        assert proxy_v2_header(src, dst) == PROXY_V2_SIGNATURE + b"\x20\x00\x00\x00"


def test_hetzner_config_loads():
    cfg = load(ROOT / "deploy" / "hetzner" / "relay.toml")
    assert (cfg.zone, cfg.relay_host, cfg.login_host) == ("cloudmorrow.tech", "relay.cloudmorrow.tech", "mesh.cloudmorrow.tech")
    assert cfg.public_ipv4 == "178.105.27.139"
    assert cfg.dns_backend == "cloudflare" and cfg.acme.client == "lego"
    assert cfg.tls_cert == Path("/var/lib/cloudmorrow-relay/tls/fullchain.pem")
    assert [r.upstream for r in cfg.routes] == [("127.0.0.1", 8443), ("127.0.0.1", 8080)]
    assert cfg.routes[0].sni == ["cloudmorrow.com", "www.cloudmorrow.com"]
    assert cfg.login_server == "https://mesh.cloudmorrow.tech"
    assert cfg.mesh_dial == "direct" and cfg.box_port == 8443


def test_the_policy_lets_the_relay_reach_boxes_only():
    """The shipped policy, read as Headscale reads it (HuJSON: comments
    and trailing commas allowed).
    """
    import re

    text = (ROOT / "deploy" / "headscale" / "policy.hujson").read_text()
    policy = json.loads(re.sub(r",(\s*[}\]])", r"\1", re.sub(r"^\s*//.*$", "", text, flags=re.M)))
    assert policy["tagOwners"] == {"tag:relay": []}
    rules = [(r["src"], r["dst"]) for r in policy["acls"]]
    assert rules == [(["autogroup:member"], ["autogroup:self:*"]), (["tag:relay"], ["autogroup:member:8443"])]
