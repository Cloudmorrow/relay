"""The relay getting its own certificate with lego, against a fake lego
that behaves like the real one: it checks what it is given, "obtains" a
certificate from the test CA, and runs the deploy hook the way lego v5 does
(split on spaces, the paths in LEGO_HOOK_CERT_PATH / _KEY_PATH).
"""

from __future__ import annotations

import asyncio
import stat
import sys
import textwrap

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from cloudmorrow_relay.acme import lego_command
from conftest import MESH, RELAY, visit


@pytest.fixture
def fake_lego(tmp_path, ca):
    issued = ca.issue("from-lego", ["*.cm.test"])
    log = tmp_path / "lego-calls.txt"
    script = tmp_path / "lego"
    script.write_text(textwrap.dedent(f"""\
        #!{sys.executable}
        import os, subprocess, sys
        args = sys.argv[1:]
        open({str(log)!r}, "a").write(" ".join(args) + "\\n" + os.environ.get("CLOUDFLARE_DNS_API_TOKEN", "-") + "\\n")
        assert "run" in args and "--accept-tos" in args
        hook = args[args.index("--deploy-hook") + 1]
        env = dict(os.environ, LEGO_HOOK_CERT_PATH={str(issued.cert)!r}, LEGO_HOOK_CERT_KEY_PATH={str(issued.key)!r})
        sys.exit(subprocess.call(hook.split(), env=env))
    """))
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return {"path": script, "log": log, "cert": issued.cert}


@pytest.fixture
def extra_config(fake_lego, tmp_path, monkeypatch):
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "cf-token-for-lego")
    # No certificate files at first: the relay starts without one.
    return {"tls": {
        "cert": str(tmp_path / "own" / "fullchain.pem"),
        "key": str(tmp_path / "own" / "privkey.pem"),
        "acme": "lego", "acme_email": "ops@example.com", "lego": str(fake_lego["path"]),
    }}


async def test_lego_gets_the_certificate_and_the_relay_serves_it(svc, fake_lego):
    for _ in range(200):
        if svc.certs.context is not None:
            break
        await asyncio.sleep(0.05)
    assert svc.certs.context is not None
    reader, writer = await visit(svc, RELAY)
    served = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
    expected = x509.load_pem_x509_certificate(fake_lego["cert"].read_bytes()).public_bytes(Encoding.DER)
    assert served == expected
    writer.close()
    call, token = fake_lego["log"].read_text().splitlines()[:2]
    # One wildcard covers the relay host, the login host and the landing
    # pages; listing them as well would make Let's Encrypt refuse.
    assert "--domains *.cm.test --force-cert-domains" in call
    assert RELAY not in call and MESH not in call
    assert "--dns cloudflare" in call and "--email ops@example.com" in call
    assert token == "cf-token-for-lego"
    assert oct(svc.cfg.tls_key.stat().st_mode & 0o777) == "0o600"


def test_http_challenge_command(tmp_path):
    from cloudmorrow_relay.config import from_dict

    cfg = from_dict({"zone": "a.test", "state_dir": str(tmp_path), "tls": {"acme": "lego", "acme_challenge": "http"}})
    cmd = lego_command(cfg)
    assert "--http.webroot" in cmd and str(tmp_path / "acme") in cmd
    assert "--dns" not in cmd
    # HTTP-01 cannot get a wildcard: the relay's two names only.
    assert [cmd[i + 1] for i, a in enumerate(cmd) if a == "--domains"] == ["relay.a.test", "mesh.a.test"]


def test_deeper_names_are_listed_beside_the_wildcard(tmp_path):
    from cloudmorrow_relay.config import from_dict

    cfg = from_dict({"zone": "a.test", "relay_host": "api.relay.a.test", "state_dir": str(tmp_path), "tls": {"acme": "lego"}})
    cmd = lego_command(cfg)
    assert [cmd[i + 1] for i, a in enumerate(cmd) if a == "--domains"] == ["*.a.test", "api.relay.a.test"]
    assert cfg.tls_cert == tmp_path / "tls" / "fullchain.pem"


def test_install_cert_needs_lego(tmp_path, monkeypatch):
    from cloudmorrow_relay.cli import main

    monkeypatch.delenv("LEGO_HOOK_CERT_PATH", raising=False)
    with pytest.raises(SystemExit):
        main(["install-cert", "--cert", str(tmp_path / "c"), "--key", str(tmp_path / "k")])


def test_the_dns_challenge_is_checked_with_public_resolvers(tmp_path):
    """Not the box's own stub resolver, which serves stale challenge records."""
    from cloudmorrow_relay.config import from_dict

    cfg = from_dict({"zone": "a.test", "state_dir": str(tmp_path), "tls": {"acme": "lego"}})
    cmd = lego_command(cfg)
    assert [cmd[i + 1] for i, a in enumerate(cmd) if a == "--dns.resolvers"] == ["1.1.1.1:53", "8.8.8.8:53"]
    cfg = from_dict({"zone": "a.test", "state_dir": str(tmp_path), "tls": {"acme": "lego", "acme_resolvers": ["9.9.9.9:53"]}})
    assert [a for a in lego_command(cfg) if a.endswith(":53")] == ["9.9.9.9:53"]
    http = from_dict({"zone": "a.test", "state_dir": str(tmp_path), "tls": {"acme": "lego", "acme_challenge": "http"}})
    assert "--dns.resolvers" not in lego_command(http)
