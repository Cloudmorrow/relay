"""The landing page at <name>.<zone>, as a visitor off the mesh sees it."""

from __future__ import annotations

import asyncio
import ssl

import pytest

from conftest import ZONE, loopback_client, visit

ACCOUNT = "acct_0123456789abcdef01234567"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
SVG = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><rect width="10" height="10"/></svg>'


@pytest.fixture
async def visitor(svc):
    """A browser at some name under the zone."""
    clients = []

    def at(name: str):
        client = loopback_client(svc.ca.path, f"https://{name}.{ZONE}:{svc.https_port}")
        clients.append(client)
        return client

    yield at
    for client in clients:
        await client.aclose()


async def test_the_page(visitor, link_box, svc):
    await link_box("larsens", ACCOUNT)
    resp = await visitor("larsens").get("/")
    assert resp.status_code == 200
    page = resp.text
    assert "<h1>A Cloudmorrow cloud</h1>" in page
    assert f"larsens.{ZONE}" in page
    assert "This cloud's web app opens on its devices. Ask someone on it for an invite." in page
    assert 'Yours? Make one in <a href="https://cloudmorrow.com/clouds">My Clouds</a>.' in page
    assert 'href="https://github.com/Cloudmorrow/cloudmorrow/releases/latest"' in page
    assert f"curl -fsSL https://larsens.{ZONE}:{svc.cfg.https_port}/install.sh | sh" in page or \
        f"curl -fsSL {svc.cfg.public_url('larsens')}/install.sh | sh" in page
    # The QR code of the login server, drawn here, no external anything.
    assert "<svg" in page and svc.cfg.login_server in page
    assert "http://" not in page.replace("http://www.w3.org/2000/svg", "")
    assert "<script" not in page
    csp = resp.headers["content-security-policy"]
    assert "default-src 'none'" in csp and "script-src" not in csp
    assert resp.headers["x-robots-tag"] == "noindex"


async def test_the_fonts_and_hedgehog_are_served_here(visitor, link_box):
    await link_box("larsens", ACCOUNT)
    browser = visitor("larsens")
    page = (await browser.get("/")).text
    for name in ("barlow-400.woff2", "barlow-semi-condensed-600.woff2", "jetbrains-mono.woff2", "morrow-128.png"):
        assert f"/_cm/{name}" in page
        resp = await browser.get(f"/_cm/{name}")
        assert resp.status_code == 200 and len(resp.content) > 1000, name
        assert resp.headers["x-content-type-options"] == "nosniff"
    assert (await browser.get("/_cm/barlow-400.woff2")).headers["content-type"] == "font/woff2"
    assert (await browser.get("/_cm/OFL-Barlow.txt")).status_code == 200
    for bad in ("/_cm/nothing.png", "/_cm/..%2Flanding.py", "/_cm/landing.py", "/_cm/.hidden.png"):
        assert (await browser.get(bad)).status_code == 404, bad
    # Anything but a page file is still the landing page's 404.
    assert (await browser.get("/_cm/a/b.png")).status_code == 404
    assert "font-src 'self'" in (await browser.get("/")).headers["content-security-policy"]


async def test_the_certificate_is_the_wildcard(link_box, svc):
    await link_box("larsens", ACCOUNT)
    reader, writer = await visit(svc, f"larsens.{ZONE}")  # verifies the name
    assert writer.get_extra_info("ssl_object") is not None
    writer.close()


async def test_display_name_and_logo_when_turned_on(visitor, link_box, admin, svc):
    one = await link_box("larsens", ACCOUNT)
    url = f"/admin/v1/clouds/{one['cloud_id']}"
    await admin.patch(url, json={"account": ACCOUNT, "display_name": "The <Larsens>"})
    await admin.put(f"{url}/logo", params={"account": ACCOUNT}, content=SVG, headers={"content-type": "image/svg+xml"})
    browser = visitor("larsens")
    page = (await browser.get("/")).text
    # Not turned on yet: neither shows.
    assert "Larsens" not in page.split("<h1>")[1].split("</h1>")[0]
    assert '<img src="/logo"' not in page
    assert (await browser.get("/logo")).status_code == 404

    await admin.patch(url, json={"account": ACCOUNT, "show_name": True, "show_logo": True})
    page = (await browser.get("/")).text
    assert "<h1>The &lt;Larsens&gt;</h1>" in page and "<title>The &lt;Larsens&gt;</title>" in page
    assert '<img src="/logo" alt="">' in page
    logo = await browser.get("/logo")
    assert logo.status_code == 200 and logo.content == SVG
    assert logo.headers["content-type"] == "image/svg+xml"
    assert "sandbox" in logo.headers["content-security-policy"]
    assert logo.headers["x-content-type-options"] == "nosniff"


async def test_install_sh(visitor, link_box, svc):
    await link_box("larsens", ACCOUNT)
    resp = await visitor("larsens").get("/install.sh")
    assert resp.status_code == 200 and resp.headers["content-type"].startswith("text/plain")
    script = resp.text
    assert script.startswith("#!/bin/sh\n")
    assert "https://github.com/Cloudmorrow/cloudmorrow/releases/latest/download/install.sh" in script
    assert f"--server '{svc.cfg.public_url('larsens')}' --invite" in script
    assert len(script.splitlines()) < 15


async def test_install_sh_runs_the_installer(visitor, link_box, svc, tmp_path):
    """The script as sh runs it, with curl standing in: it fetches the
    installer and hands it the server and the invite.
    """
    import os
    import subprocess

    await link_box("larsens", ACCOUNT)
    script = (await visitor("larsens").get("/install.sh")).text
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "curl").write_text(
        '#!/bin/sh\nwhile [ "$1" != "-o" ]; do shift; done\n'
        'printf \'echo "installer: $*"\\n\' > "$2"\n'
    )
    (bin_dir / "curl").chmod(0o755)
    out = subprocess.run(
        ["sh", "-s", "--", "ABC234"], input=script, capture_output=True, text=True,
        env={**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"}, timeout=10,
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == f"installer: --server {svc.cfg.public_url('larsens')} --invite ABC234"


async def test_no_cloud_here(visitor, svc):
    resp = await visitor("nobody").get("/")
    assert resp.status_code == 404
    assert "There is no cloud here." in resp.text
    assert (await visitor("nobody").get("/install.sh")).status_code == 404


async def test_deep_links_get_the_page_and_nothing_reaches_a_box(visitor, link_box):
    await link_box("larsens", ACCOUNT)
    resp = await visitor("larsens").get("/files/some-note")
    assert resp.status_code == 404 and "Ask someone on it for an invite." in resp.text
    assert (await visitor("larsens").post("/api/login", json={})).status_code == 405


async def test_the_sni_decides_not_the_host_header(link_box, svc):
    await link_box("larsens", ACCOUNT)
    async with loopback_client(svc.ca.path, f"https://larsens.{ZONE}:{svc.https_port}") as client:
        resp = await client.get("/", headers={"Host": f"nobody.{ZONE}"})
        assert resp.status_code == 200 and "Ask someone on it" in resp.text


async def test_port_80_redirects(link_box, svc):
    await link_box("larsens", ACCOUNT)
    for name in ("larsens", "nobody"):
        reader, writer = await asyncio.open_connection("127.0.0.1", svc.http_port)
        writer.write(f"GET /install.sh?x=1 HTTP/1.1\r\nHost: {name}.{ZONE}\r\n\r\n".encode())
        data = await asyncio.wait_for(reader.read(), 5)
        writer.close()
        head = data.decode().split("\r\n")
        assert head[0] == "HTTP/1.1 308 Permanent Redirect"
        assert f"Location: {svc.cfg.public_url(name)}/install.sh?x=1" in head


async def test_deeper_names_and_other_zones_are_closed(svc):
    for name in (f"a.larsens.{ZONE}", "example.com"):
        with pytest.raises((ssl.SSLError, ConnectionError, OSError)):
            reader, writer = await visit(svc, name, verify=False)
            await asyncio.wait_for(reader.read(), 2)
            raise ConnectionError("closed")
