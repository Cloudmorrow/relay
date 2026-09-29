"""The landing page at `<name>.<zone>`, for anybody not on the cloud's mesh.

Everywhere outside the mesh a cloud's name resolves to the relay (the
Cloudflare wildcard, or our own DNS server), and the relay answers with its
wildcard certificate for `*.<zone>`. Nothing is forwarded to the box: a
cloud's web app opens only on its devices. What a visitor gets instead is
one page:

- the display name and logo, if the owner turned them on; otherwise "A
  Cloudmorrow cloud";
- the client downloads, linked to the core's GitHub Releases, and
  `/install.sh`, a few lines of sh that fetch the released client installer
  and run it for this cloud (`--server https://<name>.<zone> --invite`);
- a QR code of the login server, for a phone's Tailscale app;
- one line saying the web app opens on the cloud's devices.

A name nobody has linked answers "There is no cloud here."

The page is plain HTML with no script, no external assets and a strict
content security policy; every value in it is escaped. A logo is served
from `/logo` with a policy of its own that forbids everything (SVG
included: an SVG opened on its own could otherwise run script), and the
page only ever shows it as an `<img>`, where no script runs anyway.
"""

from __future__ import annotations

import html

import segno
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response

PAGE_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Robots-Tag": "noindex",
    "Cache-Control": "no-cache",
}

LOGO_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-cache",
    "Content-Disposition": "inline",
}

# A small pixel cloud, drawn in rectangles; the page's only picture of its
# own. As a data: URL it is also the tab's icon.
CLOUD_PIXELS = [
    (5, 0, 4, 1), (4, 1, 6, 1), (11, 1, 3, 1), (2, 2, 13, 1), (1, 3, 15, 1), (0, 4, 16, 2), (1, 6, 14, 1),
]


def pixel_cloud(fill: str = "currentColor", size: int = 42) -> str:
    rects = "".join(f'<rect x="{x}" y="{y}" width="{w}" height="{h}"/>' for x, y, w, h in CLOUD_PIXELS)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 7" width="{size}" height="{size * 7 // 16}" '
        f'fill="{fill}" shape-rendering="crispEdges" aria-hidden="true">{rects}</svg>'
    )


def _favicon() -> str:
    from urllib.parse import quote

    return "data:image/svg+xml," + quote(pixel_cloud("#5b6cff", 32))


FAVICON = _favicon()

STYLE = """
:root{--bg:#f4f1ea;--card:#fffdf8;--ink:#1d1b16;--soft:#5d584c;--accent:#5b6cff;--accent2:#ff7a59;--code:#ece7db}
@media (prefers-color-scheme: dark){:root{--bg:#131219;--card:#1c1b24;--ink:#ecebf3;--soft:#a5a2b3;--accent:#8c98ff;--accent2:#ff9a7e;--code:#262431}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:17px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:40rem;margin:0 auto;padding:3rem 1rem 4rem}
.card{background:var(--card);border:3px solid var(--ink);box-shadow:6px 6px 0 var(--ink);padding:1.5rem 1.5rem 1.25rem;margin-bottom:1.75rem}
.band{height:6px;margin:-1.5rem -1.5rem 1.25rem;background:linear-gradient(90deg,var(--accent),var(--accent2))}
header{display:flex;gap:1rem;align-items:center}
header .mark{color:var(--accent);flex:none}
header img{width:64px;height:64px;object-fit:contain;flex:none;image-rendering:auto}
h1{font:700 1.6rem/1.2 ui-monospace,"SF Mono",Menlo,Consolas,monospace;margin:0;letter-spacing:-.01em;overflow-wrap:anywhere}
.host{margin:.2rem 0 0;color:var(--soft);font:600 .95rem ui-monospace,Menlo,Consolas,monospace;overflow-wrap:anywhere}
.lead{font-size:1.1rem;margin:1.25rem 0 0}
h2{font:700 .85rem ui-monospace,Menlo,Consolas,monospace;text-transform:uppercase;letter-spacing:.12em;margin:0 0 .6rem;color:var(--accent)}
h2::before{content:"";display:inline-block;width:.6em;height:.6em;background:var(--accent2);margin-right:.5em;vertical-align:.05em}
pre{background:var(--code);border:2px solid var(--ink);padding:.7rem .8rem;overflow-x:auto;font:.9rem/1.4 ui-monospace,Menlo,Consolas,monospace;margin:.6rem 0}
a{color:var(--accent);font-weight:600}
.button{display:inline-block;text-decoration:none;color:var(--card);background:var(--ink);padding:.45rem .9rem;border:2px solid var(--ink);box-shadow:3px 3px 0 var(--accent)}
.phone{display:flex;gap:1.25rem;align-items:center;flex-wrap:wrap}
.phone>div:last-child{flex:1 1 14rem;min-width:0}
.phone p{overflow-wrap:anywhere}
.qr{background:#fff;padding:6px;border:3px solid var(--ink);line-height:0;flex:none}
.qr svg{width:148px;height:148px}
small,.soft{color:var(--soft)}
footer{text-align:center;font:.8rem ui-monospace,Menlo,Consolas,monospace;color:var(--soft)}
"""


def _document(title: str, body: str) -> str:
    return (
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<title>{html.escape(title)}</title><link rel=\"icon\" href=\"{FAVICON}\">"
        f"<style>{STYLE}</style></head><body><main>{body}</main></body></html>"
    )


def qr_svg(text: str) -> str:
    """A QR code of `text` as inline SVG, dark on white whatever the
    theme: scanners want it that way round.
    """
    code = segno.make(text, error="m")
    return code.svg_inline(scale=4, border=2, dark="#1d1b16", light="#ffffff", title=text)


def landing_html(cfg, cloud, has_logo: bool) -> str:
    host = cfg.public_host(cloud.name)
    url = cfg.public_url(cloud.name)
    title = cloud.display_name if (cloud.show_name and cloud.display_name) else "A Cloudmorrow cloud"
    mark = (
        '<img src="/logo" alt="">' if (cloud.show_logo and has_logo)
        else f'<span class="mark">{pixel_cloud(size=56)}</span>'
    )
    e = html.escape
    body = f"""
<section class="card">
 <div class="band"></div>
 <header>{mark}<div><h1>{e(title)}</h1><p class="host">{e(host)}</p></div></header>
 <p class="lead">This cloud's web app opens on its devices. Ask someone on it for an invite.</p>
</section>
<section class="card">
 <h2>On a computer</h2>
 <p>Get the Cloudmorrow client, then use your invite to join.</p>
 <p><a class="button" href="{e(cfg.releases_url)}">Download the client</a></p>
 <p class="soft">Or in a terminal (macOS, Linux):</p>
 <pre>curl -fsSL {e(url)}/install.sh | sh</pre>
</section>
<section class="card">
 <h2>On a phone</h2>
 <div class="phone">
  <div class="qr">{qr_svg(cfg.login_server)}</div>
  <div>
   <p>Install the Tailscale app, choose a custom login server, and scan this
   or type <b>{e(cfg.login_server)}</b>.</p>
   <p class="soft">The app then opens a page that asks for your invite.</p>
  </div>
 </div>
</section>
<footer>{pixel_cloud(size=21)}<br>Cloudmorrow</footer>
"""
    return _document(title, body)


def nobody_html() -> str:
    body = f"""
<section class="card">
 <div class="band"></div>
 <header><span class="mark">{pixel_cloud(size=56)}</span><div><h1>There is no cloud here.</h1></div></header>
 <p class="lead soft">Nobody has linked a cloud to this name.</p>
</section>
"""
    return _document("There is no cloud here.", body)


def install_sh(cfg, cloud) -> str:
    url = cfg.public_url(cloud.name)
    return f"""#!/bin/sh
# Installs the Cloudmorrow client for {cfg.public_host(cloud.name)} and joins it
# with an invite. The installer itself comes from the Cloudmorrow releases:
#   {cfg.installer_url}
# Pass the invite as `sh -s -- <code>`, or type it when asked.
set -eu
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
curl -fsSL '{cfg.installer_url}' -o "$tmp"
sh "$tmp" --server '{url}' --invite "$@"
"""


def create_app(svc) -> FastAPI:
    cfg = svc.cfg
    store = svc.store
    app = FastAPI(title="Cloudmorrow landing", docs_url=None, redoc_url=None, openapi_url=None)

    def cloud_for(request: Request):
        label = cfg.cloud_label(svc.entry_name(request))
        return store.cloud_by_name(label) if label else None

    @app.get("/install.sh", include_in_schema=False)
    async def installer(request: Request):
        cloud = cloud_for(request)
        if cloud is None:
            return PlainTextResponse("There is no cloud here.\n", 404, headers=PAGE_HEADERS)
        return PlainTextResponse(install_sh(cfg, cloud), headers=PAGE_HEADERS)

    @app.get("/logo", include_in_schema=False)
    async def logo(request: Request):
        cloud = cloud_for(request)
        found = store.logo(cloud.id) if cloud is not None and cloud.show_logo else None
        if found is None:
            return Response(status_code=404, headers=LOGO_HEADERS)
        content_type, data = found
        return Response(data, media_type=content_type, headers=LOGO_HEADERS)

    @app.api_route("/{path:path}", methods=["GET", "HEAD"], include_in_schema=False)
    async def page(request: Request, path: str):
        cloud = cloud_for(request)
        if cloud is None:
            return HTMLResponse(nobody_html(), 404, headers=PAGE_HEADERS)
        # Any path gets the page: a link into the cloud's web app, opened
        # off the mesh, lands here and learns why. Only "/" is a 200.
        status = 200 if path == "" else 404
        return HTMLResponse(landing_html(cfg, cloud, store.has_logo(cloud.id)), status, headers=PAGE_HEADERS)

    return app
