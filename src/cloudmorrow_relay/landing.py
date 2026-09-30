"""The offline page at `<name>.<zone>`, when the relay cannot pass a
visitor through to the cloud's box.

Everywhere outside the mesh a cloud's name resolves to the relay, which
passes the visitor's TLS through to the box unread (router.py). When it
cannot — the box has no mesh address or does not answer, or its owner
turned "Reachable from anywhere" off — the relay ends TLS itself with its
wildcard certificate for `*.<zone>` and answers with this page, and
nothing else. What a visitor gets:

- the display name and logo, if the owner turned them on; otherwise "A
  Cloudmorrow cloud";
- "This cloud can't be reached right now", or, when the owner took it off
  the internet, "This cloud opens at home and on its own devices";
- the client downloads, linked to the core's GitHub Releases, so they
  cost the relay nothing.

Every path answers 503 with the page (a link into the cloud's web app,
opened while the box is away, lands here and learns why), so `curl -f
…/install.sh | sh` fails rather than feeding a web page to sh. A name
nobody has linked answers "There is no cloud here." (404).

The page looks like cloudmorrow.com and is plain HTML with no script, no
external assets (its fonts and hedgehog are served from `/_cm/`) and a
strict content security policy; every value in it is escaped. A logo is served
from `/logo` with a policy of its own that forbids everything (SVG
included: an SVG opened on its own could otherwise run script), and the
page only ever shows it as an `<img>`, where no script runs anyway.
"""

from __future__ import annotations

import html
from functools import cache
from pathlib import Path

import segno
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, Response

PAGE_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; img-src 'self' data:; font-src 'self'; style-src 'unsafe-inline'; "
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

# The website's look (cloudmorrow.com, brand/tokens.css and site.css in
# cloudmorrow-web), with its fonts and hedgehog served from here: the page
# loads nothing from anywhere else. assets/ holds the latin subsets of
# Barlow, Barlow Semi Condensed and JetBrains Mono (SIL OFL, the OFL-*.txt
# beside them) and Morrow, the hedgehog, from the brand's assets.
ASSETS = Path(__file__).parent / "assets"
ASSET_TYPES = {".woff2": "font/woff2", ".png": "image/png", ".txt": "text/plain; charset=utf-8"}
ASSET_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "public, max-age=604800",
    "Access-Control-Allow-Origin": "*",
}
ASSET_PREFIX = "/_cm/"


@cache
def asset(name: str) -> bytes | None:
    """One of the page's own files, by its bare name; None for anything else."""
    if "/" in name or name.startswith(".") or Path(name).suffix not in ASSET_TYPES:
        return None
    path = ASSETS / name
    return path.read_bytes() if path.is_file() else None


# The website's 8x8 pixel icons, drawn as its dots are.
ICONS = {
    "screens": ["XXXXXXXX", "X......X", "X......X", "X......X", "XXXXXXXX", "...XX...", "..XXXX..", "........"],
    "phone": ["..XXXX..", ".X....X.", ".X....X.", ".X....X.", ".X....X.", ".X....X.", ".X.XX.X.", "..XXXX.."],
}


def px(name: str) -> str:
    dots = "".join(
        f'<rect x="{x + 0.08:g}" y="{y + 0.08:g}" width=".84" height=".84" rx=".14"/>'
        for y, row in enumerate(ICONS[name]) for x, cell in enumerate(row) if cell == "X"
    )
    return f'<svg class="px-icon" viewBox="0 0 8 8" fill="currentColor" aria-hidden="true">{dots}</svg>'


STYLE = """
@font-face{font-family:"Barlow";font-weight:400;font-display:swap;src:url(/_cm/barlow-400.woff2) format("woff2")}
@font-face{font-family:"Barlow";font-weight:600;font-display:swap;src:url(/_cm/barlow-600.woff2) format("woff2")}
@font-face{font-family:"Barlow Semi Condensed";font-weight:600;font-display:swap;src:url(/_cm/barlow-semi-condensed-600.woff2) format("woff2")}
@font-face{font-family:"Barlow Semi Condensed";font-weight:700;font-display:swap;src:url(/_cm/barlow-semi-condensed-700.woff2) format("woff2")}
@font-face{font-family:"JetBrains Mono";font-weight:400 600;font-display:swap;src:url(/_cm/jetbrains-mono.woff2) format("woff2")}
:root{
 --cm-night:#0b0d12;--cm-ink:#14171f;--cm-surface:#1f242e;--cm-line:#333a48;--cm-line-bright:#4a5364;
 --cm-text:#dfe5f0;--cm-muted:#99a1b3;--cm-deep:#0a3f75;--cm-cloud:#1c70b1;--cm-sky:#5aa6e0;
 --cm-spine:#845b28;--cm-lens:#e0a84c;
 --bg:var(--cm-ink);--surface:var(--cm-surface);--line:var(--cm-line);--text:var(--cm-text);
 --text-muted:var(--cm-muted);--link:var(--cm-sky);
 --font-display:"Barlow Semi Condensed","Barlow","Arial Narrow",sans-serif;
 --font-body:"Barlow",system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
 --font-mono:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
 color-scheme:dark}
@media (prefers-color-scheme:light){:root{--bg:#f4f6f9;--surface:#fff;--line:#d5dbe5;--text:var(--cm-ink);
 --text-muted:#5a6275;--link:#1a5e9c;color-scheme:light}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--text);font:400 1.0625rem/1.6 var(--font-body);-webkit-font-smoothing:antialiased}
h1,h2{margin:0;font-family:var(--font-display);font-weight:600;line-height:1.1;text-wrap:balance}
p{margin:0}
a{color:var(--link);text-underline-offset:3px}
code{font-family:var(--font-mono)}
.wrap{max-width:1040px;margin:0 auto;padding-inline:max(16px,4vw)}
.top{background:var(--cm-night);border-bottom:1px solid var(--cm-line);color-scheme:dark}
.top .wrap{display:flex;align-items:center;min-height:64px}
.brand{display:flex;align-items:center;gap:10px;text-decoration:none;color:#ececec}
.brand img{width:32px;height:32px}
.brand span{font:700 1.25rem/1 var(--font-display);letter-spacing:.035em}
.hero{background:radial-gradient(45% 60% at 80% 50%,color-mix(in srgb,var(--cm-cloud) 22%,transparent),transparent 70%),var(--cm-night);
 color:var(--cm-text);color-scheme:dark;border-bottom:1px solid var(--cm-line)}
.hero .wrap{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:32px;align-items:center;padding-block:56px}
.label{font:600 .8125rem/1.3 var(--font-display);letter-spacing:.14em;text-transform:uppercase;color:var(--cm-muted)}
.hero h1{font-size:clamp(2.4rem,6vw,3.5rem);line-height:1;margin-top:12px;overflow-wrap:anywhere}
.host{margin-top:10px;font:400 .95rem/1.4 var(--font-mono);color:var(--cm-sky);overflow-wrap:anywhere}
.lead{margin-top:24px;font-size:1.3125rem;line-height:1.5;max-width:30em}
.fine{margin-top:12px;color:var(--cm-muted)}
.hero a{color:var(--cm-sky)}
.hero figure{margin:0;width:176px;height:176px;display:grid;place-items:center}
.hero figure img{max-width:100%;max-height:100%;object-fit:contain}
.ways{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:24px;padding-block:48px}
.card{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:24px;display:grid;gap:14px;align-content:start;min-width:0}
.card h2{display:flex;align-items:center;gap:10px;font-size:1.625rem}
.card h2 .px-icon{width:20px;height:20px;color:var(--link)}
.muted{color:var(--text-muted)}
.btn{justify-self:start;display:inline-flex;align-items:center;min-height:44px;padding:0 20px;border-radius:10px;
 font:600 1rem/1 var(--font-display);letter-spacing:.04em;text-decoration:none;
 background:var(--cm-lens);color:var(--cm-ink);box-shadow:inset 0 -3px 0 color-mix(in srgb,var(--cm-spine) 55%,transparent)}
.btn:hover{filter:brightness(1.07)}
.cmd{background:var(--cm-night);border:1px solid var(--cm-line);border-radius:10px;color:var(--cm-text);color-scheme:dark;
 padding:14px 16px;font:400 .84rem/1.55 var(--font-mono);overflow-wrap:anywhere}
.cmd .p{color:var(--cm-lens);user-select:none}
.phone{display:flex;gap:20px;align-items:center;flex-wrap:wrap}
.phone>div:last-child{flex:1 1 12rem;min-width:0;display:grid;gap:10px}
.phone b{font:400 .8rem var(--font-mono);overflow-wrap:anywhere}
.qr{background:#fff;padding:6px;border-radius:10px;line-height:0;flex:none}
.qr svg{width:128px;height:128px}
.foot{border-top:1px solid var(--line);padding-block:32px;color:var(--text-muted);font-size:.93rem}
.foot .wrap{display:flex;align-items:center;gap:14px}
.foot img{width:40px;height:40px;flex:none}
.foot a{color:var(--text-muted)}
@media (max-width:720px){
 .hero .wrap{grid-template-columns:1fr;padding-block:40px}
 .hero figure{grid-row:1;width:112px;height:112px}
 .ways{grid-template-columns:1fr;padding-block:32px}}
"""


def _document(title: str, hero: str, rest: str = "") -> str:
    return (
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<title>{html.escape(title)}</title>"
        "<link rel=\"icon\" href=\"/_cm/morrow-head-32.png\" type=\"image/png\">"
        "<meta name=\"theme-color\" content=\"#0b0d12\">"
        f"<style>{STYLE}</style></head><body>"
        "<header class=\"top\"><div class=\"wrap\"><a class=\"brand\" href=\"https://cloudmorrow.com/\">"
        "<img src=\"/_cm/morrow-32.png\" srcset=\"/_cm/morrow-32.png 1x, /_cm/morrow-64.png 2x\" alt=\"\">"
        "<span>CLOUDMORROW</span></a></div></header>"
        f"<section class=\"hero\"><div class=\"wrap\">{hero}</div></section>{rest}"
        "<footer class=\"foot\"><div class=\"wrap\">"
        "<img src=\"/_cm/morrow-64.png\" srcset=\"/_cm/morrow-64.png 1x, /_cm/morrow-128.png 2x\" alt=\"\">"
        "<p>Cloudmorrow is free software under the GNU AGPL v3. Your data is yours, and so is the code. "
        "<a href=\"https://cloudmorrow.com/\">cloudmorrow.com</a></p></div></footer>"
        "</body></html>"
    )


def qr_svg(text: str) -> str:
    """A QR code of `text` as inline SVG, dark on white whatever the
    theme: scanners want it that way round.
    """
    code = segno.make(text, error="m")
    return code.svg_inline(scale=4, border=2, dark="#14171f", light="#ffffff", title=text)


MORROW = (
    '<img src="/_cm/morrow-128.png" srcset="/_cm/morrow-128.png 1x, /_cm/morrow-256.png 2x" '
    'width="176" height="176" alt="">'
)


def offline_html(cfg, cloud, has_logo: bool) -> str:
    host = cfg.public_host(cloud.name)
    url = cfg.public_url(cloud.name)
    named = bool(cloud.show_name and cloud.display_name)
    title = cloud.display_name if named else "A Cloudmorrow cloud"
    mark = '<img src="/logo" alt="">' if (cloud.show_logo and has_logo) else MORROW
    e = html.escape
    if cloud.public:
        lead = "This cloud can't be reached right now."
        fine = "Its box may be switched off, or away from the internet. Try again in a little while."
    else:
        lead = "This cloud opens at home and on its own devices."
        fine = "Its owner keeps it off the internet. On its home network, or in the Cloudmorrow app, it opens as usual."
    hero = f"""
<div>
 {'<p class="label">A Cloudmorrow cloud</p>' if named else ''}
 <h1>{e(title)}</h1>
 <p class="host">{e(host)}</p>
 <p class="lead">{e(lead)}</p>
 <p class="fine">{e(fine)}</p>
 <p class="fine">Yours? <a href="{e(cfg.clouds_url)}">My Clouds</a> shows how it is doing.</p>
</div>
<figure>{mark}</figure>
"""
    rest = f"""
<main class="wrap ways">
<section class="card">
 <h2>{px("screens")}On a computer</h2>
 <p class="muted">The desktop app and the terminal clients. Once you have signed in, they go straight to this cloud's box, wherever you are.</p>
 <a class="btn" href="{e(cfg.releases_url)}">Download the app</a>
</section>
<section class="card">
 <h2>{px("phone")}On a phone</h2>
 <div class="phone">
  <div class="qr">{qr_svg(url)}</div>
  <div>
   <p class="muted">Open this address in the phone's browser, and add it to the home screen:</p>
   <b>{e(url)}</b>
  </div>
 </div>
</section>
</main>
"""
    return _document(title, hero, rest)


def nobody_html() -> str:
    hero = f"""
<div>
 <h1>There is no cloud here.</h1>
 <p class="lead">Nobody has linked a cloud to this name.</p>
 <p class="fine"><a href="https://cloudmorrow.com/">What is Cloudmorrow?</a></p>
</div>
<figure>{MORROW}</figure>
"""
    return _document("There is no cloud here.", hero)


def create_app(svc) -> FastAPI:
    cfg = svc.cfg
    store = svc.store
    app = FastAPI(title="Cloudmorrow offline page", docs_url=None, redoc_url=None, openapi_url=None)

    def cloud_for(request: Request):
        label = cfg.cloud_label(svc.entry_name(request))
        return store.cloud_by_name(label) if label else None

    @app.get(ASSET_PREFIX + "{name}", include_in_schema=False)
    async def page_asset(name: str):
        data = asset(name)
        if data is None:
            return Response(status_code=404, headers=LOGO_HEADERS)
        return Response(data, media_type=ASSET_TYPES[Path(name).suffix], headers=ASSET_HEADERS)

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
        # The cloud is there but not here: every path, "/" too.
        headers = PAGE_HEADERS | ({"Retry-After": "60"} if cloud.public else {})
        return HTMLResponse(offline_html(cfg, cloud, store.has_logo(cloud.id)), 503, headers=headers)

    return app
