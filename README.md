# Cloudmorrow relay

The cloudmorrow.tech side of *reaching your cloud*: what links a Cloudmorrow
box behind a home router to a cloudmorrow.com account, gives it the name
`larsens.cloudmorrow.tech`, and lets its people's phones and laptops join
its private mesh from anywhere. The contract it implements is the "Reaching
your cloud" section of the core repository's
[`docs/HOSTING.md`](https://github.com/Cloudmorrow/cloudmorrow/blob/main/docs/HOSTING.md).

**No cloud's traffic goes through it.** A cloud's web app opens only on its
own devices, over the mesh: WireGuard, end to end between devices, which
the relay coordinates (through [Headscale](https://github.com/juanfont/headscale))
and carries only when two devices cannot reach each other directly, still
encrypted. Anybody else who opens a cloud's name gets a landing page the
relay serves itself, with the client downloads; nothing is forwarded to a
box.

One process, these parts, one SQLite file:

| part | module | port |
| --- | --- | --- |
| SNI routing on 443, Host routing on 80 | `router.py`, `sni.py`, `conn.py` | 443, 80 |
| The control API (`/v1`) for boxes, linking, invites | `control.py`, `links.py`, `names.py` | loopback |
| The admin API (`/admin/v1`) for the website | `admin.py`, `logos.py` | loopback |
| The landing pages at `<name>.<zone>` | `landing.py` | loopback |
| The phone pairing page on the login host | `pairing.py` | loopback |
| Watching the boxes in Headscale: extra DNS records, uptime | `meshwatch.py`, `headscale.py` | — |
| The zone's DNS: our own authoritative server, or records at Cloudflare | `dnsbackend.py`, `dnsserver.py`, `cloudflare.py` | 53 UDP+TCP (builtin only) |
| The relay's own wildcard certificate, by lego (DNS-01 via Cloudflare, or HTTP-01) | `acme.py` | — |

plus `store.py` (SQLite), `config.py` (TOML), `limits.py` (rate limits),
`service.py` (starts it all), `cli.py`, and for dev and tests only
`devcerts.py` (a throwaway CA) and `fakeheadscale.py`.

## What it knows, and what it cannot know

It knows which names exist and which account owns each (an opaque id from
the website); the hash of each cloud's token; each box's mesh addresses and
when it went online or offline, over the last month, read from Headscale;
which devices are on each cloud's mesh (Headscale's own list: their keys,
addresses, and the device name a phone's Tailscale app reports, which the
relay neither stores nor passes on); what an owner chose to show on the
landing page; and, for minutes, the (hashed) link and invite codes. It sees
visitors' addresses while they are connected, for its rate limits; it does
not log them.

It cannot know what anybody said: mesh traffic is WireGuard between
devices. It keeps no labels for devices ("Jimmi's laptop" stays on the
box) and no names of people.

A cloud that wants none of it runs this repository itself and points the
core's `access_control` at it, or is never linked.

## Quick start (on one machine)

```
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/cloudmorrow-relay dev
```

`dev` runs everything on loopback: the relay on 18443 and 18080, DNS on
18053, a fake Headscale on 18081, a throwaway CA, and the zone `cm.localhost`
(which resolves to this machine without touching `/etc/hosts`). Names can
be claimed at once there (`open_claims`), and the link flow works with the
admin secret it prints. It prints what to point the core at:

```
  control server   https://relay.cm.localhost:18443
  admin API        https://relay.cm.localhost:18443/admin/v1   (Authorization: Bearer dev-admin-secret-not-for-real-use)
  landing pages    https://<name>.cm.localhost:18443   (http on :18080 redirects there)
  login server     https://mesh.cm.localhost:18443   (a fake Headscale behind it, on :18081)
  DNS              dig @127.0.0.1 -p 18053 <name>.cm.localhost
...
Point the core at it:
  access_control = "https://relay.cm.localhost:18443"
  SSL_CERT_FILE=<dir>/tls/bundle.pem   (so the core trusts the relay)
  The box's local TLS upstream (Caddy) serves <dir>/tls/box.pem (*.cm.localhost)
```

`--dir` keeps the state between runs; `--port-base` moves the ports;
`RELAY_ADMIN_SECRET` sets the admin secret.

Tests: `.venv/bin/pytest` (about 170 tests, about a minute). The live
Headscale tests download the release binary from GitHub into `.cache/` once
and are skipped when that fails.

## Choices for a deployment

**DNS: `[dns] backend`.** `"builtin"` (the default) makes the relay the
zone's authoritative server; the parent delegates to it (steps 1–2 below).
Every cloud's name answers with the relay's own addresses. `"cloudflare"`
leaves the zone at Cloudflare, with `*.<zone>` and `<zone>` pointing at the
machine, **DNS only** (the relay must see the visitor's own TLS). The relay
then writes only what the wildcard cannot say: `_acme-challenge.<name>` TXT
records for the acme-dns endpoint, and beside one an A/AAAA record at
`<name>` for the relay (see the protocol notes). Every record it creates
carries the comment `cloudmorrow-relay`; it never changes or deletes one
without it, and a full sync every ten minutes repairs anything a failed
call left (including the mesh-address records older versions wrote). The
token comes from `$CLOUDFLARE_API_TOKEN` (Zone → DNS → Edit, Zone → Zone →
Read, this zone only), never from the config file. A box's mesh address is
never published outside the mesh.

**Other sites on the same machine: `[[routes]]`.** The relay owns 443 and
80, so a website on the same box sits behind it: `sni = [...]` names are
passed through on 443 untouched (the site does its own TLS), and `host =
[...]` names on 80 by Host. `proxy_protocol = true` sends a PROXY v1 line
first, for an upstream that wants the visitor's address.

**The relay's own certificate: `[tls] acme = "lego"`.** The relay runs
[lego](https://go-acme.github.io/lego/) (shipped in the image) at start and
every twelve hours; lego gets or renews the certificate when due, its
deploy hook copies it to `tls.cert` / `tls.key`, and the relay re-reads it
without dropping anything. `acme_challenge = "dns-cloudflare"` uses the
same Cloudflare token and gets the wildcard `*.<zone>`, which covers the
relay host, the login host and every landing page. `"http"` answers
HTTP-01 from the webroot our port 80 serves, and gets the relay host and
the login host only: the landing pages then have no certificate. Without
`acme`, the files are yours to provide (certbot, step 4 below), and SIGHUP
re-reads them; for landing pages the certificate must cover `*.<zone>`.

**Linking, or open claims: `open_claims`.** Off (the default), a name comes
only through linking: the box asks for a link code, the person enters it on
the website, and the website approves it over the admin API. The admin API
needs a secret, from `$RELAY_ADMIN_SECRET` (`[admin] secret_env` names
another variable) or `[admin] secret_file`; at least 24 characters, and
without one the admin API is off. A self-hosted relay with no website sets
`open_claims = true`, and boxes claim a name with `POST /v1/clouds`.

## Deploying on the Hetzner box

cloudmorrow.tech at Cloudflare, one machine at 178.105.27.139 running the
relay, Headscale and the website. The files are in `deploy/hetzner/`:
`docker-compose.yml`, `relay.toml` (zone `cloudmorrow.tech`, relay
`relay.cloudmorrow.tech`, login `mesh.cloudmorrow.tech`, Cloudflare DNS,
lego, the website's routes), `headscale/config.yaml`, and a placeholder
`website/Caddyfile`. Everything that lasts is under `/srv/cloudmorrow-relay`.

Before: at Cloudflare, `cloudmorrow.tech` and `*.cloudmorrow.tech` A
178.105.27.139, **DNS only** (grey cloud) — already there. Make an API
token: *My Profile → API Tokens → Create Token → Edit zone DNS*, zone
`cloudmorrow.tech`, plus *Zone → Zone → Read*. In the Hetzner firewall open
22/tcp, 80/tcp, 443/tcp and 3478/udp (53 is not needed with Cloudflare).
`cloudmorrow.com` at Cloudflare: A 178.105.27.139, proxied, SSL mode *Full
(strict)*.

On the box, as root (Docker with the compose plugin installed):

```
mkdir -p /srv/cloudmorrow-relay && cd /srv/cloudmorrow-relay
git clone https://github.com/Cloudmorrow/relay.git relay
install -d -o 10001 -m 0750 state                 # the relay runs as uid 10001
install -d -o 10001 -m 0755 headscale-dns         # the relay writes, Headscale reads
echo '[]' > headscale-dns/extra-records.json && chown 10001 headscale-dns/extra-records.json
install -d headscale headscale-run website/data website/config
( umask 077; printf 'CLOUDFLARE_API_TOKEN=%s\nRELAY_ADMIN_SECRET=%s\n' '<the token>' "$(openssl rand -hex 32)" > secrets.env )
touch headscale-api-key && chown 10001 headscale-api-key && chmod 0400 headscale-api-key

cd /srv/cloudmorrow-relay/relay/deploy/hetzner
docker compose up -d headscale
docker compose exec headscale headscale apikeys create --expiration 3650d \
  | tail -n1 > /srv/cloudmorrow-relay/headscale-api-key
docker compose up -d --build relay website
docker compose logs -f relay     # wait for "loaded the relay's certificate" (a minute or two)
```

Check it:

```
curl -s https://relay.cloudmorrow.tech/v1/clouds/me          # {"detail":"A valid token is required."}
curl -s https://mesh.cloudmorrow.tech/health                  # Headscale: {"status":"pass"}
curl -s https://relay.cloudmorrow.tech/admin/v1/names/larsens \
  -H "Authorization: Bearer $RELAY_ADMIN_SECRET"             # {"available":true,"problem":null}
curl -s https://nobody.cloudmorrow.tech | grep -o 'There is no cloud here.'   # the landing page
curl -sI https://cloudmorrow.com                              # the website, through Cloudflare
```

Then clouds use `access_control = "https://relay.cloudmorrow.tech"` (the
core's server config), and the website calls
`https://relay.cloudmorrow.tech/admin/v1` with `RELAY_ADMIN_SECRET` from
`secrets.env`. `https://anything.cloudmorrow.tech` shows *There is no cloud
here.* until a box is linked under that name.

Update: `cd /srv/cloudmorrow-relay/relay && git pull && cd deploy/hetzner &&
docker compose up -d --build relay`. Back up `/srv/cloudmorrow-relay/state`
(the database, its `secret`, lego's account) and
`/srv/cloudmorrow-relay/headscale` (its database and `noise_private.key`);
`secrets.env` and `headscale-api-key` can be made again. The website service
is a placeholder: replace its image and `website/Caddyfile` with
cloudmorrow-web; it must keep serving TLS itself on its 443 (the relay
passes `cloudmorrow.com` through) and HTTP on 80 (Let's Encrypt's HTTP-01
arrives there through Cloudflare).

## Running it for real (your own DNS server)

What you need: a small VPS with a public IPv4 (and IPv6 if you have it), the
domain, and Docker. Everything below uses `cloudmorrow.com`, `203.0.113.10`
and `2001:db8::10`; replace them.

**1. DNS delegation.** The relay is the authoritative server for the whole
zone, so the zone's own records (the website, mail) move into its config
(`[[dns.records]]` in `relay.toml`). At the registrar:

- register the nameservers `ns1.cloudmorrow.com` and `ns2.cloudmorrow.com`
  with glue records `203.0.113.10` (and `2001:db8::10`) — most registrars
  call this "host records" or "child nameservers";
- set the domain's nameservers to those two.

Two names at one address is what registrars insist on. Until the delegation
has propagated (check with `dig NS cloudmorrow.com @a.gtld-servers.net`),
certbot below cannot work. If moving the whole domain is not wanted, use a
subzone instead (`zone = "c.cloudmorrow.com"`, delegated with two `NS`
records at the current DNS provider, no glue needed) — the names then
become `larsens.c.cloudmorrow.com`.

**2. Ports.** Open 53/udp, 53/tcp, 80/tcp, 443/tcp and 3478/udp (STUN for
Headscale's DERP). Nothing else. If the machine runs systemd-resolved, its
stub resolver holds 127.0.0.53:53: either list the public addresses in
`[listen] addresses` (the example does) or set `DNSStubListener=no`.

**3. Configure.** In `deploy/`:

```
cp relay.example.toml relay.toml              # zone, hosts, IPs, static records
$EDITOR headscale/config.yaml                 # server_url, derp ipv4/ipv6
mkdir -p secrets && touch secrets/headscale-api-key
docker compose up -d headscale
docker compose exec headscale headscale apikeys create --expiration 3650d > secrets/headscale-api-key
docker compose up -d relay
```

`deploy/headscale/policy.hujson` is what keeps each cloud's devices to
themselves (`autogroup:self`); without it Headscale lets every device reach
every other. The relay warns at start if the policy is missing it.

**4. The relay's own certificate.** One certificate for the relay host and
the login host (and `*.<zone>` for the landing pages, which needs a DNS
challenge; without it everything but the landing pages works). The relay
answers the HTTP challenge for its own names from `acme_webroot` on port
80, and starts without a certificate (refusing its own names on 443) until
there is one:

```
docker run --rm -v /etc/letsencrypt:/etc/letsencrypt \
  -v deploy_relay-state:/var/lib/cloudmorrow-relay \
  certbot/certbot certonly --webroot -w /var/lib/cloudmorrow-relay/acme \
  -d relay.cloudmorrow.com -d mesh.cloudmorrow.com -m you@example.com --agree-tos -n
deploy/install-cert.sh     # copies it where the relay (uid 10001) can read it, sends SIGHUP
```

(`deploy_relay-state` is the compose volume; the prefix is the compose
project name, `deploy` when run from that folder.) Let's Encrypt's own
folders are readable by root only, so `install-cert.sh` copies the two
files to `deploy/tls/` for the relay's user and sends SIGHUP, which makes
the relay re-read them without dropping anything. Renewal: `certbot renew`
from a daily timer, then `install-cert.sh`. With lego instead: `lego --http
--http.webroot <the same folder> -d relay.cloudmorrow.com -d
mesh.cloudmorrow.com run`, then copy its two files the same way.

**5. Backups.** Two things, both small: the relay's SQLite file
(`/var/lib/cloudmorrow-relay/relay.sqlite` plus `secret`, in the
`relay-state` volume) and Headscale's `/var/lib/headscale` (its
`db.sqlite` and `noise_private.key`: lose the key and every device must
enroll again). Use `sqlite3 relay.sqlite ".backup copy.sqlite"` for a
consistent copy while it runs. The extra-records file is rewritten from
Headscale within a minute of starting and needs no backup.

**Anybody can self-host it.** The same steps with your own domain, and
`open_claims = true` unless you run a website that links boxes; then in the
core's server config set `access_control = "https://relay.<your zone>"`.
Nothing in the core knows about cloudmorrow.com except that default.

## Protocol notes

Where the contract in HOSTING.md is silent or loose, this is what the relay
does. A box, or the website, talking to it should do the same.

**Routing.** On 443, SNI equal to the relay host or the login host is
terminated by the relay with its own certificate. A name in `[[routes]]
sni` is passed through untouched. Any other `<name>.<zone>` (one label) is
terminated with the same certificate (`*.<zone>`) and gets the landing
page, whether or not a cloud has the name. Everything else is closed — a
deeper name (`a.larsens.<zone>`), another zone, no SNI, or garbage. On 80
the `Host` header decides (exactly one; CRLF line ends only): the relay's
own names go to the control app (the ACME challenge, and a 308 to https),
routes to their upstream, and `<name>.<zone>` gets a 308 to
`https://<name>.<zone>` with the path kept.

**The login host.** Headscale's paths for Tailscale's protocol (`/ts2021`,
`/key`, `/health`, `/version`, `/verify`, `/derp…`, `/bootstrap-dns`,
`/machine/…`) go to Headscale; every other path (above all
`/register/<auth_id>`) goes to the relay's pairing page. The upstream is
picked by the first request, and the relay rewrites that request to
`Connection: close` (unless it is an upgrade), so a connection cannot carry
a second request somewhere else. Headscale's own `/api` is not reachable
from outside.

**The control API.** Created: 201 (`POST /v1/links`, `…/mesh/keys`,
`…/mesh/invites`, `/v1/invites/redeem`, `/v1/acme-dns/register`, and
`/v1/clouds` where claims are open). Deleted: 204, no body. `POST
/v1/links/poll` is 202 while waiting. Otherwise 200. Errors: 401 (token),
403 (`POST /v1/clouds` with claims closed), 404, 409 (name taken), 410
(link code gone), 413 (body over 16 KiB), 422 (bad name or field), 429
(rate limit), 502 (Headscale did not answer), 503 (no Headscale configured).
Every error body is `{"detail": "<sentence>"}`.

- **Names** are folded (Unicode NFKC, trimmed, lower case) and must then be
  5–40 of `a-z 0-9 -`, start and end with a letter or digit, and have no
  `--` (which also rules out `xn--` look-alikes). Reserved: the list in
  `config.py` (`www relay mesh api mail admin cloud …`), the labels the
  zone's own names and static records use, and `reserved` in the config.
- **Linking.** `POST /v1/links` (no body) → `{code, poll, url, expires_at,
  interval}`: `code` is eight characters from
  `23456789ABCDEFGHJKMNPQRSTUVWXYZ`, given as `KXRT-4829` and accepted in
  any case, with or without the hyphen or spaces; `poll` is a secret only
  the box has; `url` is `link_url` (`https://cloudmorrow.com/link`);
  `interval` is 5 (seconds). Both live fifteen minutes. Ten per address an
  hour. `POST /v1/links/poll {poll}` → 202 `{detail}` while waiting; once
  200 with `{cloud_id, token, name, zone, login_server, acme_dns}`; 410 when
  it ran out, was refused, was already collected, or is unknown. An
  approved link can be collected for fifteen minutes after the approval,
  however late in the code's life that came. The token is made when the box
  collects it, never before: nothing that works as a token waits in the
  database.
- `acme_dns` is what acme-dns's own `register` answers: `{username,
  password, subdomain, fulldomain, allowfrom, server_url}`. `fulldomain` is
  `_acme-challenge.<name>.<zone>` itself — the record is published at the
  name, so no CNAME is needed. `server_url` is
  `https://<relay_host>/v1/acme-dns` (for Caddy's `acmedns` module).
  `POST /v1/acme-dns/register` (with the token) rotates them; `update`
  keeps the latest two values (as acme-dns does) with a TTL of 1 s.
- `GET /v1/clouds/me` → `{cloud_id, name, zone, mesh_address,
  login_server}`. `mesh_address` is the box's mesh IPv4 as Headscale last
  said (within a minute), or null. There is no `PATCH`: renaming is the
  website's.
- `DELETE /v1/clouds/me` removes the Headscale user and its devices first;
  if Headscale does not answer, nothing is deleted (502). The same happens
  for the website's unlink.
- `POST …/mesh/keys` `{ephemeral: false, expires_in: 3600 (60…2592000
  seconds)}` → `{key, login_server, expires_at, node_hint}`. `node_hint` is
  `"cloud"` while the cloud has no box on the mesh (the key is for the box
  itself), else null. Anything else in the body (an older box's `for`) is
  ignored and not stored. Thirty an hour per cloud.
- `POST …/mesh/invites` (also at its old name, `…/mesh/pair`) → `{code,
  expires_at, login_server}`: six characters from the same alphabet, good
  once, for ten minutes, for a computer or a phone. Twenty an hour per
  cloud.
- `POST /v1/invites/redeem {name, code}`, no token → 201 `{key,
  login_server, expires_at}`, a one-time key valid an hour; 404 for a wrong,
  used or expired code, or a code of another cloud (which does not use it
  up). Ten tries per address and thirty per cloud name every ten minutes.
  If Headscale does not answer, the code is given back (502).
- `GET …/mesh/devices` → `{devices: [{id, address, online, last_seen}]}`
  (`address` is the mesh IPv4), all of the cloud's nodes, the box's own
  included. `DELETE …/mesh/devices/{id}` only for this cloud's own nodes.
- `PUT …/mesh/address` is accepted and ignored (older boxes): the relay
  reads the box's address from Headscale.

**The admin API** (`/admin/v1`, `Authorization: Bearer <admin secret>`;
401 for a wrong one, 429 after thirty wrong ones a minute from an address,
503 when no secret is configured). Accounts are opaque strings, at most 200
characters. A cloud that is not the account's is a 404, like one that does
not exist.

- `GET names/{name}` → `{available, problem}`, `problem` a sentence or null.
- `GET links/{code}` → `{waiting: true, expires_at}`; 404 for a code never
  given, 410 for one that ran out, was refused or was approved.
- `POST links/{code}/approve {account, name}` → 201 with the cloud's row,
  as in the list; 409 name taken, 410 code gone, 422 bad name.
  `POST links/{code}/refuse` → 204, or 410.
- `GET accounts/{account}/clouds` → a JSON list of `{cloud_id, name,
  created, online, online_since, state_since, uptime_30d, show_name,
  show_logo, display_name, has_logo}`. `online_since` and `state_since`
  are both when the *current* state began, online or offline ("offline for
  two days"); null before the relay has looked. `uptime_30d` is a fraction
  from 0 to 1, over the last thirty days or since the relay first looked,
  whichever is shorter; null before then.
- `PATCH clouds/{id} {account, name?, display_name?, show_name?,
  show_logo?}` → the row. `display_name` is at most 80 characters, inner
  space folded; `""` clears it.
- `GET`/`PUT`/`DELETE clouds/{id}/logo?account=…`: the logo, as the body
  with its content type. PNG, JPEG or SVG, at most 256 KiB, checked
  against its signature (422 with the reason). An SVG with script, event
  handlers, `foreignObject`, a DOCTYPE or entities, or links to anything
  outside itself is refused, not cleaned. `GET` answers it whether or not
  the landing page shows it.
- `POST clouds/{id}/invites {account}` → 201 `{code, expires_at,
  login_server}`: an invite, the same as one the box makes, for an owner
  with no device on the mesh yet to make one from. It counts against the
  cloud's invites per hour (429), and is 503 without Headscale.
- `DELETE clouds/{id}?account=…` → 204: unlink.

**The landing page.** `/`: the display name if `show_name` and one is set,
else *A Cloudmorrow cloud*; the logo if `show_logo` and one is set, as `<img
src="/logo">`; the client downloads (`[landing] releases_url`); `curl
-fsSL https://<name>.<zone>/install.sh | sh`; a QR code of the login
server; and *This cloud's web app opens on its devices. Ask someone on it
for an invite.* Any other path shows the same page with 404 (a link into
the web app, opened off the mesh). `/install.sh` downloads
`[landing] installer_url` and runs it with `--server https://<name>.<zone>
--invite`, passing on its own arguments (`sh -s -- <code>`). A name with no
cloud answers *There is no cloud here.* (404). The page has no script, no
external assets, and `default-src 'none'`; `/logo` is served with
`default-src 'none'; sandbox`. The name comes from the SNI, not the `Host`
header.

**Pairing a phone.** The page at `/register/<auth_id>` asks for an invite
code, accepted in any case with spaces or hyphens. If Headscale refuses the
registration (the phone's request expired), the code is given back. Ten
tries per address and per waiting phone every ten minutes.

**Watching the mesh.** Once a minute, and at once after a removed device or
an older box's address report, the relay lists every node
in Headscale. A cloud's box is the node with hostname `cloud` in the user
`cloud-<id>` (online first, then the one seen last). Its addresses go into
the database and into the extra-records file, `<name>.<zone>` A and AAAA,
rewritten only when it changed; renames and unlinks rewrite it at once.
Whether the box is online is stored when it changes, kept thirty-one days.
When Headscale does not answer, nothing changes.

**DNS.** `<name>.<zone>` is the relay's addresses, for everybody: the
landing page. Devices on the mesh resolve it to the box through
Headscale's extra records instead (which every device on the whole tailnet
can read; the policy is what keeps them from reaching another cloud's box).
With Cloudflare, a TXT record at `_acme-challenge.<name>` makes `<name>` an
empty non-terminal, which a wildcard does not cover (RFC 4592), so while a
cloud has challenge values the relay also writes `<name>` A/AAAA → its own
address. TXT values are written quoted, TTL 60.

**Headscale.** 0.26 or later (tested with 0.29.4). One user per cloud,
named `cloud-<cloud_id>`, so renames never touch Headscale. Pre-auth keys
are single-use.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
