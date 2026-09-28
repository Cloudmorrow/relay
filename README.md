# Cloudmorrow relay

The cloudmorrow.com side of *reaching your cloud*: what lets a Cloudmorrow
box behind a home router be reached as `https://larsens.cloudmorrow.com`
from anywhere, and lets its people's phones and laptops join it privately.
The contract it implements is the "Reaching your cloud" section of the core
repository's [`docs/HOSTING.md`](https://github.com/bramlabs-io/cloudmorrow/blob/main/docs/HOSTING.md).

**It moves bytes it cannot read.** A visitor's TLS goes through the relay to
the box untouched: the relay reads the server name in the ClientHello, and
nothing after it. It never holds a certificate for a cloud. The private mesh
is WireGuard, end to end between devices; the relay only coordinates it.

One process, four parts, one SQLite file:

| part | module | port |
| --- | --- | --- |
| The relay: SNI routing on 443, Host routing on 80, the `cmtunnel/1` tunnels | `router.py`, `sni.py`, `tunnel.py`, `conn.py` | 443, 80 |
| The control API (`/v1`) and the phone pairing pages, behind the relay's own TLS | `control.py`, `pairing.py` | loopback |
| The zone's DNS: our own authoritative server, or records at Cloudflare | `dnsbackend.py`, `dnsserver.py`, `cloudflare.py` | 53 UDP+TCP (builtin only) |
| The relay's own certificate, by lego (DNS-01 via Cloudflare, or HTTP-01) | `acme.py` | — |
| Keeping [Headscale](https://github.com/juanfont/headscale) in step: a user per cloud, keys, devices, DNS records | `headscale.py` | — |

plus `store.py` (SQLite), `config.py` (TOML), `limits.py` (rate limits),
`service.py` (starts it all), `cli.py`, and for dev and tests only
`devcerts.py` (a throwaway CA) and `fakeheadscale.py`.

## What it knows, and what it cannot know

It knows which names exist and which cloud each belongs to; the hash of each
cloud's token; whether its tunnel is up and since when; how many bytes went
through it each way; the box's mesh address; which devices are enrolled in
each cloud's mesh, with the labels the cloud gave them; and, for ten
minutes, the (hashed) pairing codes. It sees visitors' IP addresses while
they are connected and passes them to the box in the `OPEN`; it does not log
them.

It cannot know what anybody said: public traffic is TLS between the visitor
and the box, and mesh traffic is WireGuard between devices. It never logs a
byte of payload. It cannot even tell which page a visitor asked for.

A cloud that wants none of it runs this repository itself and points the
core's `access_control` at it, or uses only the home network.

## Quick start (on one machine)

```
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/cloudmorrow-relay dev
```

`dev` runs everything on loopback: the relay on 18443 and 18080, DNS on
18053, a fake Headscale on 18081, a throwaway CA, and the zone `cm.localhost`
(which resolves to this machine without touching `/etc/hosts`). It prints
what to point the core at:

```
  control server   https://relay.cm.localhost:18443
  tunnel           relay.cm.localhost:18443  (TLS, then "CMTUNNEL/1 <cloud_id> <token>\n")
  public names     https://<name>.cm.localhost:18443   http://<name>.cm.localhost:18080
  login server     https://mesh.cm.localhost:18443   (a fake Headscale behind it, on :18081)
  DNS              dig @127.0.0.1 -p 18053 <name>.cm.localhost
...
Point the core at it:
  access_control = "https://relay.cm.localhost:18443"
  SSL_CERT_FILE=<dir>/tls/bundle.pem   (so the core trusts the relay)
  The box's local TLS upstream (Caddy) serves <dir>/tls/box.pem (*.cm.localhost)
```

`--dir` keeps the state between runs; `--port-base` moves the ports.

Tests: `.venv/bin/pytest` (about 130 tests, under a minute). The live
Headscale tests download the release binary from GitHub into `.cache/` once
and are skipped when that fails.

## Choices for a deployment

**DNS: `[dns] backend`.** `"builtin"` (the default) makes the relay the
zone's authoritative server; the parent delegates to it (steps 1–2 below).
`"cloudflare"` leaves the zone at Cloudflare, with `*.<zone>` and `<zone>`
pointing at the machine, **DNS only** (the relay must see the visitor's own
TLS). The relay then writes only what the wildcard cannot say:
`_acme-challenge.<name>` TXT records for the acme-dns endpoint, and for a
private cloud an A/AAAA record at `<name>` pointing at its mesh address
(removed again when it goes public or is deleted). Every record it creates
carries the comment `cloudmorrow-relay`; it never changes or deletes one
without it, and a full sync every ten minutes repairs anything a failed
call left. The token comes from `$CLOUDFLARE_API_TOKEN` (Zone → DNS → Edit,
Zone → Zone → Read, this zone only), never from the config file.

**Other sites on the same machine: `[[routes]]`.** The relay owns 443 and
80, so a website on the same box sits behind it: `sni = [...]` names are
passed through on 443 untouched, exactly like a cloud (the site does its own
TLS), and `host = [...]` names on 80 by Host. `proxy_protocol = true` sends a
PROXY v1 line first, for an upstream that wants the visitor's address.

**The relay's own certificate: `[tls] acme = "lego"`.** The relay runs
[lego](https://go-acme.github.io/lego/) (shipped in the image) at start and
every twelve hours; lego gets or renews the certificate for the relay host
and the login host when due, its deploy hook copies it to `tls.cert` /
`tls.key`, and the relay re-reads it without dropping anything.
`acme_challenge = "dns-cloudflare"` uses the same Cloudflare token;
`"http"` answers HTTP-01 from the webroot our port 80 serves. Without
`acme`, the files are yours to provide (certbot, step 4 below), and SIGHUP
re-reads them.

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
( umask 077; echo 'CLOUDFLARE_API_TOKEN=<the token>' > secrets.env )
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
curl -sI https://cloudmorrow.com                              # the website, through Cloudflare
```

Then clouds use `access_control = "https://relay.cloudmorrow.tech"` (the
core's server config).

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
the login host. The relay answers the HTTP challenge for its own names from
`acme_webroot` on port 80, and starts without a certificate (refusing its
own names on 443) until there is one:

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
consistent copy while it runs. The extra-records file is rewritten at start
and needs no backup.

**Anybody can self-host it.** The same steps with your own domain; then in
the core's server config set `access_control = "https://relay.<your zone>"`.
Nothing in the core knows about cloudmorrow.com except that default.

## Protocol notes

Where the contract in HOSTING.md is silent or loose, this is what the relay
does. A box talking to it should do the same.

**Where the tunnel goes.** The box dials the host and port of its
`access_control` URL (in production `relay_host:443`; in dev mode another
port), TLS with the relay's certificate, and sends the handshake line. The
relay tells the tunnel from an HTTP request by the first bytes
(`CMTUNNEL/1 `).

**The handshake.** One line, at most 512 bytes, within 10 seconds. `OK
<name>.<zone>` or `NO <reason>`, then the relay closes. Reasons: `unknown
cloud or wrong token`, `public access is off for this cloud`, `not a
cmtunnel/1 handshake`, `frames before OK`, `too many failed attempts, wait a
minute`. The box must read `OK` before sending frames. On `NO` it backs off;
for "public access is off" it waits until it turns public access on again.
A box that connects while the relay still holds its previous tunnel
replaces it: the old one is closed.

**Stream ids and stream 0.** Only the relay opens streams; it numbers them
from 1 upwards and never reuses a live one. Stream 0 is the connection
itself: `PING` and `PONG` are sent on stream 0.

**Frames.** A frame longer than 64 KiB (any type) ends the connection, as
does `OPEN` from the box, `DATA` beyond the window, or a `PING`/`WINDOW`
with the wrong payload size. Frame types the relay does not know are
skipped. `DATA`, `WINDOW` and `CLOSE` for a stream the relay has forgotten
are ignored (they crossed on the wire).

**`OPEN`.** UTF-8 JSON, `{"port": 443|80, "remote": "ip:port"}`; an IPv6
address is in brackets: `"[2001:db8::1]:51234"`. On 443 the first `DATA` is
the visitor's ClientHello; on 80, the request head (and whatever followed
it in the same read).

**Windows.** Counted in `DATA` payload bytes. `WINDOW` carries an unsigned
32-bit big-endian credit. The relay returns credit after it has written the
bytes to the visitor's socket (one `WINDOW` per `DATA` it handed on), so a
visitor who stops reading stops the box on that stream only. If the box
leaves more than 256 KiB unacknowledged on a stream, the relay ends the
tunnel.

**`CLOSE`.** "I will send no more `DATA` on this stream." A stream is gone
when both sides have sent it.
- The visitor ends its side: the relay sends `CLOSE` and keeps delivering
  what the box sends until the box's `CLOSE`.
- The box sends `CLOSE` (its upstream ended, or it could not connect): the
  relay writes out what it has, closes the visitor's connection, and sends
  its own `CLOSE`. Data the relay sent before seeing it may still arrive at
  the box; the box drops it.
- The box, on the relay's `CLOSE`: shut down the write side of its upstream
  and keep sending the upstream's answer until it ends, then `CLOSE`.

**Keepalive.** Silence means no frame *received*. After 25 s of it the relay
sends a `PING` (8 random bytes); after 60 s it drops the tunnel. `PONG`
counts as a frame.

**Routing.** On 443, SNI equal to the relay host or the **login host** is
terminated by the relay with its own certificate (one certificate for both
names). Everything else is `<name>.<zone>` with a live tunnel, or closed —
a name with no tunnel, a private cloud, a deeper name
(`a.larsens.<zone>`), no SNI, or garbage. On 80 the `Host` header decides
(exactly one; CRLF line ends only); a cloud's connection then goes to the box
whole, keep-alive and all.

**The login host.** Headscale's paths for Tailscale's protocol (`/ts2021`,
`/key`, `/health`, `/version`, `/verify`, `/derp…`, `/bootstrap-dns`,
`/machine/…`) go to Headscale; every other path (above all
`/register/<auth_id>`) goes to the relay's pairing pages. The upstream is
picked by the first request, and the relay rewrites that request to
`Connection: close` (unless it is an upgrade), so a connection cannot carry
a second request somewhere else. Headscale's own `/api` is not reachable
from outside.

**Pairing.** The page at `/register/<auth_id>` asks for the code; codes are
six characters from `23456789ABCDEFGHJKMNPQRSTUVWXYZ`, accepted in any case
with spaces or hyphens. A code works once, for ten minutes; if Headscale
refuses the registration (the phone's request expired), the code is given
back. Ten tries per address and per waiting phone every ten minutes.

**The control API.** Created: 201 (`POST /v1/clouds`, `…/mesh/keys`,
`…/mesh/pair`, `/v1/acme-dns/register`). Deleted: 204, no body. Otherwise
200. Errors: 401 (token), 404, 409 (name taken), 413 (body over 16 KiB), 422
(bad name or field), 429 (rate limit), 502 (Headscale did not answer), 503
(no Headscale configured). Every error body is `{"detail": "<sentence>"}`.

- Names are folded (Unicode NFKC, trimmed, lower case) and must then be
  3–40 of `a-z 0-9 -`, start and end with a letter or digit, and have no
  `--` (which also rules out `xn--` look-alikes). Reserved: the list in
  `config.py` (`www relay mesh api mail ns1 …`), the labels the zone's own
  names and static records use, and `reserved` in the config.
- `GET /v1/clouds/me` → `{cloud_id, name, zone, public_host, public, tunnel:
  {connected, connected_since}, bytes_in, bytes_out, mesh_address,
  login_server, devices}`. `bytes_in` is visitors → box. `PATCH` answers the
  same record without `devices`.
- `POST …/mesh/keys` `{ephemeral: false, expires_in: 3600 (60…2592000
  seconds), for: ""}`. `for` is at most 64 characters, as in `…/pair`.
- A device is `{id, name, label, addresses, online, last_seen, created_at}`;
  `label` is the `for` of the key or code it joined with.
- `PUT …/mesh/address` `{address}`: must lie in Headscale's prefixes and
  belong to one of this cloud's devices; `null` clears it.
- `DELETE /v1/clouds/me` removes the Headscale user and its devices first; if
  Headscale does not answer, nothing is deleted (502).
- acme-dns: `register` rotates the credentials and answers `{username,
  password, subdomain, fulldomain, allowfrom, server_url}`. `fulldomain` is
  `_acme-challenge.<name>.<zone>` itself — the record is published at the
  name, so no CNAME is needed. `update` keeps the latest two values (as
  acme-dns does) with a TTL of 1 s. For Caddy's `acmedns` module:
  `server_url` is `https://<relay_host>/v1/acme-dns`.

**DNS with Cloudflare.** The wildcard answers for public clouds and the
relay's names. A TXT record at `_acme-challenge.<name>` makes `<name>` an
empty non-terminal, which a wildcard does not cover (RFC 4592), so while a
public cloud has challenge values the relay also writes `<name>` A/AAAA →
its own address. TXT values are written quoted, TTL 60.

**DNS.** `<name>.<zone>` is the relay's addresses when public; the mesh
address when private and one is known; no address (NOERROR, empty) when
private without one. The mesh address is also published inside the mesh,
as a Headscale extra record, which all enrolled devices of all clouds can
resolve (the policy is what keeps them from reaching it).

**Headscale.** 0.26 or later (tested with 0.29.4). One user per cloud,
named `cloud-<cloud_id>`, so renames never touch Headscale. Pre-auth keys
are single-use.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
