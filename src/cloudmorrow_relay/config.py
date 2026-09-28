"""The relay's configuration, read once from a TOML file.

Everything the relay needs to know about where it lives is here: the zone it
answers for, the two names that are its own (the relay host, which carries
the tunnels and the control API, and the login host, which is Headscale's
address for the Tailscale apps), the addresses it listens on and publishes
in DNS, and where its certificate and Headscale are.

The file is the operator's; the relay never writes it. What changes at run
time (clouds, tokens, codes) lives in the SQLite file in `state_dir`.
"""

from __future__ import annotations

import ipaddress
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


class ConfigError(ValueError):
    pass


@dataclass
class StaticRecord:
    """A DNS record the operator wants in the zone besides the clouds: the
    website at the apex, `www`, mail. Written as it would be in a zone file.
    """

    name: str  # relative to the zone; "@" is the apex
    type: str
    value: str
    ttl: int = 3600


@dataclass
class Nameserver:
    name: str  # fully qualified
    ipv4: str | None = None
    ipv6: str | None = None


@dataclass
class Route:
    """A name that is not a cloud's but shares the machine: the website,
    the shop. On 443 it is matched by SNI and passed through untouched,
    exactly like a cloud's; on 80 by Host. The upstream (a local Caddy, say)
    does its own TLS.
    """

    upstream: tuple[str, int]
    sni: list[str] = field(default_factory=list)
    host: list[str] = field(default_factory=list)
    # Send a PROXY protocol v1 line first, so the upstream sees the
    # visitor's address instead of the relay's (Caddy: proxy_protocol).
    proxy_protocol: bool = False


@dataclass
class Acme:
    """Getting the relay's own certificate (relay host + login host) by
    itself, with lego. Off when `client` is empty: then the files at
    tls.cert/tls.key are somebody else's business, as before.
    """

    client: str = ""  # "" or "lego"
    challenge: str = "dns-cloudflare"  # or "http" (webroot on our port 80)
    email: str = ""
    server: str = "https://acme-v02.api.letsencrypt.org/directory"
    lego: str = "lego"
    path: Path | None = None  # lego's own storage; default state_dir/lego
    renew_hours: float = 12.0


@dataclass
class Limits:
    # A name is cheap to claim and a squatter is patient: a handful an hour
    # from one address is plenty for anybody setting up a box.
    enrol_per_hour: int = 5
    # Pairing codes are made by a signed-in cloud, and tried by anybody who
    # can reach the login page. Six characters from 31 is about 2^29.7, so
    # the tries per address (and per phone waiting to be registered) are
    # what keeps guessing hopeless within a code's ten minutes.
    pair_codes_per_hour: int = 20
    pair_attempts_per_10min: int = 10
    mesh_keys_per_hour: int = 30
    bad_auth_per_minute: int = 30
    # The peek at the first bytes of a connection, before we know where it
    # goes: a slow or silent client is dropped after this long.
    peek_timeout: float = 10.0
    peek_max_bytes: int = 16 * 1024
    handshake_timeout: float = 10.0
    max_pending_connections: int = 2048
    body_max_bytes: int = 16 * 1024
    # cmtunnel/1 keepalive, seconds. The contract says 25 and 60; tests
    # shorten them.
    ping_after: float = 25.0
    dead_after: float = 60.0


RESERVED_NAMES = frozenset(
    """
    www relay mesh api mail smtp imap pop pop3 ftp sftp ns ns1 ns2 ns3 ns4 dns
    mx webmail autoconfig autodiscover admin administrator root hostmaster
    postmaster abuse security support help status docs blog shop store
    app apps dev staging test demo cdn static assets login auth account
    accounts id sso oauth derp headscale tailscale acme cloud cloudmorrow
    control console dashboard billing localhost broadcasthost wpad
    """.split()
)


@dataclass
class Config:
    zone: str
    relay_host: str
    login_host: str
    state_dir: Path
    public_ipv4: str | None = None
    public_ipv6: str | None = None
    listen: list[str] = field(default_factory=lambda: ["0.0.0.0", "::"])
    https_port: int = 443
    http_port: int = 80
    dns_port: int = 53
    # The port the world reaches https on, for the URLs the API hands out.
    # Only differs from https_port behind a port mapping or in dev mode.
    advertised_https_port: int | None = None
    tls_cert: Path | None = None
    tls_key: Path | None = None
    acme_webroot: Path | None = None
    headscale_url: str | None = None
    headscale_api_key: str | None = None
    # Read when the service starts, so a config can be checked before
    # Headscale has made its key.
    headscale_api_key_file: Path | None = None
    extra_records_path: Path | None = None
    mesh_prefixes: list[str] = field(
        default_factory=lambda: ["100.64.0.0/10", "fd7a:115c:a1e0::/48"]
    )
    nameservers: list[Nameserver] = field(default_factory=list)
    hostmaster: str | None = None
    dns_ttl: int = 60
    records: list[StaticRecord] = field(default_factory=list)
    extra_reserved: list[str] = field(default_factory=list)
    limits: Limits = field(default_factory=Limits)
    # Where the zone's records live: "builtin" (our own DNS server, the
    # parent delegates to it) or "cloudflare" (the zone is at Cloudflare
    # with a wildcard to this machine; we write only what the wildcard
    # cannot say).
    dns_backend: str = "builtin"
    cloudflare_api_url: str = "https://api.cloudflare.com/client/v4"
    cloudflare_zone: str | None = None  # default: the zone
    cloudflare_token_env: str = "CLOUDFLARE_API_TOKEN"
    dns_tag: str = "cloudmorrow-relay"
    routes: list[Route] = field(default_factory=list)
    acme: Acme = field(default_factory=Acme)

    # --- derived -------------------------------------------------------

    @property
    def db_path(self) -> Path:
        return self.state_dir / "relay.sqlite"

    @property
    def _port_suffix(self) -> str:
        port = self.advertised_https_port or self.https_port
        return "" if port == 443 else f":{port}"

    @property
    def login_server(self) -> str:
        return f"https://{self.login_host}{self._port_suffix}"

    @property
    def control_url(self) -> str:
        return f"https://{self.relay_host}{self._port_suffix}"

    def public_host(self, name: str) -> str:
        return f"{name}.{self.zone}"

    def reserved(self) -> frozenset[str]:
        """Names a cloud may not have: the built-in list, the operator's
        additions, and every label the zone already uses for itself.
        """
        own = set(self.extra_reserved)
        for host in [self.relay_host, self.login_host] + [n.name for n in self.nameservers]:
            if host.endswith("." + self.zone):
                own.add(host[: -len(self.zone) - 1].split(".")[-1])
        for rec in self.records:
            if rec.name not in ("@", ""):
                own.add(rec.name.split(".")[-1].lower())
        for route in self.routes:
            for host in route.sni + route.host:
                if host.endswith("." + self.zone):
                    own.add(host[: -len(self.zone) - 1].split(".")[-1])
        return RESERVED_NAMES | {n.lower() for n in own}


def _host(value: str, what: str) -> str:
    value = value.strip().lower().rstrip(".")
    if not value or " " in value:
        raise ConfigError(f"{what} is not a host name")
    return value


def _ip(value: str | None, version: int, what: str) -> str | None:
    if not value:
        return None
    try:
        addr = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ConfigError(f"{what} is not an IP address") from exc
    if addr.version != version:
        raise ConfigError(f"{what} is not an IPv{version} address")
    return str(addr)


def _upstream(value: str) -> tuple[str, int]:
    host, sep, port = str(value).rpartition(":")
    if not sep or not port.isdigit():
        raise ConfigError(f"route upstream {value!r} is not host:port")
    return host.strip("[]"), int(port)


def _routes(items: list[dict]) -> list[Route]:
    routes = []
    for item in items:
        unknown = set(item) - {"sni", "host", "upstream", "proxy_protocol"}
        if unknown:
            raise ConfigError(f"[[routes]]: unknown {', '.join(sorted(unknown))}")
        if "upstream" not in item or not (item.get("sni") or item.get("host")):
            raise ConfigError("[[routes]] needs an upstream and sni or host names")
        routes.append(Route(
            upstream=_upstream(item["upstream"]),
            sni=[_host(h, "route sni") for h in item.get("sni", [])],
            host=[_host(h, "route host") for h in item.get("host", [])],
            proxy_protocol=bool(item.get("proxy_protocol", False)),
        ))
    return routes


def from_dict(data: dict, base: Path | None = None) -> Config:
    """Build a Config from the parsed TOML. Relative paths are taken from
    the config file's folder, so a config and its certificates can move
    together.
    """

    def path(value: str | None) -> Path | None:
        if not value:
            return None
        p = Path(value).expanduser()
        return p if p.is_absolute() or base is None else base / p

    try:
        zone = _host(data["zone"], "zone")
    except KeyError as exc:
        raise ConfigError("the config needs a zone") from exc
    listen = data.get("listen", {})
    tls = data.get("tls", {})
    hs = data.get("headscale", {})
    dns = data.get("dns", {})
    try:
        limits = Limits(**data.get("limits", {}))
    except TypeError as exc:
        raise ConfigError(f"[limits]: {exc}") from exc

    nameservers = [
        Nameserver(
            name=_host(ns["name"], "nameserver"),
            ipv4=_ip(ns.get("ipv4"), 4, "nameserver ipv4"),
            ipv6=_ip(ns.get("ipv6"), 6, "nameserver ipv6"),
        )
        for ns in dns.get("nameservers", [])
    ]
    cfg = Config(
        zone=zone,
        relay_host=_host(data.get("relay_host", f"relay.{zone}"), "relay_host"),
        login_host=_host(data.get("login_host", f"mesh.{zone}"), "login_host"),
        state_dir=path(data.get("state_dir", "/var/lib/cloudmorrow-relay")),
        public_ipv4=_ip(data.get("public_ipv4"), 4, "public_ipv4"),
        public_ipv6=_ip(data.get("public_ipv6"), 6, "public_ipv6"),
        listen=list(listen.get("addresses", ["0.0.0.0", "::"])),
        https_port=int(listen.get("https_port", 443)),
        http_port=int(listen.get("http_port", 80)),
        dns_port=int(listen.get("dns_port", 53)),
        advertised_https_port=listen.get("advertised_https_port"),
        tls_cert=path(tls.get("cert")),
        tls_key=path(tls.get("key")),
        acme_webroot=path(tls.get("acme_webroot")),
        headscale_url=(hs.get("url") or "").rstrip("/") or None,
        headscale_api_key=hs.get("api_key"),
        headscale_api_key_file=path(hs.get("api_key_file")),
        extra_records_path=path(hs.get("extra_records_path")),
        mesh_prefixes=list(
            hs.get("mesh_prefixes", ["100.64.0.0/10", "fd7a:115c:a1e0::/48"])
        ),
        nameservers=nameservers,
        hostmaster=dns.get("hostmaster"),
        dns_ttl=int(dns.get("ttl", 60)),
        records=[StaticRecord(**r) for r in dns.get("records", [])],
        extra_reserved=list(data.get("reserved", [])),
        limits=limits,
        dns_backend=dns.get("backend", "builtin"),
        cloudflare_api_url=dns.get("cloudflare_api_url", "https://api.cloudflare.com/client/v4").rstrip("/"),
        cloudflare_zone=dns.get("cloudflare_zone"),
        cloudflare_token_env=dns.get("cloudflare_token_env", "CLOUDFLARE_API_TOKEN"),
        dns_tag=dns.get("tag", "cloudmorrow-relay"),
        routes=_routes(data.get("routes", [])),
        acme=Acme(
            client=tls.get("acme", ""),
            challenge=tls.get("acme_challenge", "dns-cloudflare"),
            email=tls.get("acme_email", ""),
            server=tls.get("acme_server", Acme.server),
            lego=tls.get("lego", "lego"),
            path=path(tls.get("lego_path")),
            renew_hours=float(tls.get("renew_hours", 12.0)),
        ),
    )
    if cfg.dns_backend not in ("builtin", "cloudflare"):
        raise ConfigError('dns.backend is "builtin" or "cloudflare"')
    if cfg.acme.client not in ("", "lego"):
        raise ConfigError('tls.acme is "lego" or empty')
    if cfg.acme.challenge not in ("dns-cloudflare", "http"):
        raise ConfigError('tls.acme_challenge is "dns-cloudflare" or "http"')
    if cfg.acme.client:
        if cfg.acme.path is None:
            cfg.acme.path = cfg.state_dir / "lego"
        # The certificate lego gets is copied here, where the relay reads it.
        if cfg.tls_cert is None:
            cfg.tls_cert = cfg.state_dir / "tls" / "fullchain.pem"
            cfg.tls_key = cfg.state_dir / "tls" / "privkey.pem"
        if cfg.acme.challenge == "http" and cfg.acme_webroot is None:
            cfg.acme_webroot = cfg.state_dir / "acme"
    for host in (cfg.relay_host, cfg.login_host):
        if not host.endswith("." + zone):
            raise ConfigError(f"{host} is not inside the zone {zone}")
    if not cfg.nameservers:
        # One nameserver named after the zone, at the relay's own address:
        # what a single-machine install has.
        cfg.nameservers = [Nameserver(f"ns1.{zone}", cfg.public_ipv4, cfg.public_ipv6)]
    if (cfg.tls_cert is None) != (cfg.tls_key is None):
        raise ConfigError("tls.cert and tls.key go together")
    return cfg


def load(path: Path) -> Config:
    with open(path, "rb") as f:
        data = tomllib.load(f)
    return from_dict(data, base=path.parent)
