"""Where the zone's records live, behind one small interface.

Two ways to run the zone:

- **builtin**: the relay is the zone's authoritative DNS server
  (dnsserver.py). It answers from the database directly, so a change needs
  no pushing anywhere; the hooks below do nothing.
- **cloudflare**: the zone lives at Cloudflare, with a wildcard
  (`*.<zone>` → this machine) that already says what a cloud's name needs.
  The relay writes only what a wildcard cannot express (cloudflare.py).

The control and admin APIs call `names_changed` after anything that can
change what DNS should say about a name (a link, a rename, an ACME
challenge value, an unlink); the backend brings those names in line. A periodic full sync heals whatever a failed call left
behind.
"""

from __future__ import annotations

import logging

from . import dnsserver

log = logging.getLogger("cloudmorrow_relay.dns")


class DnsError(Exception):
    pass


class DnsBackend:
    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass

    async def names_changed(self, names: list[str]) -> None:
        """Bring the records for these cloud names (labels, not FQDNs) in
        line with the database. Raises DnsError if that did not happen.
        """

    async def sync_all(self) -> None:
        pass


class BuiltinDns(DnsBackend):
    """Our own authoritative server on port 53 (UDP and TCP)."""

    def __init__(self, cfg, store):
        self.cfg = cfg
        self.authority = dnsserver.Authority(cfg, store)
        self.port = 0
        self._tcp = None
        self._udp: list = []

    async def start(self) -> None:
        self._tcp, self._udp, self.port = await dnsserver.start(
            self.authority, self.cfg.listen, self.cfg.dns_port
        )

    async def stop(self) -> None:
        if self._tcp is not None:
            self._tcp.close()
        for transport in self._udp:
            transport.close()
