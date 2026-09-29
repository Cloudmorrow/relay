"""The authoritative DNS for the zone.

The zone's parent delegates to this server (NS records and glue at the
registrar), and it answers from the same database the control API writes,
so a linked name, a rename, an unlink or a new ACME challenge value is in
DNS the moment the call returns. Nothing to sync, no API
tokens for a DNS provider anywhere.

What it answers:

    <zone>, and names from [[dns.records]]    the operator's static records
    relay host, login host, nameservers     the relay's public addresses
    <name>.<zone>                            the relay's public addresses
                                             (the landing page; devices on
                                             the mesh ask Headscale instead)
    _acme-challenge.<name>.<zone> TXT        the cloud's latest two values

Anything else inside the zone is NXDOMAIN; anything outside it is REFUSED
(this is not a resolver, and must not be usable as an amplifier). ANY
queries get the smallest honest answer, as RFC 8482 suggests.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import socket
import time

from dnslib import AAAA, QTYPE, RCODE, RR, SOA, TXT, A, DNSHeader, DNSLabel, DNSRecord, NS

log = logging.getLogger("cloudmorrow_relay.dns")

MAX_UDP = 512
TCP_IDLE = 10.0
TCP_MAX_QUERIES = 32


class Authority:
    def __init__(self, cfg, store):
        self.cfg = cfg
        self.store = store
        self.zone = cfg.zone
        self._static: dict[str, list[RR]] = {}
        for rec in cfg.records:
            name = self.zone if rec.name in ("@", "") else f"{rec.name.lower()}.{self.zone}"
            zone_line = f"{name}. {rec.ttl} IN {rec.type.upper()} {rec.value}"
            for rr in RR.fromZone(zone_line):
                self._static.setdefault(name, []).append(rr)
        self._own_hosts: dict[str, tuple[str | None, str | None]] = {
            cfg.relay_host: (cfg.public_ipv4, cfg.public_ipv6),
            cfg.login_host: (cfg.public_ipv4, cfg.public_ipv6),
        }
        for ns in cfg.nameservers:
            if ns.name == self.zone or ns.name.endswith("." + self.zone):
                self._own_hosts[ns.name] = (ns.ipv4, ns.ipv6)

    # --- records ------------------------------------------------------------

    def soa(self) -> RR:
        mname = self.cfg.nameservers[0].name
        rname = self.cfg.hostmaster or f"hostmaster.{self.zone}"
        # The serial only matters to secondaries, which this setup has none
        # of; the clock is as good a counter as any.
        serial = int(time.time())
        return RR(
            self.zone,
            QTYPE.SOA,
            ttl=self.cfg.dns_ttl,
            rdata=SOA(mname, rname.replace("@", "."), (serial, 3600, 600, 1209600, self.cfg.dns_ttl)),
        )

    def _address_rrs(self, name: str, v4: str | None, v6: str | None, ttl: int) -> list[RR]:
        out = []
        if v4:
            out.append(RR(name, QTYPE.A, ttl=ttl, rdata=A(v4)))
        if v6:
            out.append(RR(name, QTYPE.AAAA, ttl=ttl, rdata=AAAA(v6)))
        return out

    def records(self, name: str) -> list[RR] | None:
        """Every record at `name`, or None if the name does not exist."""
        ttl = self.cfg.dns_ttl
        out: list[RR] = list(self._static.get(name, []))
        exists = bool(out)
        if name == self.zone:
            exists = True
            out.append(self.soa())
            out += [RR(self.zone, QTYPE.NS, ttl=3600, rdata=NS(ns.name)) for ns in self.cfg.nameservers]
        if name in self._own_hosts:
            exists = True
            out += self._address_rrs(name, *self._own_hosts[name], ttl)
        if exists:
            return out
        if not name.endswith("." + self.zone):
            return None
        labels = name[: -len(self.zone) - 1].split(".")
        if len(labels) == 1:
            cloud = self.store.cloud_by_name(labels[0])
            if cloud is None:
                return None
            return self._address_rrs(name, self.cfg.public_ipv4, self.cfg.public_ipv6, ttl)
        if len(labels) == 2 and labels[0] == "_acme-challenge":
            cloud = self.store.cloud_by_name(labels[1])
            if cloud is None:
                return None
            # A short TTL, so a retried challenge is seen at once.
            return [RR(name, QTYPE.TXT, ttl=1, rdata=TXT(t)) for t in self.store.acme_txt(cloud.id)]
        return None

    # --- answering ------------------------------------------------------------

    def answer(self, request: DNSRecord) -> DNSRecord:
        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, ra=0, rd=request.header.rd), q=request.q)
        if request.header.opcode != 0 or len(request.questions) != 1:
            reply.header.rcode = RCODE.NOTIMP
            return reply
        q = request.q
        name = str(q.qname).lower().rstrip(".")
        if not (name == self.zone or name.endswith("." + self.zone)):
            reply.header.rcode = RCODE.REFUSED
            return reply
        reply.header.aa = 1
        try:
            records = self.records(name)
        except Exception:  # a store error must not take the server down
            log.exception("answering %s", name)
            reply.header.rcode = RCODE.SERVFAIL
            return reply
        if records is None:
            reply.header.rcode = RCODE.NXDOMAIN
            reply.add_auth(self.soa())
            return reply
        qname = q.qname  # answer with the asker's own spelling (0x20)
        cname = [r for r in records if r.rtype == QTYPE.CNAME]
        if cname and q.qtype != QTYPE.CNAME:
            matched = cname
        elif q.qtype == QTYPE.ANY:
            matched = records[:1]
        else:
            matched = [r for r in records if r.rtype == q.qtype]
        for rr in matched:
            reply.add_answer(RR(qname, rr.rtype, rclass=rr.rclass, ttl=rr.ttl, rdata=rr.rdata))
        if not matched:
            reply.add_auth(self.soa())
        return reply

    def handle(self, data: bytes, max_size: int | None) -> bytes | None:
        try:
            request = DNSRecord.parse(data)
        except Exception:
            return None  # garbage gets no answer at all
        if request.header.qr:
            return None
        packed = self.answer(request).pack()
        if max_size is not None and len(packed) > max_size:
            truncated = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, tc=1), q=request.q)
            packed = truncated.pack()
        return packed


class _Udp(asyncio.DatagramProtocol):
    def __init__(self, authority: Authority):
        self.authority = authority
        self.transport = None

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        reply = self.authority.handle(data, MAX_UDP)
        if reply is not None:
            self.transport.sendto(reply, addr)


async def _tcp(authority: Authority, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        for _ in range(TCP_MAX_QUERIES):
            async with asyncio.timeout(TCP_IDLE):
                size = int.from_bytes(await reader.readexactly(2), "big")
                data = await reader.readexactly(size)
            reply = authority.handle(data, None)
            if reply is None:
                break
            writer.write(len(reply).to_bytes(2, "big") + reply)
            await writer.drain()
    except (TimeoutError, asyncio.IncompleteReadError, ConnectionError, OSError):
        pass
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def start(authority: Authority, hosts: list[str], port: int):
    """Listen on UDP and TCP; returns what to close, and the port (useful
    when asked for port 0).
    """
    loop = asyncio.get_running_loop()
    tcp = await asyncio.start_server(lambda r, w: _tcp(authority, r, w), hosts, port)
    actual = tcp.sockets[0].getsockname()[1]
    transports = []
    for host in hosts:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        if family == socket.AF_INET6:
            # "::" would otherwise take IPv4 as well and collide with a
            # separate "0.0.0.0" listener, as asyncio's TCP servers avoid.
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind((host, actual))
        transport, _ = await loop.create_datagram_endpoint(lambda: _Udp(authority), sock=sock)
        transports.append(transport)
    return tcp, transports, actual
