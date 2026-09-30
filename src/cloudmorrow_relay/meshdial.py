"""Reaching a box over the mesh, to pass a visitor through to it.

The relay's host is a node on the mesh (`tag:relay`), and the policy lets
it reach port 8443 of the clouds' boxes and nothing else. How the relay
process gets onto the mesh is the operator's choice (`mesh_dial`):

    "direct"               the host runs tailscaled in kernel mode and the
                           relay uses host networking: a box's 100.64.x.x
                           address is an ordinary connect
    "socks5://host:port"   a userspace tailscaled (`--tun=userspace-networking
                           --socks5-server=host:port`), whose SOCKS5 proxy
                           makes the connection on the relay's behalf

Either way the relay then writes a PROXY protocol v2 header, so the box's
Caddy knows the visitor's address, and after it the visitor's own bytes,
starting with the ClientHello the relay read to find the name. The TLS in
them ends on the box.
"""

from __future__ import annotations

import asyncio
import ipaddress

from .conn import PlainConn

PROXY_V2_SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"


def proxy_v2_header(src: tuple | None, dst: tuple | None) -> bytes:
    """A PROXY protocol v2 header for a TCP connection from `src` to
    `dst` (each `(address, port, …)` as a socket reports it).

    The visitor's address and the relay address it came in on; an address
    the header cannot carry (families that differ, or none at all) gives
    a LOCAL header, which tells the box to use the connection's own
    addresses (the relay's) rather than to trust anything.
    """
    def ip(value: str):
        addr = ipaddress.ip_address(value.split("%")[0])
        # An IPv4 visitor on a dual-stack socket shows as ::ffff:a.b.c.d.
        return (addr.ipv4_mapped or addr) if addr.version == 6 else addr

    try:
        a, b = ip(src[0]), ip(dst[0])
        ports = int(src[1]).to_bytes(2, "big") + int(dst[1]).to_bytes(2, "big")
    except (TypeError, IndexError, ValueError, AttributeError):
        a = b = None
    if a is None or a.version != b.version:
        return PROXY_V2_SIGNATURE + b"\x20\x00\x00\x00"
    family = b"\x11" if a.version == 4 else b"\x21"  # TCP over IPv4 / IPv6
    body = a.packed + b.packed + ports
    return PROXY_V2_SIGNATURE + b"\x21" + family + len(body).to_bytes(2, "big") + body


async def _socks5(proxy: tuple[str, int], host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """A CONNECT through a SOCKS5 proxy with no authentication, as
    tailscaled's is. It answers only once the connection to the box is
    made, or refused.
    """
    reader, writer = await asyncio.open_connection(*proxy)
    try:
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        if await reader.readexactly(2) != b"\x05\x00":
            raise ConnectionError("the SOCKS5 proxy wants authentication")
        addr = ipaddress.ip_address(host)
        kind = b"\x01" if addr.version == 4 else b"\x04"
        writer.write(b"\x05\x01\x00" + kind + addr.packed + port.to_bytes(2, "big"))
        await writer.drain()
        head = await reader.readexactly(4)
        if head[0] != 5 or head[1] != 0:
            raise ConnectionError(f"the SOCKS5 proxy could not connect (reply {head[1]})")
        if head[3] == 1:
            await reader.readexactly(4 + 2)
        elif head[3] == 4:
            await reader.readexactly(16 + 2)
        elif head[3] == 3:
            await reader.readexactly((await reader.readexactly(1))[0] + 2)
        else:
            raise ConnectionError("the SOCKS5 proxy answered in a way it should not")
    except BaseException:
        writer.close()
        raise
    return reader, writer


async def dial(cfg, host: str) -> PlainConn:
    """A connection to port `box_port` of the box at mesh address `host`,
    within `box_connect_timeout`. Raises OSError (or TimeoutError, which is
    one) when the box cannot be reached.
    """
    proxy = cfg.mesh_socks5
    port = cfg.box_port
    async with asyncio.timeout(cfg.limits.box_connect_timeout):
        if proxy is None:
            reader, writer = await asyncio.open_connection(host, port)
        else:
            try:
                reader, writer = await _socks5(proxy, host, port)
            except asyncio.IncompleteReadError as exc:
                raise ConnectionError("the SOCKS5 proxy closed the connection") from exc
    return PlainConn(reader, writer)
