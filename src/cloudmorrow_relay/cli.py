"""`cloudmorrow-relay serve` and `cloudmorrow-relay dev`.

`serve` runs everything from a TOML config (deploy/relay.example.toml);
SIGHUP re-reads the certificate files, SIGTERM stops.

`dev` runs everything on high loopback ports, for trying a box against it
on one machine: a throwaway CA and certificates, a fake Headscale, and a
zone under `.localhost`, which resolves to this machine without touching
/etc/hosts (systemd-resolved and glibc's myhostname both answer
`*.localhost`, as do curl and browsers).
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import socket
import sys
import tempfile
from pathlib import Path

from . import __version__
from .config import from_dict, load
from .service import Service, start_uvicorn

DEV_ZONE = "cm.localhost"


async def _serve(cfg) -> None:
    svc = Service(cfg)
    await svc.start()
    logging.getLogger("cloudmorrow_relay").info(
        "serving %s: https %d, http %d, dns %d", cfg.zone, svc.https_port, svc.http_port, svc.dns_port
    )
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGHUP, svc.reload_certs)
    loop.add_signal_handler(signal.SIGTERM, stop.set)
    loop.add_signal_handler(signal.SIGINT, stop.set)
    await stop.wait()
    await svc.stop()


def _free(port: int) -> bool:
    with socket.socket() as s:
        try:
            s.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


async def _dev(folder: Path, base: int) -> None:
    from .devcerts import DevCA
    from .fakeheadscale import FakeHeadscale

    https, http, dns, hs_port = base + 443, base + 80, base + 53, base + 81
    for port in (https, http, dns, hs_port):
        if not _free(port):
            sys.exit(f"port {port} is in use; pick another --port-base")

    relay_host, login_host = f"relay.{DEV_ZONE}", f"mesh.{DEV_ZONE}"
    ca = DevCA(folder / "tls")
    own = ca.issue("relay", [relay_host, login_host])
    box = ca.issue("box", [f"*.{DEV_ZONE}", DEV_ZONE])
    bundle = ca.bundle()

    api_key = "dev-headscale-api-key"
    fake = FakeHeadscale(api_key)
    hs_server, hs_task = await start_uvicorn(fake.app, host="127.0.0.1", port=hs_port)

    cfg = from_dict({
        "zone": DEV_ZONE,
        "relay_host": relay_host,
        "login_host": login_host,
        "state_dir": str(folder / "state"),
        "public_ipv4": "127.0.0.1",
        "public_ipv6": "::1",
        "listen": {"addresses": ["127.0.0.1", "::1"], "https_port": https, "http_port": http, "dns_port": dns},
        "tls": {"cert": str(own.cert), "key": str(own.key)},
        "headscale": {
            "url": f"http://127.0.0.1:{hs_port}",
            "api_key": api_key,
            "extra_records_path": str(folder / "state" / "extra-records.json"),
        },
        # A laptop tries things over and over.
        "limits": {"enrol_per_hour": 1000, "pair_codes_per_hour": 1000, "mesh_keys_per_hour": 1000},
    })
    svc = Service(cfg)
    await svc.start()

    control = f"https://{relay_host}:{https}"
    print(f"""
Cloudmorrow relay {__version__}, dev mode — everything on this machine, nothing real.

  control server   {control}
  tunnel           {relay_host}:{https}  (TLS, then "CMTUNNEL/1 <cloud_id> <token>\\n")
  public names     https://<name>.{DEV_ZONE}:{https}   http://<name>.{DEV_ZONE}:{http}
  login server     https://{login_host}:{https}   (a fake Headscale behind it, on :{hs_port})
  DNS              dig @127.0.0.1 -p {dns} <name>.{DEV_ZONE}
  state            {folder}

Certificates (a throwaway CA, valid 30 days):
  CA               {ca.path}
  CA + public roots {bundle}
  for the box      {box.cert}  {box.key}   (*.{DEV_ZONE})

Point the core at it:
  access_control = "{control}"
  SSL_CERT_FILE={bundle}   (so the core trusts the relay)
  The tunnel is dialled at the host and port of access_control ({relay_host}:{https}).
  The box's local TLS upstream (Caddy) serves the box certificate above.

Try it:
  curl --cacert {ca.path} -X POST {control}/v1/clouds -H 'content-type: application/json' -d '{{"name": "larsens"}}'
  curl --cacert {ca.path} {control}/v1/clouds/me -H 'authorization: Bearer <token>'

Ctrl-C stops it.
""", flush=True)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGINT, stop.set)
    loop.add_signal_handler(signal.SIGTERM, stop.set)
    await stop.wait()
    await svc.stop()
    hs_server.should_exit = True
    await hs_task


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="cloudmorrow-relay", description="The relay, control server and DNS for reaching clouds.")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    p_serve = sub.add_parser("serve", help="run everything from a config file")
    p_serve.add_argument("--config", "-c", type=Path, default=Path("/etc/cloudmorrow-relay/relay.toml"))
    p_dev = sub.add_parser("dev", help="run everything on loopback with throwaway certificates")
    p_dev.add_argument("--dir", type=Path, help="where to keep the dev state (default: a new temporary folder)")
    p_dev.add_argument("--port-base", type=int, default=18000, help="ports are this plus 443, 80, 53 and 81")
    for p in (p_serve, p_dev):
        p.add_argument("--log-level", default="info")
    args = parser.parse_args(argv)
    logging.basicConfig(level=args.log_level.upper(), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    # httpx logs every request it makes to Headscale at INFO; that is noise.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    try:
        if args.command == "serve":
            asyncio.run(_serve(load(args.config)))
        else:
            folder = args.dir or Path(tempfile.mkdtemp(prefix="cloudmorrow-relay-dev-"))
            asyncio.run(_dev(folder.resolve(), args.port_base))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":  # pragma: no cover
    main()
