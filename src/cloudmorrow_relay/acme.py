"""The relay's own certificate, got and renewed by itself.

One certificate for the relay host and the login host, from Let's Encrypt,
by [lego](https://go-acme.github.io/lego/) — a maintained ACME client that
the image ships as one static binary. Writing an ACME client here would be
more code to trust than calling one.

`lego run` gets the certificate when there is none and renews it when it
is due (it decides; ARI included), and does nothing otherwise. So the relay
simply runs it at start and every `renew_hours`. When lego did get a new
certificate, its deploy hook (`cloudmorrow-relay install-cert`) copies it
to tls.cert/tls.key, and the relay re-reads them — the same path SIGHUP
takes, so nothing is dropped.

The challenge is DNS-01 through Cloudflare (the same token as the DNS
backend, handed to lego as CLOUDFLARE_DNS_API_TOKEN), or HTTP-01 through
the ACME webroot that port 80 serves for the relay's own names.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import sys
import tempfile
from pathlib import Path

log = logging.getLogger("cloudmorrow_relay.acme")


def lego_command(cfg) -> list[str]:
    acme = cfg.acme
    hook = " ".join([
        sys.executable, "-m", "cloudmorrow_relay", "install-cert",
        "--cert", str(cfg.tls_cert), "--key", str(cfg.tls_key),
    ])
    cmd = [
        acme.lego, "--log.format", "text", "run",
        "--accept-tos",
        "--path", str(acme.path),
        "--server", acme.server,
        "--domains", cfg.relay_host,
        "--domains", cfg.login_host,
        "--deploy-hook", hook,
    ]
    if acme.email:
        cmd += ["--email", acme.email]
    if acme.challenge == "http":
        cmd += ["--http", "--http.webroot", str(cfg.acme_webroot)]
    else:
        cmd += ["--dns", "cloudflare"]
    return cmd


def lego_env(cfg) -> dict[str, str]:
    env = dict(os.environ)
    token = os.environ.get(cfg.cloudflare_token_env)
    if token and cfg.acme.challenge == "dns-cloudflare":
        env.setdefault("CLOUDFLARE_DNS_API_TOKEN", token)
        if cfg.cloudflare_api_url != "https://api.cloudflare.com/client/v4":
            env.setdefault("CLOUDFLARE_BASE_URL", cfg.cloudflare_api_url)
    return env


def install(cert_src: Path, key_src: Path, cert: Path, key: Path) -> None:
    """Copy a certificate and its key into place, each in one rename, key
    first, so the relay never pairs a new certificate with an old key for
    longer than the moment between the two.
    """
    for src, dst, mode in ((key_src, key, 0o600), (cert_src, cert, 0o644)):
        dst.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=dst.parent, prefix=f".{dst.name}.")
        with os.fdopen(fd, "wb") as out, open(src, "rb") as inp:
            shutil.copyfileobj(inp, out)
        os.chmod(tmp, mode)
        os.replace(tmp, dst)


class Renewer:
    def __init__(self, cfg, certs):
        self.cfg = cfg
        self.certs = certs
        self._task: asyncio.Task | None = None

    async def run_once(self) -> bool:
        cmd = lego_command(self.cfg)
        self.cfg.acme.path.mkdir(parents=True, exist_ok=True)
        try:
            proc = await asyncio.create_subprocess_exec(*cmd, env=lego_env(self.cfg))
        except OSError as exc:
            log.warning("could not run lego (%s): %s", self.cfg.acme.lego, exc)
            return False
        code = await proc.wait()
        if code != 0:
            log.warning("lego exited with %d; the current certificate stays", code)
            return False
        # Cheap, and right whether lego renewed or found nothing due.
        self.certs.reload()
        return True

    async def _loop(self) -> None:
        while True:
            await self.run_once()
            await asyncio.sleep(self.cfg.acme.renew_hours * 3600)

    def start(self) -> None:
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
