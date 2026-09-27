"""A throwaway certificate authority, for dev mode and the tests.

Real certificates come from Let's Encrypt; on a laptop there is nothing to
ask, so `cloudmorrow-relay dev` makes a CA that lives for the session and
signs the relay's certificate and a wildcard for the boxes. Anything that
should trust them is pointed at `ca.pem` (or at `bundle.pem`, which is the
usual public roots plus this one).
"""

from __future__ import annotations

import datetime as dt
import ipaddress
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


@dataclass
class Issued:
    cert: Path
    key: Path


def _key():
    return ec.generate_private_key(ec.SECP256R1())


def _write_key(key, path: Path) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)


class DevCA:
    def __init__(self, folder: Path, name: str = "Cloudmorrow relay dev CA"):
        folder.mkdir(parents=True, exist_ok=True)
        self.folder = folder
        self.key = _key()
        now = dt.datetime.now(dt.timezone.utc)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=True,
                    content_commitment=False, key_encipherment=False, data_encipherment=False,
                    key_agreement=False, encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(self.key, hashes.SHA256())
        )
        self.path = folder / "ca.pem"
        self.path.write_bytes(self.cert.public_bytes(serialization.Encoding.PEM))

    def issue(self, stem: str, names: list[str]) -> Issued:
        key = _key()
        now = dt.datetime.now(dt.timezone.utc)
        sans: list[x509.GeneralName] = []
        for n in names:
            try:
                sans.append(x509.IPAddress(ipaddress.ip_address(n)))
            except ValueError:
                sans.append(x509.DNSName(n))
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
            .issuer_name(self.cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(self.key, hashes.SHA256())
        )
        cert_path = self.folder / f"{stem}.pem"
        key_path = self.folder / f"{stem}-key.pem"
        cert_path.write_bytes(
            cert.public_bytes(serialization.Encoding.PEM)
            + self.cert.public_bytes(serialization.Encoding.PEM)
        )
        _write_key(key, key_path)
        return Issued(cert_path, key_path)

    def bundle(self) -> Path:
        """The public roots plus this CA, for SSL_CERT_FILE."""
        path = self.folder / "bundle.pem"
        roots = b""
        try:
            import certifi

            roots = Path(certifi.where()).read_bytes()
        except ImportError:  # pragma: no cover
            pass
        path.write_bytes(roots + b"\n" + self.path.read_bytes())
        return path
