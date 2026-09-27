"""What the relay remembers, in one SQLite file.

A cloud is a row: its id, its name, the hash of its token, whether it is
public, its mesh address, and how many bytes went through. Around it: the
acme-dns credentials and TXT values for its `_acme-challenge` record,
pairing codes, and labels for devices ("Jimmi's laptop").

Secrets are kept as hashes. A token is 32 random bytes, so a plain SHA-256
is enough to make a stolen database useless for impersonating a box. A
pairing code is only six characters, so its hash is keyed with a secret
that lives beside the database (`secret`, made on first start); a copy of
the database alone does not give the codes away, and they expire in ten
minutes anyway.

The relay is one process on one small machine: calls here are synchronous
and short (indexed lookups), made straight from the event loop. That keeps
the code plain; if it ever matters, this is the one place to change.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS clouds (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE,
    token_hash    TEXT NOT NULL UNIQUE,
    public        INTEGER NOT NULL DEFAULT 1,
    mesh_address  TEXT,
    bytes_in      INTEGER NOT NULL DEFAULT 0,
    bytes_out     INTEGER NOT NULL DEFAULT 0,
    acme_user     TEXT UNIQUE,
    acme_key_hash TEXT,
    acme_subdomain TEXT UNIQUE,
    created_at    REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS acme_txt (
    cloud_id   TEXT NOT NULL REFERENCES clouds(id) ON DELETE CASCADE,
    txt        TEXT NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS acme_txt_cloud ON acme_txt(cloud_id);
CREATE TABLE IF NOT EXISTS pair_codes (
    code_hash  TEXT PRIMARY KEY,
    cloud_id   TEXT NOT NULL REFERENCES clouds(id) ON DELETE CASCADE,
    label      TEXT NOT NULL DEFAULT '',
    expires_at REAL NOT NULL,
    used_at    REAL
);
CREATE TABLE IF NOT EXISTS labels (
    kind     TEXT NOT NULL,          -- 'key' (a pre-auth key id) or 'node'
    ref      TEXT NOT NULL,
    cloud_id TEXT NOT NULL REFERENCES clouds(id) ON DELETE CASCADE,
    label    TEXT NOT NULL,
    PRIMARY KEY (kind, ref)
);
"""

# acme-dns keeps the two most recent values, so a certificate for a name
# and its wildcard (two challenges at once) can be issued. We do the same.
ACME_TXT_KEEP = 2


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def tokens_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


@dataclass
class Cloud:
    id: str
    name: str
    token_hash: str
    public: bool
    mesh_address: str | None
    bytes_in: int
    bytes_out: int
    acme_user: str | None
    acme_key_hash: str | None
    acme_subdomain: str | None
    created_at: float

    @property
    def mesh_user(self) -> str:
        # The Headscale user is named after the id, not the name: a rename
        # then touches nothing in Headscale.
        return f"cloud-{self.id}"


class NameTaken(Exception):
    pass


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.executescript(SCHEMA)
        self._lock = threading.Lock()
        self.secret = self._load_secret(path.parent / "secret")

    @staticmethod
    def _load_secret(path: Path) -> bytes:
        if path.exists():
            return bytes.fromhex(path.read_text().strip())
        secret = secrets.token_bytes(32)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secret.hex())
        return secret

    def close(self) -> None:
        self._db.close()

    def _one(self, sql: str, *args) -> sqlite3.Row | None:
        with self._lock:
            return self._db.execute(sql, args).fetchone()

    def _all(self, sql: str, *args) -> list[sqlite3.Row]:
        with self._lock:
            return self._db.execute(sql, args).fetchall()

    def _exec(self, sql: str, *args) -> int:
        with self._lock:
            return self._db.execute(sql, args).rowcount

    @staticmethod
    def _cloud(row: sqlite3.Row | None) -> Cloud | None:
        if row is None:
            return None
        return Cloud(**{k: row[k] for k in row.keys()} | {"public": bool(row["public"])})

    # --- clouds --------------------------------------------------------

    def create_cloud(self, name: str) -> tuple[Cloud, str]:
        """A new cloud with a fresh token; the token is returned once and
        only its hash is kept.
        """
        cloud_id = secrets.token_hex(8)
        token = "cmr_" + secrets.token_urlsafe(32)
        try:
            self._exec(
                "INSERT INTO clouds (id, name, token_hash, created_at) VALUES (?, ?, ?, ?)",
                cloud_id, name, hash_token(token), time.time(),
            )
        except sqlite3.IntegrityError as exc:
            raise NameTaken(name) from exc
        return self.cloud(cloud_id), token

    def cloud(self, cloud_id: str) -> Cloud | None:
        return self._cloud(self._one("SELECT * FROM clouds WHERE id = ?", cloud_id))

    def cloud_by_name(self, name: str) -> Cloud | None:
        return self._cloud(self._one("SELECT * FROM clouds WHERE name = ?", name))

    def cloud_by_token(self, token: str) -> Cloud | None:
        digest = hash_token(token)
        cloud = self._cloud(self._one("SELECT * FROM clouds WHERE token_hash = ?", digest))
        # The lookup is by an index on the hash, which leaks nothing useful
        # about the token; the comparison is constant-time all the same.
        if cloud is None or not tokens_equal(cloud.token_hash, digest):
            return None
        return cloud

    def check_token(self, cloud_id: str, token: str) -> Cloud | None:
        cloud = self.cloud(cloud_id)
        # Hash even when the id is unknown, so a wrong id and a wrong token
        # take the same time.
        digest = hash_token(token)
        if cloud is None or not tokens_equal(cloud.token_hash, digest):
            return None
        return cloud

    def all_clouds(self) -> list[Cloud]:
        return [self._cloud(r) for r in self._all("SELECT * FROM clouds ORDER BY name")]

    def rename(self, cloud_id: str, name: str) -> None:
        try:
            self._exec("UPDATE clouds SET name = ? WHERE id = ?", name, cloud_id)
        except sqlite3.IntegrityError as exc:
            raise NameTaken(name) from exc

    def set_public(self, cloud_id: str, public: bool) -> None:
        self._exec("UPDATE clouds SET public = ? WHERE id = ?", int(public), cloud_id)

    def set_mesh_address(self, cloud_id: str, address: str | None) -> None:
        self._exec("UPDATE clouds SET mesh_address = ? WHERE id = ?", address, cloud_id)

    def add_bytes(self, cloud_id: str, bytes_in: int, bytes_out: int) -> None:
        if bytes_in or bytes_out:
            self._exec(
                "UPDATE clouds SET bytes_in = bytes_in + ?, bytes_out = bytes_out + ? WHERE id = ?",
                bytes_in, bytes_out, cloud_id,
            )

    def delete_cloud(self, cloud_id: str) -> None:
        self._exec("DELETE FROM clouds WHERE id = ?", cloud_id)

    # --- acme-dns ------------------------------------------------------

    def acme_register(self, cloud_id: str) -> tuple[str, str, str]:
        """New acme-dns credentials for a cloud, replacing any old ones.
        Returns (username, password, subdomain); the password is kept hashed.
        """
        user = secrets.token_hex(16)
        password = secrets.token_urlsafe(30)
        subdomain = secrets.token_hex(16)
        self._exec(
            "UPDATE clouds SET acme_user = ?, acme_key_hash = ?, acme_subdomain = ? WHERE id = ?",
            user, hash_token(password), subdomain, cloud_id,
        )
        return user, password, subdomain

    def acme_check(self, user: str, password: str) -> Cloud | None:
        cloud = self._cloud(self._one("SELECT * FROM clouds WHERE acme_user = ?", user))
        digest = hash_token(password)
        if cloud is None or not cloud.acme_key_hash:
            return None
        if not tokens_equal(cloud.acme_key_hash, digest):
            return None
        return cloud

    def acme_set_txt(self, cloud_id: str, txt: str) -> None:
        with self._lock:
            db = self._db
            db.execute("BEGIN")
            try:
                db.execute(
                    "INSERT INTO acme_txt (cloud_id, txt, updated_at) VALUES (?, ?, ?)",
                    (cloud_id, txt, time.time()),
                )
                db.execute(
                    """DELETE FROM acme_txt WHERE cloud_id = ? AND rowid NOT IN (
                         SELECT rowid FROM acme_txt WHERE cloud_id = ?
                         ORDER BY updated_at DESC, rowid DESC LIMIT ?)""",
                    (cloud_id, cloud_id, ACME_TXT_KEEP),
                )
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise

    def acme_txt(self, cloud_id: str) -> list[str]:
        rows = self._all(
            "SELECT txt FROM acme_txt WHERE cloud_id = ? ORDER BY updated_at DESC, rowid DESC",
            cloud_id,
        )
        return [r["txt"] for r in rows]

    # --- pairing codes -------------------------------------------------

    def code_hash(self, code: str) -> str:
        return hmac.new(self.secret, code.encode(), hashlib.sha256).hexdigest()

    def add_pair_code(self, cloud_id: str, code: str, label: str, expires_at: float) -> bool:
        self._exec("DELETE FROM pair_codes WHERE expires_at < ?", time.time() - 3600)
        try:
            self._exec(
                "INSERT INTO pair_codes (code_hash, cloud_id, label, expires_at) VALUES (?, ?, ?, ?)",
                self.code_hash(code), cloud_id, label, expires_at,
            )
        except sqlite3.IntegrityError:
            return False
        return True

    def claim_pair_code(self, code: str) -> tuple[Cloud, str] | None:
        """Use a code: it works once, until it expires. The claim is one
        UPDATE, so two phones racing with the same code cannot both win.
        """
        digest = self.code_hash(code)
        now = time.time()
        claimed = self._exec(
            "UPDATE pair_codes SET used_at = ? WHERE code_hash = ? AND used_at IS NULL AND expires_at > ?",
            now, digest, now,
        )
        if not claimed:
            return None
        row = self._one("SELECT cloud_id, label FROM pair_codes WHERE code_hash = ?", digest)
        cloud = self.cloud(row["cloud_id"]) if row else None
        return (cloud, row["label"]) if cloud else None

    def release_pair_code(self, code: str) -> None:
        """Give a claimed code back when the registration it was for failed
        on Headscale's side, so the person can try again with it.
        """
        self._exec("UPDATE pair_codes SET used_at = NULL WHERE code_hash = ?", self.code_hash(code))

    # --- labels --------------------------------------------------------

    def set_label(self, kind: str, ref: str, cloud_id: str, label: str) -> None:
        if not label:
            return
        self._exec(
            "INSERT OR REPLACE INTO labels (kind, ref, cloud_id, label) VALUES (?, ?, ?, ?)",
            kind, ref, cloud_id, label,
        )

    def labels(self, cloud_id: str) -> dict[tuple[str, str], str]:
        rows = self._all("SELECT kind, ref, label FROM labels WHERE cloud_id = ?", cloud_id)
        return {(r["kind"], r["ref"]): r["label"] for r in rows}

    def drop_label(self, kind: str, ref: str) -> None:
        self._exec("DELETE FROM labels WHERE kind = ? AND ref = ?", kind, ref)
