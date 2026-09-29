"""What the relay remembers, in one SQLite file.

A cloud is a row: its id, its name, the account that owns it (an opaque
string from the website), the hash of its token, its box's mesh addresses,
and what the owner chose to show on the landing page. Around it: the
acme-dns credentials and TXT values for its `_acme-challenge` record,
invite codes, link codes waiting for the website, its logo, and the times
its box went online or offline.

Secrets are kept as hashes. A token is 32 random bytes, so a plain SHA-256
is enough to make a stolen database useless for impersonating a box. Invite
and link codes are short, so their hashes are keyed with a secret that
lives beside the database (`secret`, made on first start); a copy of the
database alone does not give the codes away, and they expire within
minutes anyway.

A linked box's token is made when the box collects it, not when the
website approves the link: nothing that works as a token ever waits in
the database in the clear.

The relay is one process on one small machine: calls here are synchronous
and short (indexed lookups), made straight from the event loop. That keeps
the code plain; if it ever matters, this is the one place to change.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass, fields
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS clouds (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL UNIQUE,
    token_hash     TEXT NOT NULL UNIQUE,
    account        TEXT,
    mesh_address   TEXT,
    mesh_address6  TEXT,
    acme_user      TEXT UNIQUE,
    acme_key_hash  TEXT,
    acme_subdomain TEXT UNIQUE,
    display_name   TEXT,
    show_name      INTEGER NOT NULL DEFAULT 0,
    show_logo      INTEGER NOT NULL DEFAULT 0,
    created_at     REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS clouds_account ON clouds(account);
CREATE TABLE IF NOT EXISTS acme_txt (
    cloud_id   TEXT NOT NULL REFERENCES clouds(id) ON DELETE CASCADE,
    txt        TEXT NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS acme_txt_cloud ON acme_txt(cloud_id);
CREATE TABLE IF NOT EXISTS invites (
    code_hash  TEXT PRIMARY KEY,
    cloud_id   TEXT NOT NULL REFERENCES clouds(id) ON DELETE CASCADE,
    expires_at REAL NOT NULL,
    used_at    REAL
);
CREATE TABLE IF NOT EXISTS links (
    code_hash   TEXT PRIMARY KEY,
    poll_hash   TEXT NOT NULL UNIQUE,
    expires_at  REAL NOT NULL,
    state       TEXT NOT NULL DEFAULT 'waiting',  -- approved, refused, collected
    cloud_id    TEXT REFERENCES clouds(id) ON DELETE SET NULL,
    approved_at REAL
);
CREATE TABLE IF NOT EXISTS logos (
    cloud_id     TEXT PRIMARY KEY REFERENCES clouds(id) ON DELETE CASCADE,
    content_type TEXT NOT NULL,
    data         BLOB NOT NULL,
    updated_at   REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS uptime (
    cloud_id TEXT NOT NULL REFERENCES clouds(id) ON DELETE CASCADE,
    at       REAL NOT NULL,
    online   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS uptime_cloud ON uptime(cloud_id, at);
"""

# What an older database has that this one does not want: the public
# tunnel's switch and byte counts, device labels, pairing codes (now
# invites; any left expire within ten minutes anyway).
MIGRATIONS = [
    "ALTER TABLE clouds ADD COLUMN account TEXT",
    "ALTER TABLE clouds ADD COLUMN mesh_address6 TEXT",
    "ALTER TABLE clouds ADD COLUMN display_name TEXT",
    "ALTER TABLE clouds ADD COLUMN show_name INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE clouds ADD COLUMN show_logo INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE clouds DROP COLUMN public",
    "ALTER TABLE clouds DROP COLUMN bytes_in",
    "ALTER TABLE clouds DROP COLUMN bytes_out",
    "DROP TABLE IF EXISTS labels",
    "DROP TABLE IF EXISTS pair_codes",
]

# How long uptime changes are kept: the website shows thirty days.
UPTIME_KEEP = 31 * 24 * 3600

# acme-dns keeps the two most recent values, so a certificate for a name
# and its wildcard (two challenges at once) can be issued. We do the same.
ACME_TXT_KEEP = 2


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def tokens_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def iso(ts: float) -> str:
    """A time as the API writes it: UTC, to the second."""
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_token() -> str:
    return "cmr_" + secrets.token_urlsafe(32)


@dataclass
class Cloud:
    id: str
    name: str
    token_hash: str
    account: str | None
    mesh_address: str | None
    mesh_address6: str | None
    acme_user: str | None
    acme_key_hash: str | None
    acme_subdomain: str | None
    display_name: str | None
    show_name: bool
    show_logo: bool
    created_at: float

    @property
    def mesh_user(self) -> str:
        # The Headscale user is named after the id, not the name: a rename
        # then touches nothing in Headscale.
        return f"cloud-{self.id}"


CLOUD_FIELDS = [f.name for f in fields(Cloud)]


class NameTaken(Exception):
    pass


class LinkGone(Exception):
    pass


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._migrate()
        self._db.executescript(SCHEMA)
        self._lock = threading.Lock()
        self.secret = self._load_secret(path.parent / "secret")

    def _migrate(self) -> None:
        exists = self._db.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'clouds'"
        ).fetchone()
        if not exists:
            return
        for sql in MIGRATIONS:
            # Each step either applies or has been applied already (a
            # duplicate or missing column); either way it is done.
            with contextlib.suppress(sqlite3.OperationalError):
                self._db.execute(sql)

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
        values = {k: row[k] for k in CLOUD_FIELDS}
        values["show_name"] = bool(values["show_name"])
        values["show_logo"] = bool(values["show_logo"])
        return Cloud(**values)

    def code_hash(self, code: str) -> str:
        return hmac.new(self.secret, code.encode(), hashlib.sha256).hexdigest()

    # --- clouds --------------------------------------------------------

    def create_cloud(self, name: str, account: str | None = None) -> tuple[Cloud, str]:
        """A new cloud with a fresh token; the token is returned once and
        only its hash is kept.
        """
        with self._lock:
            cloud_id, token = self._insert_cloud(name, account)
        return self.cloud(cloud_id), token

    def _insert_cloud(self, name: str, account: str | None) -> tuple[str, str]:
        # Called with the lock held.
        cloud_id = secrets.token_hex(8)
        token = new_token()
        try:
            self._db.execute(
                "INSERT INTO clouds (id, name, token_hash, account, created_at) VALUES (?, ?, ?, ?, ?)",
                (cloud_id, name, hash_token(token), account, time.time()),
            )
        except sqlite3.IntegrityError as exc:
            raise NameTaken(name) from exc
        return cloud_id, token

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

    def all_clouds(self) -> list[Cloud]:
        return [self._cloud(r) for r in self._all("SELECT * FROM clouds ORDER BY name")]

    def clouds_of(self, account: str) -> list[Cloud]:
        rows = self._all("SELECT * FROM clouds WHERE account = ? ORDER BY name", account)
        return [self._cloud(r) for r in rows]

    def rename(self, cloud_id: str, name: str) -> None:
        try:
            self._exec("UPDATE clouds SET name = ? WHERE id = ?", name, cloud_id)
        except sqlite3.IntegrityError as exc:
            raise NameTaken(name) from exc

    def new_token(self, cloud_id: str) -> str:
        """Replace a cloud's token; the old one stops working at once."""
        token = new_token()
        self._exec("UPDATE clouds SET token_hash = ? WHERE id = ?", hash_token(token), cloud_id)
        return token

    def set_mesh_addresses(self, cloud_id: str, v4: str | None, v6: str | None) -> None:
        self._exec(
            "UPDATE clouds SET mesh_address = ?, mesh_address6 = ? WHERE id = ?", v4, v6, cloud_id
        )

    def set_landing(self, cloud_id: str, **values) -> None:
        """The landing page's switches: display_name, show_name, show_logo."""
        for key, value in values.items():
            if key not in ("display_name", "show_name", "show_logo"):
                raise ValueError(key)
            if key != "display_name":
                value = int(bool(value))
            self._exec(f"UPDATE clouds SET {key} = ? WHERE id = ?", value, cloud_id)

    def delete_cloud(self, cloud_id: str) -> None:
        self._exec("DELETE FROM clouds WHERE id = ?", cloud_id)

    # --- logos -----------------------------------------------------------

    def set_logo(self, cloud_id: str, content_type: str, data: bytes) -> None:
        self._exec(
            "INSERT OR REPLACE INTO logos (cloud_id, content_type, data, updated_at) VALUES (?, ?, ?, ?)",
            cloud_id, content_type, data, time.time(),
        )

    def logo(self, cloud_id: str) -> tuple[str, bytes] | None:
        row = self._one("SELECT content_type, data FROM logos WHERE cloud_id = ?", cloud_id)
        return (row["content_type"], bytes(row["data"])) if row else None

    def has_logo(self, cloud_id: str) -> bool:
        return self._one("SELECT 1 FROM logos WHERE cloud_id = ?", cloud_id) is not None

    def delete_logo(self, cloud_id: str) -> None:
        self._exec("DELETE FROM logos WHERE cloud_id = ?", cloud_id)

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

    # --- invite codes --------------------------------------------------

    def add_invite(self, cloud_id: str, code: str, expires_at: float) -> bool:
        self._exec("DELETE FROM invites WHERE expires_at < ?", time.time() - 3600)
        try:
            self._exec(
                "INSERT INTO invites (code_hash, cloud_id, expires_at) VALUES (?, ?, ?)",
                self.code_hash(code), cloud_id, expires_at,
            )
        except sqlite3.IntegrityError:
            return False
        return True

    def claim_invite(self, code: str, cloud_id: str | None = None) -> Cloud | None:
        """Use a code: it works once, until it expires, and (when
        `cloud_id` is given) only for that cloud. The claim is one UPDATE,
        so two devices racing with the same code cannot both win.
        """
        digest = self.code_hash(code)
        now = time.time()
        sql = "UPDATE invites SET used_at = ? WHERE code_hash = ? AND used_at IS NULL AND expires_at > ?"
        args: list = [now, digest, now]
        if cloud_id is not None:
            sql += " AND cloud_id = ?"
            args.append(cloud_id)
        if not self._exec(sql, *args):
            return None
        row = self._one("SELECT cloud_id FROM invites WHERE code_hash = ?", digest)
        return self.cloud(row["cloud_id"]) if row else None

    def release_invite(self, code: str) -> None:
        """Give a claimed code back when what it was for failed on
        Headscale's side, so the person can try again with it.
        """
        self._exec("UPDATE invites SET used_at = NULL WHERE code_hash = ?", self.code_hash(code))

    # --- link codes ----------------------------------------------------

    def add_link(self, code: str, poll: str, expires_at: float) -> bool:
        # Links that ended an hour ago are of no use to anybody.
        self._exec("DELETE FROM links WHERE expires_at < ?", time.time() - 3600)
        try:
            self._exec(
                "INSERT INTO links (code_hash, poll_hash, expires_at) VALUES (?, ?, ?)",
                self.code_hash(code), hash_token(poll), expires_at,
            )
        except sqlite3.IntegrityError:
            return False
        return True

    def link(self, code: str) -> sqlite3.Row | None:
        return self._one("SELECT * FROM links WHERE code_hash = ?", self.code_hash(code))

    def approve_link(self, code: str, name: str, account: str) -> Cloud:
        """Make the cloud a waiting link asked for, owned by `account`, in
        one transaction: the name is taken and the link approved together,
        or neither. Raises LinkGone or NameTaken.
        """
        digest = self.code_hash(code)
        with self._lock:
            db = self._db
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute(
                    "SELECT state, expires_at FROM links WHERE code_hash = ?", (digest,)
                ).fetchone()
                if row is None or row["state"] != "waiting" or row["expires_at"] <= time.time():
                    raise LinkGone(code)
                # The token made here is thrown away: the box gets a fresh
                # one when it collects the link.
                cloud_id, _ = self._insert_cloud(name, account)
                db.execute(
                    "UPDATE links SET state = 'approved', cloud_id = ?, approved_at = ? WHERE code_hash = ?",
                    (cloud_id, time.time(), digest),
                )
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
        return self.cloud(cloud_id)

    def refuse_link(self, code: str) -> bool:
        return bool(self._exec(
            "UPDATE links SET state = 'refused' WHERE code_hash = ? AND state = 'waiting'",
            self.code_hash(code),
        ))

    def collect_link(self, poll: str, lifetime: float) -> str | Cloud:
        """What a polling box gets: "waiting", "gone", or (once) the cloud
        it was approved for. An approved link can be collected for
        `lifetime` seconds after the approval, however late in the code's
        own life that came.
        """
        digest = hash_token(poll)
        now = time.time()
        claimed = self._exec(
            "UPDATE links SET state = 'collected' WHERE poll_hash = ? AND state = 'approved' AND approved_at > ?",
            digest, now - lifetime,
        )
        row = self._one("SELECT * FROM links WHERE poll_hash = ?", digest)
        if row is None or not tokens_equal(row["poll_hash"], digest):
            return "gone"
        if claimed:
            cloud = self.cloud(row["cloud_id"]) if row["cloud_id"] else None
            return cloud or "gone"
        if row["state"] == "waiting" and row["expires_at"] > now:
            return "waiting"
        return "gone"

    # --- uptime --------------------------------------------------------

    def last_seen_state(self, cloud_id: str) -> tuple[float, bool] | None:
        row = self._one(
            "SELECT at, online FROM uptime WHERE cloud_id = ? ORDER BY at DESC, rowid DESC LIMIT 1",
            cloud_id,
        )
        return (row["at"], bool(row["online"])) if row else None

    def record_state(self, cloud_id: str, online: bool, at: float | None = None) -> bool:
        """Note the box's online state; only a change is stored. True if
        it was one.
        """
        last = self.last_seen_state(cloud_id)
        if last is not None and last[1] == online:
            return False
        at = time.time() if at is None else at
        self._exec("INSERT INTO uptime (cloud_id, at, online) VALUES (?, ?, ?)", cloud_id, at, int(online))
        # Forget what is older than the window, but keep the last change
        # before it: that says what the state was when the window opens.
        self._exec(
            """DELETE FROM uptime WHERE cloud_id = ? AND at < ? AND rowid NOT IN (
                 SELECT rowid FROM uptime WHERE cloud_id = ? AND at < ?
                 ORDER BY at DESC, rowid DESC LIMIT 1)""",
            cloud_id, at - UPTIME_KEEP, cloud_id, at - UPTIME_KEEP,
        )
        return True

    def state_changes(self, cloud_id: str) -> list[tuple[float, bool]]:
        rows = self._all(
            "SELECT at, online FROM uptime WHERE cloud_id = ? ORDER BY at, rowid", cloud_id
        )
        return [(r["at"], bool(r["online"])) for r in rows]
