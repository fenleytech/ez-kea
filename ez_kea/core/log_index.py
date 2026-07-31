# SPDX-FileCopyrightText: 2026 Kaleb Fenley
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

"""
ez_kea/core/log_index.py

A SQLite-backed index over the Kea DHCP daemon logs, so that "which device had
10.20.20.31 at 14:05 last Tuesday?" is an indexed lookup rather than a grep.

Why an index at all
-------------------
The Logs page used to read the last 1000 lines of the live log file and
substring-filter them in Python. That is fine for eyeballing recent activity
and useless for the thing operators actually get asked for: an audit or abuse
complaint naming one MAC or one IP and a time window, often weeks back and
therefore several log rotations into the past.

Scanning the files on every search would answer those queries, but the cost is
paid per search and grows with the log — exactly the "don't slow the site down"
failure mode. So instead the parse cost is paid once, incrementally, in the
background, and every search afterwards is an index seek.

Design notes
------------
* **Its own database file.** Kept out of ez-kea.db (users, auth, license) so
  the index can grow, be pruned, be VACUUMed, or be deleted and rebuilt without
  ever putting account data at risk. Deleting this file is always safe; it
  rebuilds from the logs.
* **WAL journaling.** Readers never block on the background writer, which is
  what keeps an in-progress backfill from stalling page loads.
* **Structured terms, not just text.** Every MAC, IPv4/IPv6 address, client-id
  and DUID found on a line is extracted into `log_terms`, so address lookups
  are equality seeks. Addresses are also stored as a fixed 16-byte sort key,
  which makes whole-subnet queries (`10.20.20.0/24`) a range scan.
* **FTS5 for free text**, with plain LIKE as a fallback if the host Python was
  built without FTS5.
* **Incremental ingest with rotation tracking.** Files are identified by a hash
  of their first bytes, not by path, so a rotated `kea-dhcp4.log` is recognised
  as a new file rather than re-read or (worse) resumed at a stale offset.
  Rotated siblings, including gzipped ones, are backfilled once each.

Nothing here is on the request path except `search()` and `index_stats()`.
"""
import glob
import gzip
import hashlib
import ipaddress
import os
import re
import sqlite3
import threading
import time
from datetime import datetime
from functools import lru_cache
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .config_manager import extract_log_file_from_config

# ---------------------------------------------------------------------------
# Tunables. Batch sizes bound how long the background writer holds the SQLite
# write lock during a backfill — small enough that a concurrent search never
# waits noticeably, large enough that a multi-GB backlog still drains.
# ---------------------------------------------------------------------------
MAX_BATCH_BYTES = 4 * 1024 * 1024
MAX_BATCH_LINES = 50_000
FINGERPRINT_BYTES = 4096
SEARCH_COUNT_CAP = 10_000
DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 500

SEVERITIES = ("DEBUG", "INFO", "WARN", "ERROR", "FATAL")


# ---------------------------------------------------------------------------
# Line parsing
# ---------------------------------------------------------------------------

# Kea's default logger layout, e.g.
#   2026-07-30 14:02:11.482 INFO  [kea-dhcp4.leases/1284.140218] DHCP4_LEASE_ALLOC ...
# The bracketed logger/pid/thread field is optional so that lines from a
# differently-configured layout still index (with a timestamp and severity,
# which is what search actually needs).
_LINE_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})[ T](?P<time>\d{2}:\d{2}:\d{2})"
    r"(?:[.,](?P<frac>\d{1,6}))?"
    r"\s+(?P<severity>DEBUG|INFO|WARN|WARNING|ERROR|FATAL)"
    r"(?:\s+\[(?P<logger>[^\]\s]+)\])?"
    r"\s*(?P<rest>.*)$"
)

# Kea message identifiers are SHOUTY_SNAKE_CASE, e.g. DHCP4_LEASE_ALLOC.
_MSG_ID_RE = re.compile(r"^(?P<msg>[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)\b")

# `cid=[01:18:64:72:5d:0e:91]` / `duid=[00:01:00:01:2f:...]`. Pulled out and
# blanked before the generic address scan below, because an 8-octet client-id
# is textually indistinguishable from a valid IPv6 address and would otherwise
# be indexed as one.
_CID_RE = re.compile(r"\bcid=\[([0-9A-Fa-f:]+)\]")
_DUID_RE = re.compile(r"\bduid=\[([0-9A-Fa-f:]+)\]")

# A colon-separated hex run. The lookarounds stop us slicing a 6-octet "MAC"
# out of the middle of a longer identifier.
_COLON_RUN_RE = re.compile(
    r"(?<![0-9A-Za-z:])((?:[0-9A-Fa-f]{0,4}:){1,7}[0-9A-Fa-f]{0,4})(?![0-9A-Za-z:])"
)
_MAC_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_IPV4_RE = re.compile(r"(?<![0-9A-Za-z.:])((?:\d{1,3}\.){3}\d{1,3})(?![0-9A-Za-z.])")


@lru_cache(maxsize=8192)
def _epoch_for(date_s: str, time_s: str) -> Optional[float]:
    """Whole-second epoch for a Kea timestamp, cached.

    Kea writes local time with no zone offset, so that is how it is read back.
    Consecutive log lines overwhelmingly share the same second, which is why
    the cache earns its keep during a large backfill.
    """
    try:
        return datetime.strptime(f"{date_s} {time_s}", "%Y-%m-%d %H:%M:%S").timestamp()
    except ValueError:
        return None


def parse_line(raw: str) -> Dict[str, Any]:
    """Split one Kea log line into indexable fields.

    Unparseable lines are not discarded — they keep their raw text and stay
    findable by free-text search, just without a timestamp or severity. Losing
    a line entirely would be the wrong trade for an audit trail.
    """
    match = _LINE_RE.match(raw)
    if not match:
        return {"ts": None, "severity": None, "logger": None, "msg_id": None, "raw": raw}

    frac = match.group("frac")
    ts = _epoch_for(match.group("date"), match.group("time"))
    if ts is not None and frac:
        ts += int(frac.ljust(6, "0")) / 1_000_000.0

    logger = match.group("logger") or ""
    # "kea-dhcp4.leases/1284.140218" -> "kea-dhcp4.leases"
    logger = logger.split("/", 1)[0] or None

    severity = match.group("severity")
    if severity == "WARNING":
        severity = "WARN"

    rest = match.group("rest") or ""
    msg_match = _MSG_ID_RE.match(rest)

    return {
        "ts": ts,
        "severity": severity,
        "logger": logger,
        "msg_id": msg_match.group("msg") if msg_match else None,
        "raw": raw,
    }


def _ip_sort_key(addr: "ipaddress._BaseAddress") -> bytes:
    """Fixed-width 16-byte ordering key for an IPv4 or IPv6 address.

    IPv4 is stored in its IPv4-mapped IPv6 form so that every key is the same
    length. SQLite compares BLOBs with memcmp and then by length, so mixing
    4-byte and 16-byte keys in one index would interleave the two families
    nonsensically and break range (subnet) queries.
    """
    if addr.version == 4:
        return b"\x00" * 10 + b"\xff\xff" + addr.packed
    return addr.packed


def _macs_from_duid(octets: Sequence[str]) -> List[str]:
    """Link-layer address embedded in a DUID-LLT (type 1) or DUID-LL (type 3).

    DUID-LLT is 2 bytes type + 2 bytes hardware type + 4 bytes time, then the
    link-layer address; DUID-LL drops the time field. Anything else (DUID-EN,
    or a non-Ethernet hardware type) carries no MAC and yields nothing.
    """
    if len(octets) >= 14 and octets[0:2] == ["00", "01"] and octets[2:4] == ["00", "01"]:
        return [":".join(octets[8:14])]
    if len(octets) >= 10 and octets[0:2] == ["00", "03"] and octets[2:4] == ["00", "01"]:
        return [":".join(octets[4:10])]
    return []


def extract_terms(raw: str) -> List[Tuple[str, str, Optional[bytes]]]:
    """Every searchable identifier on a line, as (kind, value, sort_key).

    Kinds are 'mac', 'ip', 'clientid' and 'duid'. Values are normalised — MACs
    lowercased, addresses run through `ipaddress` so that `2001:0db8::0001`
    and `2001:db8::1` are the same term — so a search matches regardless of how
    the operator typed it or how Kea happened to print it.
    """
    terms: Dict[Tuple[str, str], Optional[bytes]] = {}
    remainder = raw

    def add(kind: str, value: str, sort_key: Optional[bytes] = None) -> None:
        terms[(kind, value)] = sort_key

    # --- Client-ids and DUIDs, removed from the text before the generic scan.
    for match in _CID_RE.finditer(raw):
        value = match.group(1).lower()
        add("clientid", value)
        octets = value.split(":")
        # RFC 2132 client-id: one hardware-type byte followed by the MAC.
        if len(octets) == 7 and octets[0] == "01":
            add("mac", ":".join(octets[1:]))

    for match in _DUID_RE.finditer(raw):
        value = match.group(1).lower()
        add("duid", value)
        for mac in _macs_from_duid(value.split(":")):
            add("mac", mac)

    remainder = _DUID_RE.sub(" ", _CID_RE.sub(" ", remainder))

    # --- Colon runs: MACs and IPv6 addresses.
    for match in _COLON_RUN_RE.finditer(remainder):
        token = match.group(1)
        if _MAC_RE.match(token):
            add("mac", token.lower())
            continue
        try:
            addr = ipaddress.ip_address(token)
        except ValueError:
            continue
        add("ip", str(addr), _ip_sort_key(addr))

    # --- IPv4 addresses.
    for match in _IPV4_RE.finditer(remainder):
        try:
            addr = ipaddress.ip_address(match.group(1))
        except ValueError:
            continue
        add("ip", str(addr), _ip_sort_key(addr))

    return [(kind, value, sort_key) for (kind, value), sort_key in terms.items()]


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS log_entries (
    id       INTEGER PRIMARY KEY,
    source_id INTEGER NOT NULL,
    version  TEXT NOT NULL,
    ts       REAL,
    severity TEXT,
    logger   TEXT,
    msg_id   TEXT,
    raw      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_entries_ts       ON log_entries(ts DESC);
CREATE INDEX IF NOT EXISTS idx_entries_ver_ts   ON log_entries(version, ts DESC);
CREATE INDEX IF NOT EXISTS idx_entries_sev_ts   ON log_entries(severity, ts DESC);
CREATE INDEX IF NOT EXISTS idx_entries_msg_ts   ON log_entries(msg_id, ts DESC);

CREATE TABLE IF NOT EXISTS log_terms (
    kind     TEXT NOT NULL,
    value    TEXT NOT NULL,
    entry_id INTEGER NOT NULL,
    sort_key BLOB,
    PRIMARY KEY (kind, value, entry_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_terms_sort  ON log_terms(kind, sort_key, entry_id);
CREATE INDEX IF NOT EXISTS idx_terms_entry ON log_terms(entry_id);

CREATE TABLE IF NOT EXISTS log_sources (
    id         INTEGER PRIMARY KEY,
    path       TEXT NOT NULL,
    version    TEXT NOT NULL,
    dev        INTEGER,
    ino        INTEGER,
    head_hash  TEXT NOT NULL,
    offset     INTEGER NOT NULL DEFAULT 0,
    complete   INTEGER NOT NULL DEFAULT 0,
    first_seen REAL,
    last_read  REAL
);
CREATE INDEX IF NOT EXISTS idx_sources_path ON log_sources(path, id DESC);

CREATE TABLE IF NOT EXISTS log_index_meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


def connect(db_path: str) -> sqlite3.Connection:
    """Open (creating if needed) the log-index database."""
    parent = os.path.dirname(os.path.abspath(db_path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30.0)
    conn.row_factory = sqlite3.Row
    # WAL is the reason a backfill in the background thread doesn't make the
    # Logs page wait; busy_timeout covers the brief exclusive moments.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=30000")
    init_db(conn)
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    """Create the schema if absent, including the FTS index where supported."""
    conn.executescript(_SCHEMA)
    if not _has_fts(conn):
        try:
            conn.executescript(
                # '.', ':' and '-' are token characters so an address stays one
                # token and matches as written. '_' deliberately is NOT, so that
                # DHCP4_PACKET_PROCESS_FAIL splits into four tokens and a search
                # for a fragment of a Kea message id (PROCESS_FAIL) still finds
                # it — quoting in _fts_query turns that into an adjacent-phrase
                # match rather than a loose OR.
                "CREATE VIRTUAL TABLE log_fts USING fts5("
                "  raw, content='log_entries', content_rowid='id',"
                "  tokenize=\"unicode61 tokenchars '.:-'\""
                ");"
            )
        except sqlite3.OperationalError:
            # Python built without FTS5. Free-text search falls back to LIKE;
            # the address/time filters that matter most are unaffected.
            pass
    conn.commit()


def _has_fts(conn: sqlite3.Connection) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='log_fts'"
    ).fetchone()
    return row is not None


# ---------------------------------------------------------------------------
# Ingest
# ---------------------------------------------------------------------------

def _head_hash(path: str, length: int) -> str:
    """Hash of the first `length` bytes of a file.

    Used to confirm a file is still the one we were reading. The length is
    always the number of bytes already consumed (capped), never a fixed window
    of the current file — hashing a fixed window would change every time a
    small file grew, and every append to a young log would look like a rotation
    and re-index the whole thing.
    """
    length = min(length, FINGERPRINT_BYTES)
    if length <= 0:
        return "empty"
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read(length)).hexdigest()


def _is_gzip(path: str) -> bool:
    return path.endswith(".gz")


def rotated_siblings(path: str) -> List[str]:
    """Rotated copies of `path`, oldest first.

    Covers both logrotate conventions — numeric (`.log.1`, `.log.2.gz`) and
    dated (`.log-20260729.gz`). Confined to the same directory as the live log,
    which has already passed `validate_log_file_path`, so this never widens
    what EZ-Kea will read.
    """
    candidates = set(glob.glob(path + ".*")) | set(glob.glob(path + "-*"))
    candidates.discard(path)
    existing = [p for p in candidates if os.path.isfile(p)]
    existing.sort(key=lambda p: os.path.getmtime(p))
    return existing


def _new_source(conn: sqlite3.Connection, path: str, version: str, stat: os.stat_result) -> int:
    """Start tracking `path` from byte zero."""
    cursor = conn.execute(
        "INSERT INTO log_sources (path, version, dev, ino, head_hash, offset, complete, first_seen) "
        "VALUES (?, ?, ?, ?, 'empty', 0, 0, ?)",
        (path, version, stat.st_dev, stat.st_ino, time.time()),
    )
    return int(cursor.lastrowid)


def _resume_point(
    conn: sqlite3.Connection, path: str, version: str, stat: os.stat_result
) -> Tuple[int, int]:
    """Which source row to continue, and at what byte offset.

    Deciding "same file, more data" vs "different file at the same path" is the
    whole of rotation handling, and there are three ways a file stops being the
    one we were reading:

      * the inode changed — logrotate's default create-a-new-file mode;
      * it is shorter than what we already consumed — truncated in place;
      * the bytes we already consumed no longer hash the same — rewritten in
        place at the same size or larger, which `copytruncate` and any
        regenerate-the-file tooling both produce.

    Any of those starts a fresh source row at offset 0. Previously indexed
    lines are kept either way: a rotated-away file's history is exactly what a
    compliance search needs.
    """
    row = conn.execute(
        "SELECT * FROM log_sources WHERE path = ? ORDER BY id DESC LIMIT 1", (path,)
    ).fetchone()
    if row is None:
        return _new_source(conn, path, version, stat), 0

    if row["dev"] != stat.st_dev or row["ino"] != stat.st_ino:
        return _new_source(conn, path, version, stat), 0
    if stat.st_size < row["offset"]:
        return _new_source(conn, path, version, stat), 0
    try:
        if _head_hash(path, row["offset"]) != row["head_hash"]:
            return _new_source(conn, path, version, stat), 0
    except OSError:
        return _new_source(conn, path, version, stat), 0

    return int(row["id"]), int(row["offset"])


def _insert_lines(
    conn: sqlite3.Connection, source_id: int, version: str, lines: Iterable[str], has_fts: bool
) -> int:
    """Index a batch of raw lines. Caller owns the transaction."""
    count = 0
    for raw in lines:
        raw = raw.rstrip("\n").rstrip("\r")
        if not raw.strip():
            continue
        parsed = parse_line(raw)
        cursor = conn.execute(
            "INSERT INTO log_entries (source_id, version, ts, severity, logger, msg_id, raw) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (source_id, version, parsed["ts"], parsed["severity"],
             parsed["logger"], parsed["msg_id"], raw),
        )
        entry_id = cursor.lastrowid
        terms = extract_terms(raw)
        if terms:
            conn.executemany(
                "INSERT OR IGNORE INTO log_terms (kind, value, entry_id, sort_key) "
                "VALUES (?, ?, ?, ?)",
                [(kind, value, entry_id, sort_key) for kind, value, sort_key in terms],
            )
        if has_fts:
            conn.execute("INSERT INTO log_fts (rowid, raw) VALUES (?, ?)", (entry_id, raw))
        count += 1
    return count


def ingest_file(conn: sqlite3.Connection, path: str, version: str) -> int:
    """Index whatever is new in `path`. Returns the number of lines indexed.

    The read, the inserts and the offset advance all happen inside one
    IMMEDIATE transaction, and the offset is re-read after the write lock is
    held. That is what makes concurrent ingesters safe without any extra
    locking: a second worker blocks, then finds the offset already advanced and
    does nothing.
    """
    if not os.path.isfile(path):
        return 0
    try:
        stat = os.stat(path)
    except OSError:
        return 0

    gz = _is_gzip(path)
    has_fts = _has_fts(conn)

    conn.execute("BEGIN IMMEDIATE")
    try:
        if gz:
            # Rotated archives are immutable, so they are read once, in full,
            # and never revisited. Byte offsets into the compressed stream
            # would not be resumable anyway.
            done = conn.execute(
                "SELECT 1 FROM log_sources WHERE path = ? AND dev = ? AND ino = ? AND complete = 1",
                (path, stat.st_dev, stat.st_ino),
            ).fetchone()
            if done:
                conn.execute("ROLLBACK")
                return 0
            source_id = _new_source(conn, path, version, stat)
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
                indexed = _insert_lines(conn, source_id, version, handle, has_fts)
            conn.execute(
                "UPDATE log_sources SET complete = 1, last_read = ? WHERE id = ?",
                (time.time(), source_id),
            )
            conn.execute("COMMIT")
            return indexed

        source_id, start_offset = _resume_point(conn, path, version, stat)

        size = stat.st_size
        if size <= start_offset:
            conn.execute("ROLLBACK")
            return 0

        with open(path, "rb") as handle:
            handle.seek(start_offset)
            chunk = handle.read(MAX_BATCH_BYTES)

        # A trailing fragment means Kea is mid-write. Hold it back rather than
        # index half a line, and leave the offset short so it is picked up
        # whole on the next pass.
        consumed = len(chunk)
        if chunk and not chunk.endswith(b"\n"):
            cut = chunk.rfind(b"\n")
            if cut == -1:
                conn.execute("ROLLBACK")
                return 0
            chunk = chunk[: cut + 1]
            consumed = cut + 1

        # Cap the batch by cutting the raw bytes at the Nth newline. Trimming
        # after decoding and re-encoding would not give back a byte count we
        # could trust as an offset (errors="replace" is lossy, and CRLF lines
        # are not one byte longer than LF ones).
        if chunk.count(b"\n") > MAX_BATCH_LINES:
            cut = -1
            for _ in range(MAX_BATCH_LINES):
                cut = chunk.index(b"\n", cut + 1)
            chunk = chunk[: cut + 1]
            consumed = cut + 1

        lines = chunk.decode("utf-8", errors="replace").splitlines()
        indexed = _insert_lines(conn, source_id, version, lines, has_fts)

        new_offset = start_offset + consumed
        conn.execute(
            "UPDATE log_sources SET offset = ?, head_hash = ?, last_read = ? WHERE id = ?",
            (new_offset, _head_hash(path, new_offset), time.time(), source_id),
        )
        conn.execute("COMMIT")
        return indexed
    except Exception:
        conn.execute("ROLLBACK")
        raise


def ingest_all(
    conn: sqlite3.Connection,
    sources: Sequence[Tuple[str, str]],
    include_rotated: bool = True,
) -> int:
    """Bring the index up to date for every (path, version) source."""
    total = 0
    for path, version in sources:
        if not path:
            continue
        if include_rotated:
            for sibling in rotated_siblings(path):
                try:
                    total += ingest_file(conn, sibling, version)
                except (OSError, sqlite3.Error):
                    # One unreadable archive must not stop the live log from
                    # being indexed.
                    continue
        try:
            total += ingest_file(conn, path, version)
        except (OSError, sqlite3.Error):
            continue
    _set_meta(conn, "last_ingest", str(time.time()))
    return total


def _set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO log_index_meta (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )
    conn.commit()


def get_meta(conn: sqlite3.Connection, key: str) -> Optional[str]:
    row = conn.execute("SELECT value FROM log_index_meta WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def prune(conn: sqlite3.Connection, retention_days: int, batch: int = 5000) -> int:
    """Drop entries older than the retention window. Returns rows removed.

    Retention is the only bound on index size, so it is deliberately generous
    by default — the point of the feature is answering questions about months
    ago. A retention_days of 0 or less disables pruning entirely.
    """
    if retention_days <= 0:
        return 0
    cutoff = time.time() - retention_days * 86400
    removed = 0
    has_fts = _has_fts(conn)
    while True:
        rows = conn.execute(
            "SELECT id, raw FROM log_entries WHERE ts IS NOT NULL AND ts < ? LIMIT ?",
            (cutoff, batch),
        ).fetchall()
        if not rows:
            break
        ids = [(row["id"],) for row in rows]
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.executemany("DELETE FROM log_terms WHERE entry_id = ?", ids)
            if has_fts:
                conn.executemany(
                    "INSERT INTO log_fts (log_fts, rowid, raw) VALUES ('delete', ?, ?)",
                    [(row["id"], row["raw"]) for row in rows],
                )
            conn.executemany("DELETE FROM log_entries WHERE id = ?", ids)
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        removed += len(rows)
    if removed:
        # Sources whose every line has aged out would otherwise keep the index
        # from ever re-reading a path that got rotated back into place.
        conn.execute(
            "DELETE FROM log_sources WHERE complete = 1 AND id NOT IN "
            "(SELECT DISTINCT source_id FROM log_entries)"
        )
        conn.commit()
    return removed


def rebuild(db_path: str) -> None:
    """Discard the index entirely so the next ingest re-reads from scratch."""
    conn = connect(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("DELETE FROM log_terms")
        if _has_fts(conn):
            conn.execute("DELETE FROM log_fts")
        conn.execute("DELETE FROM log_entries")
        conn.execute("DELETE FROM log_sources")
        conn.execute("COMMIT")
        conn.execute("VACUUM")
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------

_ADDRESSISH = set(".:-")


def _fts_query(text: str) -> Optional[str]:
    """Turn user input into an FTS5 MATCH expression, safely.

    Every token is quoted (and internal quotes doubled) so that FTS operators a
    user happens to type — `OR`, `NEAR`, `*`, `-` — are matched as text rather
    than reinterpreted as query syntax. Address-shaped tokens get a prefix
    match so that typing `10.20.20` finds `10.20.20.31`.
    """
    tokens = []
    for token in text.split():
        prefix = token.endswith("*")
        token = token.rstrip("*")
        if not any(char.isalnum() for char in token):
            # Pure punctuation tokenizes to nothing; an empty FTS phrase is a
            # syntax error, so drop it.
            continue
        quoted = '"' + token.replace('"', '""') + '"'
        if prefix or any(char in _ADDRESSISH for char in token):
            quoted += "*"
        tokens.append(quoted)
    return " AND ".join(tokens) if tokens else None


# The MAC spellings worth accepting, matched by shape rather than by stripping
# punctuation. Shape matters: '2001:db8:20::a3f' also contains exactly twelve
# hex digits, and treating that as a MAC would silently turn an IPv6 lookup
# into a lookup for a device that doesn't exist.
_MAC_INPUT_RES = (
    re.compile(r"^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$"),      # aa:bb:cc:dd:ee:ff
    re.compile(r"^[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5}$"),      # AA-BB-CC-DD-EE-FF
    re.compile(r"^[0-9A-Fa-f]{4}(?:\.[0-9A-Fa-f]{4}){2}$"),     # aabb.ccdd.eeff (Cisco)
    re.compile(r"^[0-9A-Fa-f]{12}$"),                           # AABBCCDDEEFF
)


def normalize_mac(value: str) -> Optional[str]:
    """Accept the MAC spellings people actually paste, return the stored form.

    `AA-BB-CC-DD-EE-FF`, `aabb.ccdd.eeff`, `AABBCCDDEEFF` and
    `aa:bb:cc:dd:ee:ff` are the same device; an audit request will use whichever
    one the complainant's tooling emitted.
    """
    value = (value or "").strip()
    if not any(pattern.match(value) for pattern in _MAC_INPUT_RES):
        return None
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", value).lower()
    return ":".join(cleaned[i:i + 2] for i in range(0, 12, 2))


def normalize_mac_prefix(value: str) -> Optional[str]:
    """Stored-form prefix for a partial MAC (e.g. an OUI vendor lookup)."""
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", value or "").lower()
    if not cleaned or len(cleaned) > 12:
        return None
    pairs = [cleaned[i:i + 2] for i in range(0, len(cleaned), 2)]
    return ":".join(pairs)


def classify_term(value: str) -> Tuple[str, str]:
    """Guess what a single search box entry means: ('mac'|'ip'|'cidr'|'text', v).

    The single box is what makes the page usable — an operator pastes whatever
    the abuse report gave them and gets an indexed lookup without first
    deciding which field it belongs in. The explicit filters remain available
    when the guess needs overriding.
    """
    value = (value or "").strip()
    if not value:
        return ("text", "")

    # Addresses are tested first: an IPv6 address can contain exactly twelve
    # hex digits and would otherwise be claimed by the MAC branch.
    if "/" in value:
        try:
            net = ipaddress.ip_network(value, strict=False)
            return ("cidr", str(net))
        except ValueError:
            pass

    try:
        addr = ipaddress.ip_address(value)
        return ("ip", str(addr))
    except ValueError:
        pass

    mac = normalize_mac(value)
    if mac:
        return ("mac", mac)

    return ("text", value)


def _term_clause(alias: str) -> str:
    """One join onto log_terms. Multiple address filters each get their own
    aliased join, which is how "this MAC *and* this subnet" narrows rather
    than unions."""
    return f"JOIN log_terms {alias} ON {alias}.entry_id = e.id"


def search(
    conn: sqlite3.Connection,
    *,
    q: Optional[str] = None,
    mac: Optional[str] = None,
    ip: Optional[str] = None,
    cidr: Optional[str] = None,
    client_id: Optional[str] = None,
    duid: Optional[str] = None,
    msg_id: Optional[str] = None,
    start: Optional[float] = None,
    end: Optional[float] = None,
    severity: Optional[str] = None,
    version: Optional[str] = None,
    limit: int = DEFAULT_PAGE_SIZE,
    offset: int = 0,
    count_cap: int = SEARCH_COUNT_CAP,
) -> Dict[str, Any]:
    """Run an indexed search. Returns rows plus a bounded total.

    The total is counted only up to `count_cap` — an exact COUNT over a
    multi-million-row match would cost more than the page of results itself,
    and "10,000+" tells the operator to narrow the window just as well as an
    exact number would.
    """
    limit = max(1, min(int(limit or DEFAULT_PAGE_SIZE), MAX_PAGE_SIZE))
    offset = max(0, int(offset or 0))

    joins: List[str] = []
    where: List[str] = []
    params: List[Any] = []

    def add_term_join(kind: str, value: str) -> None:
        alias = f"t{len(joins)}"
        joins.append(_term_clause(alias))
        where.append(f"{alias}.kind = ? AND {alias}.value = ?")
        params.extend([kind, value])

    if mac:
        normalized = normalize_mac(mac)
        if normalized:
            add_term_join("mac", normalized)
        else:
            prefix = normalize_mac_prefix(mac)
            if prefix is None:
                # Uninterpretable as any MAC — return nothing rather than
                # silently ignoring the filter and over-reporting matches.
                return {"rows": [], "total": 0, "capped": False, "limit": limit, "offset": offset}
            alias = f"t{len(joins)}"
            joins.append(_term_clause(alias))
            where.append(f"{alias}.kind = ? AND {alias}.value LIKE ? ESCAPE '\\'")
            params.extend(["mac", _like_escape(prefix) + "%"])

    if ip:
        try:
            addr = ipaddress.ip_address(ip.strip())
        except ValueError:
            return {"rows": [], "total": 0, "capped": False, "limit": limit, "offset": offset}
        add_term_join("ip", str(addr))

    if cidr:
        try:
            net = ipaddress.ip_network(cidr.strip(), strict=False)
        except ValueError:
            return {"rows": [], "total": 0, "capped": False, "limit": limit, "offset": offset}
        alias = f"t{len(joins)}"
        joins.append(_term_clause(alias))
        where.append(f"{alias}.kind = ? AND {alias}.sort_key BETWEEN ? AND ?")
        params.extend([
            "ip",
            _ip_sort_key(net.network_address),
            _ip_sort_key(net.broadcast_address),
        ])

    if client_id:
        add_term_join("clientid", client_id.strip().lower())
    if duid:
        add_term_join("duid", duid.strip().lower())

    if msg_id:
        where.append("e.msg_id = ?")
        params.append(msg_id.strip().upper())
    if severity:
        where.append("e.severity = ?")
        params.append(severity.strip().upper())
    if version in ("4", "6"):
        where.append("e.version = ?")
        params.append(version)
    if start is not None:
        where.append("e.ts >= ?")
        params.append(float(start))
    if end is not None:
        where.append("e.ts <= ?")
        params.append(float(end))

    fts_expr = _fts_query(q) if q else None
    use_like = False
    if q and fts_expr and _has_fts(conn):
        where.append("e.id IN (SELECT rowid FROM log_fts WHERE log_fts MATCH ?)")
        params.append(fts_expr)
    elif q:
        use_like = True
        where.append("e.raw LIKE ? ESCAPE '\\'")
        params.append("%" + _like_escape(q.strip()) + "%")

    join_sql = " ".join(joins)
    where_sql = (" WHERE " + " AND ".join(f"({clause})" for clause in where)) if where else ""

    select_sql = (
        "SELECT e.id, e.ts, e.severity, e.logger, e.msg_id, e.version, e.raw "
        f"FROM log_entries e {join_sql}{where_sql} "
        "ORDER BY e.ts DESC, e.id DESC LIMIT ? OFFSET ?"
    )
    count_sql = (
        "SELECT COUNT(*) AS n FROM (SELECT e.id "
        f"FROM log_entries e {join_sql}{where_sql} LIMIT ?)"
    )

    try:
        rows = conn.execute(select_sql, (*params, limit, offset)).fetchall()
        total_row = conn.execute(count_sql, (*params, count_cap + 1)).fetchone()
    except sqlite3.OperationalError:
        if not q or use_like:
            raise
        # An FTS expression SQLite rejected despite the quoting above. Retry
        # with a plain substring match rather than showing the operator an
        # error page. The FTS clause is always the last one appended, so
        # dropping the final clause/param pair leaves the other filters intact.
        return _search_like_fallback(
            conn, q, joins, where[:-1], params[:-1], limit, offset, count_cap
        )

    total = int(total_row["n"]) if total_row else 0
    capped = total > count_cap
    if capped:
        total = count_cap

    return {
        "rows": [dict(row) for row in rows],
        "total": total,
        "capped": capped,
        "limit": limit,
        "offset": offset,
    }


def _search_like_fallback(
    conn: sqlite3.Connection,
    q: str,
    joins: List[str],
    where: List[str],
    params: List[Any],
    limit: int,
    offset: int,
    count_cap: int,
) -> Dict[str, Any]:
    """Re-run a search with LIKE after an FTS MATCH was rejected."""
    where = where + ["e.raw LIKE ? ESCAPE '\\'"]
    params = params + ["%" + _like_escape(q.strip()) + "%"]
    join_sql = " ".join(joins)
    where_sql = " WHERE " + " AND ".join(f"({clause})" for clause in where)
    rows = conn.execute(
        "SELECT e.id, e.ts, e.severity, e.logger, e.msg_id, e.version, e.raw "
        f"FROM log_entries e {join_sql}{where_sql} ORDER BY e.ts DESC, e.id DESC LIMIT ? OFFSET ?",
        (*params, limit, offset),
    ).fetchall()
    total_row = conn.execute(
        f"SELECT COUNT(*) AS n FROM (SELECT e.id FROM log_entries e {join_sql}{where_sql} LIMIT ?)",
        (*params, count_cap + 1),
    ).fetchone()
    total = int(total_row["n"]) if total_row else 0
    capped = total > count_cap
    return {
        "rows": [dict(row) for row in rows],
        "total": count_cap if capped else total,
        "capped": capped,
        "limit": limit,
        "offset": offset,
    }


def iter_search(conn: sqlite3.Connection, *, page_size: int = MAX_PAGE_SIZE, **filters: Any):
    """Yield every match, page by page — the CSV export's data source.

    Streaming in pages keeps a 500,000-row export from being materialised in
    memory before the first byte reaches the client.
    """
    filters.pop("limit", None)
    offset = int(filters.pop("offset", 0) or 0)
    while True:
        result = search(conn, limit=page_size, offset=offset, **filters)
        rows = result["rows"]
        if not rows:
            return
        for row in rows:
            yield row
        if len(rows) < page_size:
            return
        offset += page_size


def _like_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def index_stats(conn: sqlite3.Connection) -> Dict[str, Any]:
    """Coverage summary for the Logs page, so operators can see what the index
    can actually answer for before they trust an empty result."""
    row = conn.execute(
        "SELECT COUNT(*) AS entries, MIN(ts) AS oldest, MAX(ts) AS newest FROM log_entries"
    ).fetchone()
    sources = conn.execute("SELECT COUNT(*) AS n FROM log_sources").fetchone()
    last_ingest = get_meta(conn, "last_ingest")
    return {
        "entries": int(row["entries"] or 0),
        "oldest": row["oldest"],
        "newest": row["newest"],
        "sources": int(sources["n"] or 0),
        "last_ingest": float(last_ingest) if last_ingest else None,
        "fts": _has_fts(conn),
    }


# ---------------------------------------------------------------------------
# Wiring into the app
# ---------------------------------------------------------------------------

def resolve_log_sources(config: Any) -> List[Tuple[str, str]]:
    """The (path, version) log files this deployment should index.

    Mirrors routes/system.py's `_log_file_for_viewing`: trust our own configured
    path when a distinct in-container path is set (the host process cannot open
    a container-namespace path), otherwise trust what Kea's own config declares.
    """
    sources: List[Tuple[str, str]] = []
    for version, config_key, log_key, in_container_key, root_key, logger_name in (
        ("4", "DHCP_CONFIG_FILE", "DHCP_LOG_FILE", "DHCP_LOG_FILE_IN_CONTAINER", "Dhcp4", "kea-dhcp4"),
        ("6", "DHCP6_CONFIG_FILE", "DHCP6_LOG_FILE", "DHCP6_LOG_FILE_IN_CONTAINER", "Dhcp6", "kea-dhcp6"),
    ):
        log_file = config.get(log_key, "") or ""
        if (config.get(in_container_key, "") or "").strip():
            path = log_file
        else:
            path = extract_log_file_from_config(
                config.get(config_key, "") or "", log_file,
                dhcp_key=root_key, logger_name=logger_name,
            )
        if path:
            sources.append((path, version))
    return sources


_indexer_threads: "dict[int, threading.Thread]" = {}
_indexer_lock = threading.Lock()


def run_once(config: Any) -> int:
    """One ingest + prune pass. Used by the background thread, the manual
    reindex action, and the tests."""
    conn = connect(config["LOG_INDEX_DB"])
    try:
        indexed = ingest_all(conn, resolve_log_sources(config))
        prune(conn, int(config.get("LOG_INDEX_RETENTION_DAYS", 365)))
        return indexed
    finally:
        conn.close()


def start_background_indexer(app: Any) -> None:
    """Start the daemon thread that keeps the index current.

    Ingest deliberately never happens on a request. A visitor hitting /logs
    while a month of rotated archives is still backfilling gets whatever is
    indexed so far, immediately, instead of waiting for the backfill.
    """
    if not app.config.get("LOG_INDEX_ENABLED", True):
        return
    if app.config.get("TESTING"):
        # Tests build many short-lived apps; each one starting a thread that
        # writes to a database on a timer makes for slow, order-dependent runs.
        # Index behaviour is tested directly against log_index instead.
        return
    with _indexer_lock:
        existing = _indexer_threads.get(id(app))
        if existing is not None and existing.is_alive():
            return

        interval = max(5, int(app.config.get("LOG_INDEX_INTERVAL", 60)))
        # Snapshot the settings the thread needs. It must not touch `app`
        # afterwards: config can be reassigned by a settings save mid-pass, and
        # a plain dict copy per pass keeps the thread off any shared state.
        def loop() -> None:
            while True:
                try:
                    run_once(dict(app.config))
                except Exception:  # pragma: no cover - defensive
                    app.logger.exception("log index pass failed")
                time.sleep(interval)

        thread = threading.Thread(target=loop, name="ez-kea-log-indexer", daemon=True)
        _indexer_threads[id(app)] = thread
        thread.start()
