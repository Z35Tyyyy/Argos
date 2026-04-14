"""
argos.database
~~~~~~~~~~~~~~
SQLite baseline storage and tamper-evident audit ledger.

Tables
------
baselines     – snapshot metadata (name, directory, algo, timestamp)
files         – per-file hash + OS metadata for a given baseline
fingerprints  – behavioral fingerprint data per file per baseline
ledger        – append-only chained audit log
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ──────────────────────────── Dataclasses ────────────────────────────

@dataclass
class ScanRecord:
    """One file's hash + metadata inside a baseline snapshot."""
    path: str
    hash_value: str
    size: int
    permissions: str          # octal, e.g. "0o755"
    owner: str
    mtime: float
    # Fingerprint fields (populated in Step 3)
    entropy: Optional[float] = None
    function_count: Optional[int] = None
    class_count: Optional[int] = None
    import_list: Optional[str] = None        # JSON array string
    has_exec_calls: Optional[bool] = None
    exec_call_list: Optional[str] = None     # JSON array string
    printable_string_count: Optional[int] = None
    is_executable: Optional[bool] = None
    file_type: Optional[str] = None


@dataclass
class ChangeRecord:
    """Describes a single detected change between baseline and current scan."""
    path: str
    change_type: str          # MODIFIED | ADDED | DELETED | META_ONLY
    old_hash: Optional[str] = None
    new_hash: Optional[str] = None
    old_size: Optional[int] = None
    new_size: Optional[int] = None
    old_permissions: Optional[str] = None
    new_permissions: Optional[str] = None
    old_mtime: Optional[float] = None
    new_mtime: Optional[float] = None
    time_delta_seconds: Optional[float] = None
    # Fingerprint deltas
    entropy_before: Optional[float] = None
    entropy_after: Optional[float] = None
    entropy_delta: Optional[float] = None
    new_exec_calls: Optional[List[str]] = field(default_factory=list)
    new_imports: Optional[List[str]] = field(default_factory=list)
    # Classification (populated in Step 5)
    severity: Optional[str] = None
    severity_reasons: List[str] = field(default_factory=list)
    # Semantic diff (populated in Step 6)
    semantic_diff: Optional[Dict[str, Any]] = None
    # AI explanation (populated in Step 7)
    ai_explanation: Optional[str] = None
    # File type
    file_type: Optional[str] = None
    old_owner: Optional[str] = None
    new_owner: Optional[str] = None


@dataclass
class LedgerEntry:
    """One row in the tamper-evident audit ledger."""
    id: Optional[int]
    timestamp: str
    action: str               # init | check | update
    directory: str
    files_scanned: int
    changes_summary_json: str
    prev_record_hash: str
    record_hash: str


# ──────────────────────────── Helpers ────────────────────────────────

def _default_db_path() -> Path:
    """Return the default path for the Argos database file."""
    env = os.environ.get("ARGOS_DB")
    if env:
        # Resolve to sanitize input and prevent path traversal
        return Path(env).expanduser().resolve()
    return Path.home() / ".argos" / "argos.db"


def _compute_record_hash(
    timestamp: str,
    action: str,
    changes_summary_json: str,
    prev_record_hash: str,
) -> str:
    """SHA-256( timestamp + action + changes_summary_json + prev_record_hash )"""
    payload = f"{timestamp}{action}{changes_summary_json}{prev_record_hash}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ──────────────────────────── DatabaseManager ────────────────────────

class DatabaseManager:
    """Context-manager wrapper around the Argos SQLite database."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path:
            self.db_path = Path(db_path).expanduser().resolve()
        else:
            self.db_path = _default_db_path()

        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: Optional[sqlite3.Connection] = None

    # ── context manager ──────────────────────────────────────────────

    def __enter__(self) -> "DatabaseManager":
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._create_tables()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("DatabaseManager must be used inside a `with` block.")
        return self._conn

    # ── schema ───────────────────────────────────────────────────────

    def _create_tables(self) -> None:
        cur = self.conn.cursor()
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS baselines (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT    NOT NULL,
                directory   TEXT    NOT NULL,
                algorithm   TEXT    NOT NULL DEFAULT 'sha256',
                created_at  TEXT    NOT NULL,
                UNIQUE(name, directory)
            );

            CREATE TABLE IF NOT EXISTS files (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                baseline_id   INTEGER NOT NULL REFERENCES baselines(id),
                path          TEXT    NOT NULL,
                hash_value    TEXT    NOT NULL,
                size          INTEGER NOT NULL,
                permissions   TEXT    NOT NULL,
                owner         TEXT    NOT NULL,
                mtime         REAL    NOT NULL,
                -- fingerprint columns
                entropy               REAL,
                function_count        INTEGER,
                class_count           INTEGER,
                import_list           TEXT,
                has_exec_calls        INTEGER,
                exec_call_list        TEXT,
                printable_string_count INTEGER,
                is_executable         INTEGER,
                file_type             TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_files_baseline
                ON files(baseline_id);

            CREATE TABLE IF NOT EXISTS ledger (
                id                    INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp             TEXT    NOT NULL,
                action                TEXT    NOT NULL,
                directory             TEXT    NOT NULL,
                files_scanned         INTEGER NOT NULL,
                changes_summary_json  TEXT    NOT NULL,
                prev_record_hash      TEXT    NOT NULL,
                record_hash           TEXT    NOT NULL
            );
        """)
        self.conn.commit()

    # ── baseline CRUD ────────────────────────────────────────────────

    def create_baseline(
        self,
        name: str,
        directory: str,
        algorithm: str,
        records: List[ScanRecord],
    ) -> int:
        """Insert a new baseline snapshot. Returns the baseline id."""
        now = datetime.now(timezone.utc).isoformat()
        cur = self.conn.cursor()

        # Upsert: if baseline with same name+dir exists, delete old files first
        cur.execute(
            "SELECT id FROM baselines WHERE name = ? AND directory = ?",
            (name, directory),
        )
        row = cur.fetchone()
        if row:
            baseline_id: int = row["id"]
            cur.execute("DELETE FROM files WHERE baseline_id = ?", (baseline_id,))
            cur.execute(
                "UPDATE baselines SET algorithm = ?, created_at = ? WHERE id = ?",
                (algorithm, now, baseline_id),
            )
        else:
            cur.execute(
                "INSERT INTO baselines (name, directory, algorithm, created_at) VALUES (?, ?, ?, ?)",
                (name, directory, algorithm, now),
            )
            baseline_id = cur.lastrowid  # type: ignore[assignment]

        # Bulk-insert file records
        cur.executemany(
            """INSERT INTO files (
                baseline_id, path, hash_value, size, permissions, owner, mtime,
                entropy, function_count, class_count, import_list,
                has_exec_calls, exec_call_list, printable_string_count,
                is_executable, file_type
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    baseline_id, r.path, r.hash_value, r.size, r.permissions,
                    r.owner, r.mtime, r.entropy, r.function_count,
                    r.class_count, r.import_list,
                    int(r.has_exec_calls) if r.has_exec_calls is not None else None,
                    r.exec_call_list, r.printable_string_count,
                    int(r.is_executable) if r.is_executable is not None else None,
                    r.file_type,
                )
                for r in records
            ],
        )
        self.conn.commit()
        return baseline_id

    def get_baseline(
        self, name: str, directory: str
    ) -> Optional[Tuple[int, str, str]]:
        """Return (id, algorithm, created_at) or None."""
        cur = self.conn.cursor()
        cur.execute(
            "SELECT id, algorithm, created_at FROM baselines WHERE name = ? AND directory = ?",
            (name, directory),
        )
        row = cur.fetchone()
        if row:
            return (row["id"], row["algorithm"], row["created_at"])
        return None

    def get_baseline_records(self, baseline_id: int) -> List[ScanRecord]:
        """Fetch all file records for a baseline."""
        cur = self.conn.cursor()
        cur.execute(
            """SELECT path, hash_value, size, permissions, owner, mtime,
                      entropy, function_count, class_count, import_list,
                      has_exec_calls, exec_call_list, printable_string_count,
                      is_executable, file_type
               FROM files WHERE baseline_id = ?""",
            (baseline_id,),
        )
        results: List[ScanRecord] = []
        for row in cur.fetchall():
            results.append(ScanRecord(
                path=row["path"],
                hash_value=row["hash_value"],
                size=row["size"],
                permissions=row["permissions"],
                owner=row["owner"],
                mtime=row["mtime"],
                entropy=row["entropy"],
                function_count=row["function_count"],
                class_count=row["class_count"],
                import_list=row["import_list"],
                has_exec_calls=bool(row["has_exec_calls"]) if row["has_exec_calls"] is not None else None,
                exec_call_list=row["exec_call_list"],
                printable_string_count=row["printable_string_count"],
                is_executable=bool(row["is_executable"]) if row["is_executable"] is not None else None,
                file_type=row["file_type"],
            ))
        return results

    def list_baselines(self) -> List[Dict[str, Any]]:
        """Return all baselines as dicts."""
        cur = self.conn.cursor()
        cur.execute("SELECT id, name, directory, algorithm, created_at FROM baselines ORDER BY created_at DESC")
        return [dict(row) for row in cur.fetchall()]

    # ── audit ledger ─────────────────────────────────────────────────

    def append_ledger(
        self,
        action: str,
        directory: str,
        files_scanned: int,
        changes_summary: Any,
    ) -> LedgerEntry:
        """Append one chained record to the audit ledger."""
        now = datetime.now(timezone.utc).isoformat()
        changes_json = json.dumps(changes_summary, default=str)

        # Get previous record hash
        cur = self.conn.cursor()
        cur.execute("SELECT record_hash FROM ledger ORDER BY id DESC LIMIT 1")
        row = cur.fetchone()
        prev_hash = row["record_hash"] if row else ("0" * 64)

        record_hash = _compute_record_hash(now, action, changes_json, prev_hash)

        cur.execute(
            """INSERT INTO ledger
               (timestamp, action, directory, files_scanned,
                changes_summary_json, prev_record_hash, record_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (now, action, directory, files_scanned, changes_json, prev_hash, record_hash),
        )
        self.conn.commit()

        return LedgerEntry(
            id=cur.lastrowid,
            timestamp=now,
            action=action,
            directory=directory,
            files_scanned=files_scanned,
            changes_summary_json=changes_json,
            prev_record_hash=prev_hash,
            record_hash=record_hash,
        )

    def verify_ledger_chain(self) -> List[Dict[str, Any]]:
        """
        Walk the entire ledger and verify the hash chain.

        Returns a list of error dicts (empty = chain is valid).
        Each error: {record_id, expected_hash, actual_hash, timestamp}
        """
        cur = self.conn.cursor()
        cur.execute(
            """SELECT id, timestamp, action, directory, files_scanned,
                      changes_summary_json, prev_record_hash, record_hash
               FROM ledger ORDER BY id ASC"""
        )

        errors: List[Dict[str, Any]] = []
        prev_hash = "0" * 64

        for row in cur.fetchall():
            expected_prev = prev_hash
            if row["prev_record_hash"] != expected_prev:
                errors.append({
                    "record_id": row["id"],
                    "field": "prev_record_hash",
                    "expected": expected_prev,
                    "actual": row["prev_record_hash"],
                    "timestamp": row["timestamp"],
                })

            expected_hash = _compute_record_hash(
                row["timestamp"],
                row["action"],
                row["changes_summary_json"],
                row["prev_record_hash"],
            )
            if row["record_hash"] != expected_hash:
                errors.append({
                    "record_id": row["id"],
                    "field": "record_hash",
                    "expected": expected_hash,
                    "actual": row["record_hash"],
                    "timestamp": row["timestamp"],
                })

            prev_hash = row["record_hash"]

        return errors

    def get_ledger_entries(
        self, since: Optional[str] = None
    ) -> List[LedgerEntry]:
        """Retrieve ledger entries, optionally filtered by timestamp."""
        cur = self.conn.cursor()
        if since:
            cur.execute(
                "SELECT * FROM ledger WHERE timestamp >= ? ORDER BY id ASC",
                (since,),
            )
        else:
            cur.execute("SELECT * FROM ledger ORDER BY id ASC")

        return [
            LedgerEntry(
                id=row["id"],
                timestamp=row["timestamp"],
                action=row["action"],
                directory=row["directory"],
                files_scanned=row["files_scanned"],
                changes_summary_json=row["changes_summary_json"],
                prev_record_hash=row["prev_record_hash"],
                record_hash=row["record_hash"],
            )
            for row in cur.fetchall()
        ]
