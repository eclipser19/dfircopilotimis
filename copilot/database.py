import hashlib
import sqlite3
import json
import uuid
import os
from datetime import datetime, timezone

from copilot.normalize import normalize_row, normalize_bound, ENTITY_FIELDS

SCHEMA_VERSION = 2
ENTITY_COLUMNS = list(ENTITY_FIELDS)  # user, process, command_line, path, hash, ip, event_id
RECORD_COLUMNS = ["evidence_id", "client_id", "hostname", "source", "event_type", "description",
                  *ENTITY_COLUMNS, "first_seen", "last_seen"]


class SchemaError(Exception):
    """The case database was created by an incompatible version."""


class CaseDatabase:
    """
    SQLite case database.
      records  — one row per artifact result row (raw data + extracted entities)
      timeline — one row per distinct timestamp found in a record (UTC, fixed width)
      records_fts — full-text (substring) index over records, when SQLite supports it
    """

    def __init__(self, case_dir="case_data"):
        os.makedirs(case_dir, exist_ok=True)
        self.db_path = os.path.join(case_dir, "case.db")
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._check_schema()
        self._init_tables()

    def _check_schema(self):
        cur = self.conn.cursor()
        tables = {r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "events" in tables and "records" not in tables:
            raise SchemaError(
                f"{self.db_path} was created by an older DFIR Copilot version. "
                f"Delete it (or start a new case directory) and collect again.")

    def _init_tables(self):
        cur = self.conn.cursor()
        entity_cols = ",\n".join(f"                {c} TEXT" for c in ENTITY_COLUMNS)
        cur.executescript(f"""
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);

            CREATE TABLE IF NOT EXISTS records (
                evidence_id   TEXT PRIMARY KEY,
                client_id     TEXT,
                hostname      TEXT,
                source        TEXT,
                event_type    TEXT,
                description   TEXT,
{entity_cols},
                first_seen    TEXT,
                last_seen     TEXT,
                raw_data      TEXT,
                ingested_at   TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_records_source ON records(source);
            CREATE INDEX IF NOT EXISTS idx_records_type ON records(event_type);
            CREATE INDEX IF NOT EXISTS idx_records_user ON records(user);
            CREATE INDEX IF NOT EXISTS idx_records_process ON records(process);
            CREATE INDEX IF NOT EXISTS idx_records_ip ON records(ip);
            CREATE INDEX IF NOT EXISTS idx_records_hash ON records(hash);

            CREATE TABLE IF NOT EXISTS timeline (
                evidence_id    TEXT,
                timestamp_utc  TEXT,
                timestamp_desc TEXT,
                PRIMARY KEY (evidence_id, timestamp_utc)
            );
            CREATE INDEX IF NOT EXISTS idx_timeline_ts ON timeline(timestamp_utc);

            CREATE TABLE IF NOT EXISTS findings (
                finding_id    TEXT PRIMARY KEY,
                timestamp_utc TEXT,
                title         TEXT,
                description   TEXT,
                evidence_ids  TEXT,
                confidence    TEXT,
                mitre_technique TEXT,
                created_at    TEXT
            );

            CREATE TABLE IF NOT EXISTS collections (
                flow_id       TEXT PRIMARY KEY,
                client_id     TEXT,
                artifact      TEXT,
                parameters    TEXT,
                state         TEXT,
                error         TEXT,
                requested_at  TEXT,
                finished_at   TEXT,
                rows_ingested INTEGER DEFAULT 0,
                ingested      INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                log_id        TEXT PRIMARY KEY,
                timestamp_utc TEXT,
                tool_name     TEXT,
                query         TEXT,
                row_count     INTEGER,
                artifact      TEXT
            );
        """)
        cur.execute("INSERT OR IGNORE INTO meta VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))
        # Trigram FTS gives case-insensitive substring search; needs SQLite >= 3.34.
        try:
            cur.execute("CREATE VIRTUAL TABLE IF NOT EXISTS records_fts "
                        "USING fts5(evidence_id UNINDEXED, text, tokenize='trigram')")
            self.has_fts = True
        except sqlite3.OperationalError:
            self.has_fts = False
        self.conn.commit()

    # --- Ingestion ---
    def ingest_artifact_results(self, results, source: str, hostname: str = "Unknown",
                                client_id: str = "") -> int:
        """
        Normalizes and stores artifact result rows (any iterable, so large flows
        can be streamed). Returns the number of NEW records; rows already in the
        database (e.g. from re-collecting an artifact) are skipped.
        """
        cur = self.conn.cursor()
        count = 0
        now = datetime.now(timezone.utc).isoformat()
        placeholders = ",".join("?" * (len(RECORD_COLUMNS) + 2))

        for row in results:
            raw = json.dumps(row, sort_keys=True, default=str)
            evidence_id = _evidence_id(client_id, source, raw)
            norm = normalize_row(row if isinstance(row, dict) else {"value": row}, source)
            stamps = norm["timestamps"]
            entities = norm["entities"]

            values = [evidence_id, client_id, hostname, source, norm["event_type"], norm["description"],
                      *[entities.get(c) for c in ENTITY_COLUMNS],
                      stamps[0][0] if stamps else None, stamps[-1][0] if stamps else None,
                      raw, now]
            cur.execute(f"INSERT OR IGNORE INTO records ({','.join(RECORD_COLUMNS)}, raw_data, ingested_at) "
                        f"VALUES ({placeholders})", values)
            if not cur.rowcount:
                continue
            count += 1
            cur.executemany("INSERT OR IGNORE INTO timeline VALUES (?,?,?)",
                            [(evidence_id, ts, desc) for ts, desc in stamps])
            if self.has_fts:
                text = " ".join([norm["description"], *entities.values(), raw])
                cur.execute("INSERT INTO records_fts (evidence_id, text) VALUES (?, ?)", (evidence_id, text))
            if count % 5000 == 0:
                self.conn.commit()

        self.conn.commit()
        return count

    # --- Query Tools ---
    def query_timeline(self, start: str = None, end: str = None,
                       event_type: str = None, source: str = None,
                       limit: int = 200) -> dict:
        """
        Timeline events (one per timestamp) in a window, oldest first.
        Returns {"total", "events", "undated"}: `undated` counts matching records
        that have no timestamp at all, so they aren't silently missing.
        """
        start, end = normalize_bound(start), normalize_bound(end)
        where, params = [], []
        if start:
            where.append("t.timestamp_utc >= ?")
            params.append(start)
        if end:
            where.append("t.timestamp_utc <= ?")
            params.append(end)
        rec_where, rec_params = _record_filters(event_type, source)
        where += rec_where
        params += rec_params
        clause = f"WHERE {' AND '.join(where)}" if where else ""

        cur = self.conn.cursor()
        base = f"FROM timeline t JOIN records r ON r.evidence_id = t.evidence_id {clause}"
        total = cur.execute(f"SELECT COUNT(*) {base}", params).fetchone()[0]
        cols = ", ".join(f"r.{c}" for c in RECORD_COLUMNS if c not in ("first_seen", "last_seen", "client_id"))
        cur.execute(f"SELECT t.timestamp_utc, t.timestamp_desc, {cols} {base} "
                    f"ORDER BY t.timestamp_utc ASC LIMIT ?", params + [limit])
        events = [_compact(dict(r)) for r in cur.fetchall()]

        undated_clause = " AND ".join(["r.first_seen IS NULL"] + rec_where)
        cur.execute(f"SELECT r.source, COUNT(*) AS records FROM records r WHERE {undated_clause} "
                    f"GROUP BY r.source", rec_params)
        undated = [dict(r) for r in cur.fetchall()]
        return {"total": total, "events": events, "undated": undated}

    def search_events(self, keyword: str, limit: int = 100) -> dict:
        """Case-insensitive substring search across descriptions, entities and raw data."""
        cur = self.conn.cursor()
        if self.has_fts and len(keyword) >= 3:
            match = '"' + keyword.replace('"', '""') + '"'
            ids_sql = "SELECT evidence_id FROM records_fts WHERE records_fts MATCH ?"
            params = [match]
        else:
            like = f"%{_escape_like(keyword)}%"
            ids_sql = ("SELECT evidence_id FROM records WHERE description LIKE ? ESCAPE '\\' "
                       "OR raw_data LIKE ? ESCAPE '\\'")
            params = [like, like]
        return self._records_where(f"r.evidence_id IN ({ids_sql})", params, limit)

    def pivot_entity(self, entity: str, field: str = None, limit: int = 100) -> dict:
        """
        Records whose extracted `field` (user, process, ip, ...) contains `entity`;
        without a field, a full search.
        """
        if not field:
            return self.search_events(entity, limit)
        if field not in ENTITY_COLUMNS:
            raise ValueError(f"Unknown field '{field}'. Use one of: {', '.join(ENTITY_COLUMNS)}.")
        return self._records_where(f"r.{field} LIKE ? ESCAPE '\\'", [f"%{_escape_like(entity)}%"], limit)

    def _records_where(self, condition: str, params: list, limit: int) -> dict:
        cur = self.conn.cursor()
        total = cur.execute(f"SELECT COUNT(*) FROM records r WHERE {condition}", params).fetchone()[0]
        cols = ", ".join(f"r.{c}" for c in RECORD_COLUMNS if c != "client_id")
        cur.execute(f"SELECT {cols} FROM records r WHERE {condition} "
                    f"ORDER BY r.first_seen IS NULL, r.first_seen ASC LIMIT ?", params + [limit])
        return {"total": total, "records": [_compact(dict(r)) for r in cur.fetchall()]}

    def get_event_detail(self, evidence_id: str) -> dict:
        """Full record (raw data included) plus every timestamp found in it."""
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM records WHERE evidence_id = ?", (evidence_id,))
        row = cur.fetchone()
        if not row:
            return {}
        record = dict(row)
        cur.execute("SELECT timestamp_utc, timestamp_desc FROM timeline WHERE evidence_id = ? "
                    "ORDER BY timestamp_utc", (evidence_id,))
        record["timestamps"] = [dict(r) for r in cur.fetchall()]
        return record

    def get_stats(self) -> dict:
        """Summary statistics of the case database."""
        cur = self.conn.cursor()
        row = cur.execute("SELECT COUNT(*) AS records, COUNT(first_seen) AS dated, "
                          "COUNT(DISTINCT source) AS sources FROM records").fetchone()
        span = cur.execute("SELECT COUNT(*) AS events, MIN(timestamp_utc) AS earliest, "
                           "MAX(timestamp_utc) AS latest FROM timeline").fetchone()
        cur.execute("SELECT r.source, r.event_type, COUNT(*) AS records, COUNT(r.first_seen) AS dated_records, "
                    "MIN(r.first_seen) AS earliest, MAX(r.last_seen) AS latest "
                    "FROM records r GROUP BY r.source ORDER BY records DESC")
        by_source = [dict(r) for r in cur.fetchall()]
        return {"total_records": row["records"], "dated_records": row["dated"],
                "undated_records": row["records"] - row["dated"],
                "timeline_events": span["events"], "unique_sources": row["sources"],
                "earliest": span["earliest"], "latest": span["latest"],
                "by_source": by_source}

    # --- Findings ---
    def record_finding(self, title: str, description: str, evidence_ids: list,
                       confidence: str = "medium", mitre_technique: str = None,
                       timestamp_utc: str = None) -> str:
        finding_id = str(uuid.uuid4())[:12]
        now = datetime.now(timezone.utc).isoformat()
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?)",
            (finding_id, timestamp_utc, title, description,
             json.dumps(evidence_ids), confidence, mitre_technique, now)
        )
        self.conn.commit()
        return finding_id

    def get_findings(self) -> list:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM findings ORDER BY timestamp_utc IS NULL, timestamp_utc ASC")
        return [dict(r) for r in cur.fetchall()]

    # --- Collections ---
    def upsert_collection(self, flow_id: str, **fields):
        """Insert or update the tracking row for a Velociraptor flow."""
        cur = self.conn.cursor()
        cur.execute("INSERT OR IGNORE INTO collections (flow_id) VALUES (?)", (flow_id,))
        for key, value in fields.items():
            if key not in _COLLECTION_FIELDS:
                raise ValueError(f"Unknown collections field: {key}")
            cur.execute(f"UPDATE collections SET {key} = ? WHERE flow_id = ?", (value, flow_id))
        self.conn.commit()

    def get_collection(self, flow_id: str) -> dict:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM collections WHERE flow_id = ?", (flow_id,))
        row = cur.fetchone()
        return dict(row) if row else {}

    def get_collections(self) -> list:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM collections ORDER BY requested_at ASC")
        return [dict(r) for r in cur.fetchall()]

    # --- Audit Log ---
    def log_query(self, tool_name: str, query: str, row_count: int, artifact: str = None):
        log_id = str(uuid.uuid4())[:12]
        now = datetime.now(timezone.utc).isoformat()
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO audit_log VALUES (?,?,?,?,?,?)",
            (log_id, now, tool_name, query, row_count, artifact)
        )
        self.conn.commit()


_COLLECTION_FIELDS = {"client_id", "artifact", "parameters", "state", "error",
                      "requested_at", "finished_at", "rows_ingested", "ingested"}


def _evidence_id(client_id: str, source: str, raw_row: str) -> str:
    """Deterministic ID: the same row from the same artifact always gets the same ID."""
    return hashlib.sha256(f"{client_id}|{source}|{raw_row}".encode("utf-8")).hexdigest()[:16]


def _escape_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _record_filters(event_type: str, source: str) -> tuple:
    where, params = [], []
    if event_type:
        where.append("r.event_type = ?")
        params.append(event_type)
    if source:
        where.append("r.source LIKE ? ESCAPE '\\'")
        params.append(f"%{_escape_like(source)}%")
    return where, params


def _compact(row: dict) -> dict:
    """Drops empty columns so tool output stays small."""
    return {k: v for k, v in row.items() if v not in (None, "")}


# Global instance
case_db = CaseDatabase(os.environ.get("DFIR_CASE_DIR", "case_data"))
