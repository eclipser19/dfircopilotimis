import hashlib
import re
import sqlite3
import json
import uuid
import os
from datetime import datetime, timezone

from copilot.normalize import (normalize_row, normalize_bound, flatten, ENTITY_FIELDS, NORMALIZER_VERSION,
                               describe, event_type_for, extract_entities)

SCHEMA_VERSION = 2

# The search index holds short text per record, not the whole raw row: indexing raw
# rows with trigrams made the database several times larger than the data.
FTS_VALUE_CHARS = 300
FTS_RECORD_CHARS = 6000
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
        self.conn = None
        self.open(case_dir)

    def open(self, case_dir: str):
        """(Re)opens the database of a case directory in place, e.g. when switching cases."""
        os.makedirs(case_dir, exist_ok=True)
        if self.conn is not None:
            self.conn.close()
        self.case_dir = case_dir
        self.db_path = os.path.join(case_dir, "case.db")
        # Several sessions can use the same case, each with its own connection: wait for a
        # writer instead of failing, and let readers work alongside it (WAL).
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=60)
        self.conn.row_factory = sqlite3.Row
        try:
            self.conn.execute("PRAGMA journal_mode=WAL")
        except sqlite3.OperationalError:
            pass  # e.g. a file system without shared memory: keep the default journal
        self._check_schema()
        self._init_tables()
        self._refresh_normalization()

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
            CREATE INDEX IF NOT EXISTS idx_records_event_id ON records(event_id);

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

            CREATE TABLE IF NOT EXISTS outputs (
                output_id   INTEGER PRIMARY KEY AUTOINCREMENT,
                path        TEXT,
                kind        TEXT,
                description TEXT,
                created_at  TEXT,
                size        INTEGER
            );

            CREATE TABLE IF NOT EXISTS conversation (key TEXT PRIMARY KEY, value TEXT, updated_at TEXT);

            -- What investigators told the copilot (copilot/feedback.py): notes, corrections, ratings.
            CREATE TABLE IF NOT EXISTS feedback (
                feedback_id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at  TEXT,
                actor       TEXT,
                kind        TEXT,          -- note | answer | dossier
                rating      INTEGER,       -- 1 right, -1 wrong, 0 no rating (a note)
                question    TEXT,
                answer      TEXT,
                comment     TEXT,          -- the note or correction: what the agent takes as given
                active      INTEGER DEFAULT 1
            );

            -- The case dossier written by an investigation turn (copilot/dossier.py); the latest counts.
            CREATE TABLE IF NOT EXISTS answer_statements (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at   TEXT,
                actor        TEXT,
                question     TEXT,
                kind         TEXT,
                text         TEXT,
                evidence_ids TEXT
            );

            CREATE TABLE IF NOT EXISTS dossiers (
                dossier_id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT,
                actor      TEXT,
                text       TEXT,
                findings   INTEGER,
                steps      INTEGER,
                tokens     INTEGER
            );

            -- Work the web app runs in the background (copilot/jobs.py): questions, investigations, triage,
            -- decided approvals. Kept here so a refresh or a server restart loses nothing.
            CREATE TABLE IF NOT EXISTS jobs (
                job_id      TEXT PRIMARY KEY,
                kind        TEXT,          -- ask | investigate | triage | decide
                user        TEXT,          -- whose conversation it answers in ("" without sign-in)
                label       TEXT,
                state       TEXT,          -- queued | running | done | failed | interrupted
                payload     TEXT,          -- JSON: what to do (enough to run it again)
                result      TEXT,          -- JSON
                error       TEXT,
                process     TEXT,          -- the server process running it (another one = interrupted)
                created_at  TEXT,
                started_at  TEXT,
                finished_at TEXT,
                seen        INTEGER DEFAULT 0   -- an interrupted or failed job the investigator dismissed
            );
            CREATE TABLE IF NOT EXISTS job_events (
                job_id TEXT,
                seq    INTEGER,
                at     TEXT,
                kind   TEXT,               -- tool | collection | notice | status
                text   TEXT,
                PRIMARY KEY (job_id, seq)
            );

            -- Agent requests waiting for an investigator's decision (copilot/approvals.py).
            CREATE TABLE IF NOT EXISTS approval_requests (
                request_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user       TEXT,           -- whose conversation asked
                job_id     TEXT,           -- the job that asked
                decide_job TEXT,           -- the job carrying out the decision
                kind       TEXT,
                summary    TEXT,
                details    TEXT,           -- JSON
                bound      TEXT,           -- JSON: the evidence a collection or memory run was asked for
                state      TEXT,           -- pending | deciding | approved | declined | failed
                created_at TEXT,
                decided_by TEXT,
                decided_at TEXT,
                result     TEXT
            );

            -- Evidence files the copilot reads itself (memory images), hashed once per version.
            CREATE TABLE IF NOT EXISTS evidence_files (
                source     TEXT,          -- memory:<image name>, as in collections.client_id
                size       INTEGER,
                modified   TEXT,          -- the file's modification time (UTC)
                sha256     TEXT,
                hashed_at  TEXT,
                PRIMARY KEY (source, size, modified)
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
        # Added after v2 shipped: findings can be retracted when later evidence disproves them.
        cols = {r[1] for r in cur.execute("PRAGMA table_info(findings)")}
        if "status" not in cols:
            cur.execute("ALTER TABLE findings ADD COLUMN status TEXT DEFAULT 'active'")
            cur.execute("ALTER TABLE findings ADD COLUMN status_reason TEXT")
        # Added with case sharing: the case a finding was copied from (cases.copy_data).
        if "origin" not in cols:
            cur.execute("ALTER TABLE findings ADD COLUMN origin TEXT")
        # Added with feedback: the investigator who checked the finding's records and confirmed it.
        if "confirmed_by" not in cols:
            cur.execute("ALTER TABLE findings ADD COLUMN confirmed_by TEXT")
        # Added with sign-in: who was working when the entry was written.
        if "actor" not in {r[1] for r in cur.execute("PRAGMA table_info(audit_log)")}:
            cur.execute("ALTER TABLE audit_log ADD COLUMN actor TEXT")
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
                text = _search_text(row, norm["description"], entities)
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

    def activity_histogram(self, start: str = None, end: str = None, bucket: str = "hour",
                           event_type: str = None, source: str = None, limit: int = 200) -> list:
        """Timeline event counts per time bucket and event type, to spot bursts of activity."""
        width = {"minute": 16, "hour": 13, "day": 10}.get(bucket)
        if not width:
            raise ValueError("bucket must be minute, hour or day.")
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
        cur.execute(f"SELECT substr(t.timestamp_utc, 1, {width}) AS bucket, r.event_type, COUNT(*) AS events "
                    f"FROM timeline t JOIN records r ON r.evidence_id = t.evidence_id {clause} "
                    f"GROUP BY bucket, r.event_type ORDER BY bucket LIMIT ?", params + [limit])
        return [dict(r) for r in cur.fetchall()]

    def activity_counts(self, start: str, end: str, bucket_seconds: int) -> dict:
        """
        Timeline events per time bucket and artifact source between two recorded times:
        {bucket_index: {source: count}}, bucket 0 starting at `start`.
        """
        start_n, end_n = normalize_bound(start), normalize_bound(end)
        start_epoch = int(datetime.strptime(start_n[:19], "%Y-%m-%dT%H:%M:%S")
                          .replace(tzinfo=timezone.utc).timestamp())
        cur = self.conn.execute(
            "SELECT CAST((CAST(strftime('%s', substr(t.timestamp_utc, 1, 19)) AS INTEGER) - ?) / ? AS INTEGER) AS b, "
            "r.source, COUNT(*) FROM timeline t JOIN records r ON r.evidence_id = t.evidence_id "
            "WHERE t.timestamp_utc >= ? AND t.timestamp_utc <= ? GROUP BY b, r.source",
            (start_epoch, int(bucket_seconds), start_n, end_n))
        counts = {}
        for bucket, source, n in cur.fetchall():
            counts.setdefault(int(bucket), {})[source] = n
        return counts

    def search_events(self, keyword: str, limit: int = 100, source: str = None) -> dict:
        """Case-insensitive substring search across descriptions, entities and raw data (of one source,
        if given: filtered in the query, so the limit applies to that source's matches)."""
        only, only_params = (" AND r.source = ?", [source]) if source else ("", [])
        if self.has_fts and len(keyword) >= 3:
            match = '"' + keyword.replace('"', '""') + '"'
            found = self._records_where("r.evidence_id IN (SELECT evidence_id FROM records_fts "
                                        "WHERE records_fts MATCH ?)" + only, [match, *only_params], limit)
            if found["total"]:
                return found
            # The index keeps only the start of long values (FTS_VALUE_CHARS, FTS_RECORD_CHARS). Before
            # answering "not there", read the full records, so a negative is a real one.
        # Raw rows are stored as JSON: a backslash in the keyword is doubled there.
        forms = list(dict.fromkeys([keyword, json.dumps(keyword)[1:-1]]))
        likes = [f"%{_escape_like(form)}%" for form in forms]
        condition = " OR ".join(["r.description LIKE ? ESCAPE '\\'"] + ["r.raw_data LIKE ? ESCAPE '\\'"] * len(likes))
        return self._records_where(f"({condition}){only}", [likes[0], *likes, *only_params], limit)

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
            "INSERT INTO findings (finding_id, timestamp_utc, title, description, evidence_ids, confidence, "
            "mitre_technique, created_at, status) VALUES (?,?,?,?,?,?,?,?, 'active')",
            (finding_id, timestamp_utc, title, description,
             json.dumps(evidence_ids), confidence, mitre_technique, now)
        )
        self.conn.commit()
        return finding_id

    def get_findings(self, include_retracted: bool = False) -> list:
        cur = self.conn.cursor()
        where = "" if include_retracted else "WHERE COALESCE(status, 'active') = 'active'"
        cur.execute(f"SELECT * FROM findings {where} ORDER BY timestamp_utc IS NULL, timestamp_utc ASC")
        return [dict(r) for r in cur.fetchall()]

    def find_finding(self, finding_id: str) -> dict:
        """Exact ID or a unique prefix (the agent often quotes IDs shortened)."""
        prefix = finding_id.strip().rstrip(".…")
        cur = self.conn.cursor()
        rows = [dict(r) for r in cur.execute("SELECT * FROM findings WHERE finding_id LIKE ? ESCAPE '\\'",
                                            (_escape_like(prefix) + "%",))]
        if len(rows) != 1 or len(prefix) < 4:
            return {}
        return rows[0]

    def confirm_finding(self, finding_id: str, by: str) -> dict:
        """An investigator checked the finding's records and agrees: recorded with who and when."""
        found = self.find_finding(finding_id)
        if found:
            when = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
            self.conn.execute("UPDATE findings SET confirmed_by = ? WHERE finding_id = ?",
                              (f"{by or 'investigator'} ({when} UTC)", found["finding_id"]))
            self.conn.commit()
        return found

    def retract_finding(self, finding_id: str, reason: str) -> dict:
        found = self.find_finding(finding_id)
        if found:
            self.conn.execute("UPDATE findings SET status = 'retracted', status_reason = ? WHERE finding_id = ?",
                              (reason, found["finding_id"]))
            self.conn.commit()
        return found

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

    def _refresh_normalization(self, batch: int = 5000):
        """
        Rebuilds descriptions, event types, extracted fields and the search index from the raw
        rows when the normalizer has improved since they were stored (NORMALIZER_VERSION), so the
        agent sees and finds the same as for a new collection. Timestamps are not affected.
        """
        stored = self.conn.execute("SELECT value FROM meta WHERE key = 'normalizer'").fetchone()
        if stored and stored[0] == str(NORMALIZER_VERSION):
            return
        assignments = ", ".join(f"{c} = ?" for c in ["event_type", "description", *ENTITY_COLUMNS])
        if self.has_fts:
            self.conn.execute("DELETE FROM records_fts")
        last = 0
        while True:
            rows = self.conn.execute("SELECT rowid, evidence_id, source, raw_data, description FROM records "
                                     "WHERE rowid > ? ORDER BY rowid LIMIT ?", (last, batch)).fetchall()
            if not rows:
                break
            updates, index = [], []
            for rowid, evidence_id, source, raw, old_description in rows:
                last = rowid
                try:
                    data = json.loads(raw)
                except (TypeError, ValueError):
                    index.append((evidence_id, old_description or ""))      # keep it findable as before
                    continue
                data = data if isinstance(data, dict) else {"value": data}
                entities = extract_entities(data, source=source)
                description = describe(data, entities, source=source)
                updates.append((event_type_for(source), description,
                                *[entities.get(c) for c in ENTITY_COLUMNS], evidence_id))
                index.append((evidence_id, _search_text(data, description, entities)))
            self.conn.executemany(f"UPDATE records SET {assignments} WHERE evidence_id = ?", updates)
            if self.has_fts:
                self.conn.executemany("INSERT INTO records_fts (evidence_id, text) VALUES (?, ?)", index)
        self.conn.execute("INSERT OR REPLACE INTO meta VALUES ('normalizer', ?)", (str(NORMALIZER_VERSION),))
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

    # --- Feedback (copilot/feedback.py) ---
    def add_feedback(self, kind: str, rating: int = 0, comment: str = "", question: str = "", answer: str = "") -> dict:
        from copilot import session
        cur = self.conn.execute(
            "INSERT INTO feedback (created_at, actor, kind, rating, question, answer, comment, active) "
            "VALUES (?,?,?,?,?,?,?,1)", (datetime.now(timezone.utc).isoformat(), session.current_user(), kind,
                                         int(rating), question or "", answer or "", (comment or "").strip()))
        self.conn.commit()
        return dict(self.conn.execute("SELECT * FROM feedback WHERE feedback_id = ?", (cur.lastrowid,)).fetchone())

    def get_feedback(self, include_withdrawn: bool = False) -> list:
        where = "" if include_withdrawn else "WHERE active = 1"
        return [dict(r) for r in self.conn.execute(f"SELECT * FROM feedback {where} ORDER BY feedback_id")]

    def withdraw_feedback(self, feedback_id: int) -> bool:
        cur = self.conn.execute("UPDATE feedback SET active = 0 WHERE feedback_id = ? AND active = 1", (int(feedback_id),))
        self.conn.commit()
        return bool(cur.rowcount)

    # --- Case dossier ---
    def save_dossier(self, text: str, steps: int = 0, tokens: int = 0) -> dict:
        from copilot import session
        cur = self.conn.execute(
            "INSERT INTO dossiers (created_at, actor, text, findings, steps, tokens) VALUES (?,?,?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(), session.current_user(), text, len(self.get_findings()),
             steps, tokens))
        self.conn.commit()
        return self.get_dossier(cur.lastrowid)

    def get_dossier(self, dossier_id: int = None) -> dict:
        """The latest dossier (or the given one), {} if none was written."""
        if dossier_id is None:
            row = self.conn.execute("SELECT * FROM dossiers ORDER BY dossier_id DESC LIMIT 1").fetchone()
        else:
            row = self.conn.execute("SELECT * FROM dossiers WHERE dossier_id = ?", (dossier_id,)).fetchone()
        return dict(row) if row else {}

    # --- Evidence files (provenance) ---
    def evidence_file(self, source: str, size: int, modified: str) -> dict:
        row = self.conn.execute("SELECT * FROM evidence_files WHERE source = ? AND size = ? AND modified = ?",
                                (source, size, modified)).fetchone()
        return dict(row) if row else {}

    def record_evidence_file(self, source: str, size: int, modified: str, sha256: str):
        self.conn.execute("INSERT OR REPLACE INTO evidence_files VALUES (?,?,?,?,?)",
                          (source, size, modified, sha256, datetime.now(timezone.utc).isoformat()))
        self.conn.commit()

    def get_evidence_files(self) -> list:
        return [dict(r) for r in self.conn.execute("SELECT * FROM evidence_files ORDER BY hashed_at")]

    def hosts_by_source(self) -> dict:
        """{client_id: [hostnames]} of the stored records."""
        hosts = {}
        for row in self.conn.execute("SELECT DISTINCT client_id, hostname FROM records"):
            if row[0] and row[1] and row[1] != "Unknown":
                hosts.setdefault(row[0], []).append(row[1])
        return {k: sorted(v) for k, v in hosts.items()}

    # --- Audit Log ---
    def log_query(self, tool_name: str, query: str, row_count: int, artifact: str = None):
        from copilot import session
        log_id = str(uuid.uuid4())[:12]
        now = datetime.now(timezone.utc).isoformat()
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO audit_log (log_id, timestamp_utc, tool_name, query, row_count, artifact, actor) "
            "VALUES (?,?,?,?,?,?,?)",
            (log_id, now, tool_name, query, row_count, artifact, session.current_user())
        )
        self.conn.commit()


_COLLECTION_FIELDS = {"client_id", "artifact", "parameters", "state", "error",
                      "requested_at", "finished_at", "rows_ingested", "ingested"}


def _evidence_id(client_id: str, source: str, raw_row: str) -> str:
    """Deterministic ID: the same row from the same artifact always gets the same ID."""
    return hashlib.sha256(f"{client_id}|{source}|{raw_row}".encode("utf-8")).hexdigest()[:16]


# Numbers are searchable only in identifier fields (PID, MFT entry, inode, USN, sequence...),
# so a file can be followed across renames by its MFT entry, without indexing every size and offset.
_ID_FIELD = re.compile(r"(?i)(id|pid|mft\w*|inode\w*|entry\w*|seq\w*|usn)$")


def _search_text(row, description: str, entities: dict) -> str:
    """Description, extracted fields, short string values and identifier numbers from the row, capped."""
    parts = [description, *entities.values()]
    for key, value in flatten(row if isinstance(row, dict) else {"value": row}):
        if isinstance(value, str) and value:
            parts.append(value[:FTS_VALUE_CHARS])
        elif isinstance(value, int) and not isinstance(value, bool) and \
                _ID_FIELD.search(re.sub(r"\[\d+\]$", "", key.rsplit(".", 1)[-1])):
            parts.append(str(value))
    text, seen = [], set()
    size = 0
    for part in parts:
        if part in seen:
            continue
        seen.add(part)
        size += len(part) + 1
        if size > FTS_RECORD_CHARS:
            break
        text.append(part)
    return " ".join(text)


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


# Where data lived before each case folder held its own (and where the legacy root case.yaml keeps it).
LEGACY_DATA_ROOT = "case_data"
CASE_DATA_FOLDER = "data"


def data_dir_for(case_file: str) -> str:
    """
    Where a case keeps its database and outputs:
    - DFIR_CASE_DIR: that folder;
    - DFIR_DATA_DIR: <that root>/<case id>, to keep the data elsewhere (e.g. another disk);
    - otherwise in the case's own folder, next to its settings: <cases_dir>/<id>/data. A case
      whose data is still in the old case_data/<id> keeps using it until it is moved
      (python -m copilot.cases move-data).
    The legacy root case.yaml uses the data root itself.
    """
    if os.environ.get("DFIR_CASE_DIR"):
        return os.environ["DFIR_CASE_DIR"]
    from copilot.case_config import cases_dir
    folder = os.path.dirname(os.path.abspath(case_file))
    in_cases = os.path.dirname(folder) == os.path.abspath(cases_dir())
    root = os.environ.get("DFIR_DATA_DIR")
    if root or not in_cases:
        root = root or LEGACY_DATA_ROOT
        return os.path.join(root, os.path.basename(folder)) if in_cases else root
    own = os.path.join(folder, CASE_DATA_FOLDER)
    old = os.path.join(LEGACY_DATA_ROOT, os.path.basename(folder))
    if not os.path.isdir(own) and os.path.isfile(os.path.join(old, "case.db")):
        return old              # not moved yet
    return own


# The active case's database in the current session (see copilot/session.py).
from copilot.session import CaseView  # noqa: E402
case_db = CaseView("db")
