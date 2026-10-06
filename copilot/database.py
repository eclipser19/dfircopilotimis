import sqlite3
import json
import uuid
import os
from datetime import datetime, timezone


class CaseDatabase:
    """SQLite database for storing normalized forensic events per case."""

    def __init__(self, case_dir="case_data"):
        os.makedirs(case_dir, exist_ok=True)
        self.db_path = os.path.join(case_dir, "case.db")
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_tables()

    def _init_tables(self):
        cur = self.conn.cursor()
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                evidence_id   TEXT PRIMARY KEY,
                timestamp_utc TEXT,
                hostname      TEXT,
                source        TEXT,
                event_type    TEXT,
                description   TEXT,
                raw_data      TEXT,
                ingested_at   TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp_utc);
            CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
            CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);

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

            CREATE TABLE IF NOT EXISTS audit_log (
                log_id        TEXT PRIMARY KEY,
                timestamp_utc TEXT,
                tool_name     TEXT,
                query         TEXT,
                row_count     INTEGER,
                artifact      TEXT
            );
        """)
        self.conn.commit()

    # --- Event Ingestion ---
    def ingest_artifact_results(self, results: list, source: str, hostname: str = "Unknown") -> int:
        """
        Ingests raw artifact result rows into the events table.
        Attempts to extract a timestamp from common Velociraptor fields.
        Returns the number of rows ingested.
        """
        cur = self.conn.cursor()
        count = 0
        now = datetime.now(timezone.utc).isoformat()

        # Common timestamp field names in Velociraptor artifacts
        ts_fields = [
            "EventTime", "Timestamp", "timestamp", "event_time",
            "TimeCreated", "Created0x10", "LastModified0x10",
            "LastRunTime", "CreatedDate", "ModifiedDate",
            "Mtime", "Atime", "Ctime", "Btime",
            "mtime", "atime", "ctime", "btime",
            "Created", "Modified", "LastAccessed",
            "StartTime", "EndTime", "LoginTime",
            "client_time", "SourceDate",
        ]

        for row in results:
            evidence_id = str(uuid.uuid4())[:12]

            # Try to find a timestamp
            ts = None
            for field in ts_fields:
                val = row.get(field)
                if val and str(val).strip() and str(val) != "0":
                    ts = str(val)
                    break

            # Build a human-readable description from key fields
            desc_parts = []
            for key in ["Message", "message", "Name", "FullPath", "CommandLine",
                        "Exe", "Details", "UserName", "SourceName", "EventID"]:
                val = row.get(key)
                if val:
                    desc_parts.append(f"{key}={val}")
            description = "; ".join(desc_parts) if desc_parts else json.dumps(row)[:500]

            # Guess event type from the source artifact name
            event_type = _guess_event_type(source)

            cur.execute(
                "INSERT OR IGNORE INTO events (evidence_id, timestamp_utc, hostname, source, event_type, description, raw_data, ingested_at) VALUES (?,?,?,?,?,?,?,?)",
                (evidence_id, ts, hostname, source, event_type, description, json.dumps(row), now)
            )
            count += 1

        self.conn.commit()
        return count

    # --- Query Tools ---
    def query_timeline(self, start: str = None, end: str = None,
                       event_type: str = None, source: str = None,
                       limit: int = 200) -> list:
        """Query events within a time window, optionally filtered."""
        query = "SELECT evidence_id, timestamp_utc, hostname, source, event_type, description FROM events WHERE 1=1"
        params = []

        if start:
            query += " AND timestamp_utc >= ?"
            params.append(start)
        if end:
            query += " AND timestamp_utc <= ?"
            params.append(end)
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        if source:
            query += " AND source LIKE ?"
            params.append(f"%{source}%")

        query += " ORDER BY timestamp_utc ASC LIMIT ?"
        params.append(limit)

        cur = self.conn.cursor()
        cur.execute(query, params)
        return [dict(r) for r in cur.fetchall()]

    def search_events(self, keyword: str, limit: int = 100) -> list:
        """Full-text search across descriptions and raw data."""
        cur = self.conn.cursor()
        cur.execute(
            "SELECT evidence_id, timestamp_utc, hostname, source, event_type, description FROM events WHERE description LIKE ? OR raw_data LIKE ? ORDER BY timestamp_utc ASC LIMIT ?",
            (f"%{keyword}%", f"%{keyword}%", limit)
        )
        return [dict(r) for r in cur.fetchall()]

    def pivot_entity(self, entity: str, limit: int = 100) -> list:
        """Find all events mentioning a specific user, process, IP, or path."""
        return self.search_events(entity, limit)

    def get_event_detail(self, evidence_id: str) -> dict:
        """Get full raw data for a specific evidence ID."""
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM events WHERE evidence_id = ?", (evidence_id,))
        row = cur.fetchone()
        return dict(row) if row else {}

    def get_stats(self) -> dict:
        """Get summary statistics of the case database."""
        cur = self.conn.cursor()
        cur.execute("SELECT COUNT(*) as total, COUNT(DISTINCT source) as sources, MIN(timestamp_utc) as earliest, MAX(timestamp_utc) as latest FROM events")
        row = cur.fetchone()
        cur.execute("SELECT source, COUNT(*) as count FROM events GROUP BY source ORDER BY count DESC")
        by_source = [dict(r) for r in cur.fetchall()]
        return {"total_events": row["total"], "unique_sources": row["sources"],
                "earliest": row["earliest"], "latest": row["latest"],
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
        cur.execute("SELECT * FROM findings ORDER BY timestamp_utc ASC")
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


def _guess_event_type(source: str) -> str:
    """Guess event category from artifact source name."""
    s = source.lower()
    if any(k in s for k in ["evtx", "eventlog", "event"]):
        return "event_log"
    if any(k in s for k in ["prefetch", "amcache", "shimcache"]):
        return "execution"
    if any(k in s for k in ["mft", "usn", "ntfs", "filefinder"]):
        return "filesystem"
    if any(k in s for k in ["network", "netstat", "dns", "connection"]):
        return "network"
    if any(k in s for k in ["registry", "run", "service", "schtask", "persistence"]):
        return "persistence"
    if any(k in s for k in ["browser", "chrome", "firefox", "edge", "history"]):
        return "browser"
    if any(k in s for k in ["logon", "login", "session", "rdp"]):
        return "authentication"
    if any(k in s for k in ["powershell", "psreadline", "script"]):
        return "script_execution"
    return "other"


# Global instance
case_db = CaseDatabase()
