import json
import sqlite3
from typing import Dict, List, Optional


class SQLiteStore:
    """
    Stores metadata, logs, snapshots, and plugin registry.
    Responsibilities:
    - Keep stable tabular data separate from graph structures.
    - Provide historical versioned snapshots.
    - Track agent runs, errors, and cached results.
    """

    def __init__(self, db_path: str = "storage/metadata.db"):
        self.db_path = db_path
        self._init_db()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS snapshots (
                    name TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    metadata_json TEXT,
                    files_json TEXT
                )
                """
            )

    def save_snapshot(self, name: str, created_at: str, metadata: Dict, files: List[Dict]):
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO snapshots (name, created_at, metadata_json, files_json)
                VALUES (?, ?, ?, ?)
                """,
                (
                    name,
                    created_at,
                    json.dumps(metadata or {}),
                    json.dumps(files or []),
                ),
            )

    def load_snapshot(self, name: str) -> Optional[Dict]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT name, created_at, metadata_json, files_json FROM snapshots WHERE name = ?",
                (name,),
            ).fetchone()
            if row is None:
                return None
            return {
                "name": row[0],
                "created_at": row[1],
                "metadata": json.loads(row[2]) if row[2] else {},
                "files": json.loads(row[3]) if row[3] else [],
            }

    def list_snapshots(self) -> List[Dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT name, created_at FROM snapshots ORDER BY created_at"
            ).fetchall()
        return [{"name": r[0], "created_at": r[1]} for r in rows]
