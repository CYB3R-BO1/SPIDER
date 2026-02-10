import hashlib
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional

from storage.sqlite_store import SQLiteStore


class SnapshotManager:
    """
    Creates and compares snapshots of the workspace.
    Snapshots are stored in SQLite as JSON metadata and file references.
    """

    def __init__(self, sqlite_store: SQLiteStore, root_dir: str = "."):
        self.store = sqlite_store
        self.root_dir = os.path.abspath(root_dir)

    def create_snapshot(self, name: str, metadata: Optional[Dict] = None):
        files = self._collect_file_refs()
        created_at = datetime.now(timezone.utc).isoformat()
        meta = metadata or {}
        meta.setdefault("root_dir", self.root_dir)
        self.store.save_snapshot(name, created_at, meta, files)

    def load_snapshot(self, name: str) -> Optional[Dict]:
        return self.store.load_snapshot(name)

    def diff_snapshots(self, a: str, b: str) -> Dict:
        snap_a = self.store.load_snapshot(a)
        snap_b = self.store.load_snapshot(b)
        if snap_a is None or snap_b is None:
            return {
                "error": "snapshot_not_found",
                "missing": [n for n, s in [(a, snap_a), (b, snap_b)] if s is None],
            }

        files_a = {f["path"]: f for f in snap_a.get("files", [])}
        files_b = {f["path"]: f for f in snap_b.get("files", [])}

        added = sorted(p for p in files_b if p not in files_a)
        removed = sorted(p for p in files_a if p not in files_b)
        modified = []
        unchanged = []

        for path in files_a.keys() & files_b.keys():
            if self._file_changed(files_a[path], files_b[path]):
                modified.append(path)
            else:
                unchanged.append(path)

        return {
            "a": a,
            "b": b,
            "added": added,
            "removed": removed,
            "modified": sorted(modified),
            "unchanged": sorted(unchanged),
        }

    # ---------------------------
    # Internal helpers
    # ---------------------------

    def _collect_file_refs(self) -> List[Dict]:
        file_refs = []
        for root, dirs, files in os.walk(self.root_dir):
            dirs[:] = [
                d
                for d in dirs
                if d not in {".git", "__pycache__", ".venv", "venv"}
            ]
            for filename in files:
                path = os.path.join(root, filename)
                rel_path = os.path.relpath(path, self.root_dir)
                try:
                    stat = os.stat(path)
                except OSError:
                    continue
                file_refs.append(
                    {
                        "path": rel_path.replace("\\", "/"),
                        "size": stat.st_size,
                        "mtime": int(stat.st_mtime),
                        "sha256": self._hash_file(path),
                    }
                )
        return file_refs

    def _hash_file(self, path: str) -> str:
        hasher = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    hasher.update(chunk)
        except OSError:
            return ""
        return hasher.hexdigest()

    def _file_changed(self, a: Dict, b: Dict) -> bool:
        for key in ("size", "mtime", "sha256"):
            if a.get(key) != b.get(key):
                return True
        return False
