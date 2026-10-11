"""SQLite access (standard library only, so it is easy to explain)."""
import os
import sqlite3
from contextlib import contextmanager


def db_path() -> str:
    url = os.getenv("DATABASE_URL", "sqlite:///./osint_platform.db")
    path = url[len("sqlite:///"):] if url.startswith("sqlite:///") else url
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    return path


@contextmanager
def conn():
    c = sqlite3.connect(db_path(), timeout=30)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    try:
        yield c
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS investigations(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target TEXT NOT NULL, target_type TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued', progress INTEGER NOT NULL DEFAULT 0,
  risk_score INTEGER NOT NULL DEFAULT 0, risk_label TEXT NOT NULL DEFAULT 'Unknown',
  summary TEXT NOT NULL DEFAULT '', summary_source TEXT NOT NULL DEFAULT '',
  use_keyed INTEGER NOT NULL DEFAULT 1, monitoring INTEGER NOT NULL DEFAULT 0,
  run_count INTEGER NOT NULL DEFAULT 0, error TEXT,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL, last_run_at TEXT,
  UNIQUE(target, target_type));
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  source TEXT NOT NULL, title TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '',
  severity TEXT NOT NULL DEFAULT 'info', provenance TEXT NOT NULL DEFAULT 'live',
  observed_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  investigation_id INTEGER REFERENCES investigations(id) ON DELETE CASCADE,
  target TEXT NOT NULL, message TEXT NOT NULL, severity TEXT NOT NULL DEFAULT 'info',
  created_at TEXT NOT NULL, is_read INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS ix_find_inv ON findings(investigation_id);
"""


def init():
    with conn() as c:
        c.executescript(SCHEMA)
