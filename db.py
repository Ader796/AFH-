"""Database layer: SQLite (WAL) schema, helpers, seeding."""
import json
import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from flask import g, has_app_context

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("AFH_DATA_DIR") or os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "afh.db")
BACKUP_DIR = os.path.join(DATA_DIR, "backups")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  full_name TEXT NOT NULL,
  full_name_ar TEXT NOT NULL DEFAULT '',
  role TEXT NOT NULL CHECK (role IN ('owner','engineer','technician')),
  active INTEGER NOT NULL DEFAULT 1,
  employee_no TEXT NOT NULL DEFAULT '',
  phone TEXT NOT NULL DEFAULT '',
  email TEXT NOT NULL DEFAULT '',
  start_date TEXT NOT NULL,
  perms TEXT NOT NULL DEFAULT '{}',
  must_change_pw INTEGER NOT NULL DEFAULT 0,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until TEXT,
  last_login TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  ip TEXT, ua TEXT
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS shifts (
  id INTEGER PRIMARY KEY CHECK (id IN (1,2,3)),
  name TEXT NOT NULL,
  name_ar TEXT NOT NULL DEFAULT '',
  start_time TEXT NOT NULL,
  end_time TEXT NOT NULL,
  color TEXT NOT NULL DEFAULT '#1f4e8c'
);
CREATE TABLE IF NOT EXISTS schedules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  effective_from TEXT NOT NULL,
  pattern TEXT NOT NULL,           -- JSON list of 7 ints, index = Python weekday (Mon=0); 0 = rest day, 1..3 = shift
  updated_by INTEGER, updated_at TEXT NOT NULL,
  UNIQUE (user_id, effective_from)
);
CREATE TABLE IF NOT EXISTS attendance (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  shift_date TEXT NOT NULL,
  shift_id INTEGER,
  check_in TEXT, check_out TEXT,
  late_minutes INTEGER NOT NULL DEFAULT 0,
  is_late INTEGER NOT NULL DEFAULT 0,
  in_lat REAL, in_lng REAL, in_dist REAL, in_acc REAL,
  out_lat REAL, out_lng REAL, out_dist REAL, out_acc REAL,
  source TEXT NOT NULL DEFAULT 'self',
  note TEXT NOT NULL DEFAULT '',
  edited_by INTEGER,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE (user_id, shift_date)
);
CREATE INDEX IF NOT EXISTS ix_att_date ON attendance(shift_date);
CREATE TABLE IF NOT EXISTS leave_types (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL, name_ar TEXT NOT NULL DEFAULT '',
  deducts INTEGER NOT NULL DEFAULT 1,
  active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS leave_balances (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  year INTEGER NOT NULL,
  total REAL NOT NULL,
  updated_by INTEGER, updated_at TEXT NOT NULL,
  PRIMARY KEY (user_id, year)
);
CREATE TABLE IF NOT EXISTS leave_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type_id INTEGER NOT NULL REFERENCES leave_types(id),
  start_date TEXT NOT NULL, end_date TEXT NOT NULL,
  days REAL NOT NULL,
  days_by_year TEXT NOT NULL DEFAULT '{}',
  reason TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL CHECK (status IN ('pending','approved','rejected','cancelled')),
  decided_by INTEGER, decided_at TEXT,
  decision_comment TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_leave_user ON leave_requests(user_id, start_date);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  actor_id INTEGER, actor_name TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL,
  entity TEXT NOT NULL DEFAULT '',
  entity_id TEXT NOT NULL DEFAULT '',
  details TEXT NOT NULL DEFAULT '{}',
  ip TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_audit_entity ON audit_log(entity, entity_id);
"""

DEFAULT_SETTINGS = {
    "company_name": "AFH Factory",
    "company_name_ar": "مصنع AFH",
    "company_address": "",
    "company_phone": "",
    "company_email": "",
    "timezone": "Africa/Cairo",
    "factory_lat": "",
    "factory_lng": "",
    "gps_radius_m": 150,
    "gps_required": 1,
    "gps_max_accuracy_m": 150,
    "late_grace_min": 10,
    "absent_after_min": 60,
    "checkin_early_min": 120,
    "allow_unscheduled": 1,
    "min_punch_gap_sec": 60,
    "max_open_hours": 20,
    "annual_leave_days": 21,
    "leave_count_mode": "calendar",   # calendar | working
    "leave_past_days_allowed": 7,
    "week_start_day": 5,              # Python weekday: Mon=0 ... Sat=5, Sun=6
    "session_days": 14,
    "backup_interval_hours": 24,
    "backup_keep": 30,
}

DEFAULT_SHIFTS = [
    (1, "Shift 1", "الوردية الأولى", "06:00", "14:00", "#1f6feb"),
    (2, "Shift 2", "الوردية الثانية", "14:00", "22:00", "#d97706"),
    (3, "Shift 3", "الوردية الثالثة", "22:00", "06:00", "#6d28d9"),
]

DEFAULT_LEAVE_TYPES = [
    ("Annual leave", "إجازة اعتيادية", 1),
    ("Casual leave", "إجازة عارضة", 1),
    ("Sick leave", "إجازة مرضية", 0),
    ("Unpaid leave", "إجازة بدون مرتب", 0),
]


def utcnow_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def connect():
    os.makedirs(DATA_DIR, exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=20, isolation_level=None)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA synchronous=NORMAL")
    c.execute("PRAGMA busy_timeout=20000")
    return c


def get_db():
    if has_app_context():
        if "db" not in g:
            g.db = connect()
        return g.db
    return connect()


def close_db(_exc=None):
    c = g.pop("db", None)
    if c is not None:
        c.close()


def rows(sql, args=()):
    return [dict(r) for r in get_db().execute(sql, args).fetchall()]


def row(sql, args=()):
    r = get_db().execute(sql, args).fetchone()
    return dict(r) if r else None


def run(sql, args=()):
    return get_db().execute(sql, args)


@contextmanager
def tx():
    """Atomic write transaction (takes the write lock immediately)."""
    c = get_db()
    c.execute("BEGIN IMMEDIATE")
    try:
        yield c
        c.execute("COMMIT")
    except BaseException:
        c.execute("ROLLBACK")
        raise


def init_db():
    from werkzeug.security import generate_password_hash
    c = connect()
    c.executescript(SCHEMA)
    for k, v in DEFAULT_SETTINGS.items():
        c.execute("INSERT OR IGNORE INTO settings(key,value) VALUES (?,?)", (k, json.dumps(v)))
    for s in DEFAULT_SHIFTS:
        c.execute("INSERT OR IGNORE INTO shifts(id,name,name_ar,start_time,end_time,color) VALUES (?,?,?,?,?,?)", s)
    if c.execute("SELECT COUNT(*) FROM leave_types").fetchone()[0] == 0:
        for n, a, d in DEFAULT_LEAVE_TYPES:
            c.execute("INSERT INTO leave_types(name,name_ar,deducts) VALUES (?,?,?)", (n, a, d))
    if c.execute("SELECT COUNT(*) FROM users WHERE role='owner'").fetchone()[0] == 0:
        pw = os.environ.get("AFH_OWNER_PASSWORD") or secrets.token_urlsafe(9)
        now = utcnow_iso()
        c.execute(
            "INSERT INTO users(username,password_hash,full_name,full_name_ar,role,start_date,must_change_pw,created_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            ("owner", generate_password_hash(pw), "System Owner", "مالك النظام", "owner", now[:10], 1, now),
        )
        path = os.path.join(DATA_DIR, "INITIAL_OWNER_CREDENTIALS.txt")
        with open(path, "w") as f:
            f.write(f"username: owner\npassword: {pw}\n(You must change this password at first login. Delete this file afterwards.)\n")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        print(f"\n*** First run: owner account created. username=owner password={pw}\n    (also saved in {path}) ***\n")
    c.close()
