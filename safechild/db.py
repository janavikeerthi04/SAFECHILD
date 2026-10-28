import hashlib
import secrets
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = BASE_DIR / "uploads"
DB_PATH = DATA_DIR / "safechild.db"

REFRESH_SECONDS = 5
COMPLAINT_STATUSES = ["Open", "Searching", "Found", "Closed"]
SEARCH_STATUSES = ["Not started", "Searching", "Completed", "Child found"]

_lock = threading.Lock()

# Sample zones: (name, colour, x, y, width, height) - edit them in the Organiser dashboard
DEFAULT_ZONES = [
    ("Entrance", "#8ecae6", 0, 0, 1, 1),
    ("Food Court", "#ffb703", 1, 0, 1, 1),
    ("Main Stage", "#fb8500", 2, 0, 1, 1),
    ("Play Area", "#90be6d", 0, 1, 1, 1),
    ("Parking", "#adb5bd", 1, 1, 1, 1),
    ("Restrooms", "#cdb4db", 2, 1, 1, 1),
]

# Demo accounts created on first run only - CHANGE THESE in the Organiser dashboard
DEFAULT_ORGANISER = ("organiser", "Event Organiser", "organiser123")
DEFAULT_STAFF_PASSWORD = "staff123"


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


@contextmanager
def connect():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def _rows(cursor):
    return [dict(r) for r in cursor.fetchall()]


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000).hex()
    return salt, digest


def init_db():
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    with _lock, connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS zones (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                colour TEXT NOT NULL DEFAULT '#8ecae6',
                x INTEGER NOT NULL DEFAULT 0, y INTEGER NOT NULL DEFAULT 0,
                w INTEGER NOT NULL DEFAULT 1, h INTEGER NOT NULL DEFAULT 1);
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                full_name TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('staff', 'organiser')),
                salt TEXT NOT NULL, pw_hash TEXT NOT NULL,
                zone_id INTEGER);
            CREATE TABLE IF NOT EXISTS complaints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                number TEXT UNIQUE,
                child_name TEXT NOT NULL, age INTEGER, gender TEXT,
                dress_colour TEXT NOT NULL, identifying_details TEXT,
                photo_path TEXT, last_zone_id INTEGER, last_location TEXT,
                time_missing TEXT NOT NULL, parent_name TEXT NOT NULL,
                parent_phone TEXT NOT NULL, extra_details TEXT,
                status TEXT NOT NULL DEFAULT 'Open', resolution TEXT,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS zone_searches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                complaint_id INTEGER NOT NULL, zone_id INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'Not started',
                staff_username TEXT, notes TEXT, updated_at TEXT,
                UNIQUE (complaint_id, zone_id));
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                complaint_id INTEGER NOT NULL, username TEXT NOT NULL,
                is_read INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);
            """
        )
        if conn.execute("SELECT COUNT(*) FROM zones").fetchone()[0] == 0:
            conn.executemany(
                "INSERT INTO zones (name, colour, x, y, w, h) VALUES (?,?,?,?,?,?)", DEFAULT_ZONES
            )
        if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            username, full_name, password = DEFAULT_ORGANISER
            salt, digest = hash_password(password)
            conn.execute(
                "INSERT INTO users (username, full_name, role, salt, pw_hash) VALUES (?,?,?,?,?)",
                (username, full_name, "organiser", salt, digest),
            )
            zones = conn.execute("SELECT id, name FROM zones ORDER BY id").fetchall()
            for i, z in enumerate(zones, start=1):
                salt, digest = hash_password(DEFAULT_STAFF_PASSWORD)
                conn.execute(
                    "INSERT INTO users (username, full_name, role, salt, pw_hash, zone_id) "
                    "VALUES (?,?,?,?,?,?)",
                    (f"staff{i}", f"Staff {i} ({z['name']})", "staff", salt, digest, z["id"]),
                )


# ---------- users ----------
def verify_user(username, password, role):
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username=? AND role=?", (username, role)
        ).fetchone()
    if not row:
        return None
    _, digest = hash_password(password, row["salt"])
    if secrets.compare_digest(digest, row["pw_hash"]):
        return {"username": row["username"], "full_name": row["full_name"], "role": row["role"]}
    return None


def get_user(username):
    with connect() as conn:
        row = conn.execute(
            "SELECT username, full_name, role, zone_id FROM users WHERE username=?", (username,)
        ).fetchone()
    return dict(row) if row else None


def list_users(role=None):
    query = (
        "SELECT u.username, u.full_name, u.role, u.zone_id, z.name AS zone_name "
        "FROM users u LEFT JOIN zones z ON z.id = u.zone_id"
    )
    params = ()
    if role:
        query += " WHERE u.role=?"
        params = (role,)
    with connect() as conn:
        return _rows(conn.execute(query + " ORDER BY u.role, u.username", params))


def add_user(username, full_name, password, role="staff", zone_id=None):
    salt, digest = hash_password(password)
    with _lock, connect() as conn:
        conn.execute(
            "INSERT INTO users (username, full_name, role, salt, pw_hash, zone_id) VALUES (?,?,?,?,?,?)",
            (username, full_name, role, salt, digest, zone_id),
        )


def assign_staff(username, zone_id):
    with _lock, connect() as conn:
        conn.execute("UPDATE users SET zone_id=? WHERE username=?", (zone_id, username))


def reset_password(username, new_password):
    salt, digest = hash_password(new_password)
    with _lock, connect() as conn:
        conn.execute("UPDATE users SET salt=?, pw_hash=? WHERE username=?", (salt, digest, username))


# ---------- zones ----------
def list_zones():
    with connect() as conn:
        return _rows(conn.execute("SELECT * FROM zones ORDER BY id"))


def add_zone(name, colour, x, y, w, h):
    with _lock, connect() as conn:
        zone_id = conn.execute(
            "INSERT INTO zones (name, colour, x, y, w, h) VALUES (?,?,?,?,?,?)",
            (name, colour, x, y, w, h),
        ).lastrowid
        for c in conn.execute(
            "SELECT id FROM complaints WHERE status IN ('Open','Searching')"
        ).fetchall():
            conn.execute(
                "INSERT OR IGNORE INTO zone_searches (complaint_id, zone_id) VALUES (?,?)",
                (c["id"], zone_id),
            )


def update_zone(zone_id, name, colour, x, y, w, h):
    with _lock, connect() as conn:
        conn.execute(
            "UPDATE zones SET name=?, colour=?, x=?, y=?, w=?, h=? WHERE id=?",
            (name, colour, x, y, w, h, zone_id),
        )


def delete_zone(zone_id):
    with _lock, connect() as conn:
        conn.execute("DELETE FROM zones WHERE id=?", (zone_id,))
        conn.execute("DELETE FROM zone_searches WHERE zone_id=?", (zone_id,))
        conn.execute("UPDATE users SET zone_id=NULL WHERE zone_id=?", (zone_id,))


# ---------- complaints ----------
COMPLAINT_SELECT = (
    "SELECT c.*, z.name AS last_zone_name FROM complaints c "
    "LEFT JOIN zones z ON z.id = c.last_zone_id"
)


def create_complaint(data, photo_bytes=None, photo_ext=None):
    """Saves the complaint as Open, gives it a SC-#### number and alerts every staff member."""
    with _lock, connect() as conn:
        ts = now_str()
        complaint_id = conn.execute(
            "INSERT INTO complaints (child_name, age, gender, dress_colour, identifying_details, "
            "last_zone_id, last_location, time_missing, parent_name, parent_phone, extra_details, "
            "status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,'Open',?,?)",
            (
                data["child_name"], data["age"], data["gender"], data["dress_colour"],
                data["identifying_details"], data["last_zone_id"], data["last_location"],
                data["time_missing"], data["parent_name"], data["parent_phone"],
                data["extra_details"], ts, ts,
            ),
        ).lastrowid
        number = f"SC-{complaint_id:04d}"
        photo_path = None
        if photo_bytes:
            UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
            file_name = f"{number}.{photo_ext}"
            (UPLOAD_DIR / file_name).write_bytes(photo_bytes)
            photo_path = f"uploads/{file_name}"
        conn.execute(
            "UPDATE complaints SET number=?, photo_path=? WHERE id=?",
            (number, photo_path, complaint_id),
        )
        for z in conn.execute("SELECT id FROM zones").fetchall():
            conn.execute(
                "INSERT OR IGNORE INTO zone_searches (complaint_id, zone_id) VALUES (?,?)",
                (complaint_id, z["id"]),
            )
        for u in conn.execute("SELECT username FROM users WHERE role='staff'").fetchall():
            conn.execute(
                "INSERT INTO notifications (complaint_id, username, created_at) VALUES (?,?,?)",
                (complaint_id, u["username"], ts),
            )
    return number


def list_complaints(statuses=None):
    query, params = COMPLAINT_SELECT, ()
    if statuses:
        query += f" WHERE c.status IN ({','.join('?' * len(statuses))})"
        params = tuple(statuses)
    with connect() as conn:
        return _rows(conn.execute(query + " ORDER BY c.id DESC", params))


def lookup_complaint(number, phone):
    with connect() as conn:
        row = conn.execute(
            COMPLAINT_SELECT + " WHERE UPPER(c.number)=UPPER(?) AND c.parent_phone=?",
            (number, phone),
        ).fetchone()
    return dict(row) if row else None


def set_complaint_status(complaint_id, status, resolution=None):
    with _lock, connect() as conn:
        conn.execute(
            "UPDATE complaints SET status=?, resolution=COALESCE(?, resolution), updated_at=? WHERE id=?",
            (status, resolution, now_str(), complaint_id),
        )


def status_counts():
    with connect() as conn:
        rows = conn.execute("SELECT status, COUNT(*) AS n FROM complaints GROUP BY status").fetchall()
    counts = {s: 0 for s in COMPLAINT_STATUSES}
    counts.update({r["status"]: r["n"] for r in rows})
    return counts


# ---------- zone searches ----------
def get_zone_searches(complaint_id):
    with connect() as conn:
        return _rows(conn.execute(
            "SELECT s.*, z.name AS zone_name FROM zone_searches s "
            "JOIN zones z ON z.id = s.zone_id WHERE s.complaint_id=? ORDER BY z.id",
            (complaint_id,),
        ))


def update_zone_search(complaint_id, zone_id, status, staff_username, notes=""):
    with _lock, connect() as conn:
        ts = now_str()
        conn.execute(
            "INSERT INTO zone_searches (complaint_id, zone_id, status, staff_username, notes, updated_at) "
            "VALUES (?,?,?,?,?,?) ON CONFLICT(complaint_id, zone_id) DO UPDATE SET "
            "status=excluded.status, staff_username=excluded.staff_username, "
            "notes=excluded.notes, updated_at=excluded.updated_at",
            (complaint_id, zone_id, status, staff_username, notes, ts),
        )
        if status == "Child found":
            conn.execute(
                "UPDATE complaints SET status='Found', updated_at=? WHERE id=?", (ts, complaint_id)
            )
        else:
            conn.execute(
                "UPDATE complaints SET status='Searching', updated_at=? WHERE id=? AND status='Open'",
                (ts, complaint_id),
            )


# ---------- notifications ----------
def get_unread_notifications(username):
    with connect() as conn:
        return _rows(conn.execute(
            "SELECT n.id, c.number, c.child_name, c.dress_colour, z.name AS last_zone_name "
            "FROM notifications n JOIN complaints c ON c.id = n.complaint_id "
            "LEFT JOIN zones z ON z.id = c.last_zone_id "
            "WHERE n.username=? AND n.is_read=0 ORDER BY n.id",
            (username,),
        ))


def mark_notifications_read(username):
    with _lock, connect() as conn:
        conn.execute("UPDATE notifications SET is_read=1 WHERE username=?", (username,)
