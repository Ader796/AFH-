"""AFH Factory Attendance Management System - Flask backend."""
import hashlib
import json
import os
import queue
import re
import secrets
import shutil
import sqlite3
import threading
import time as _time
from collections import defaultdict, deque
from datetime import date, datetime, timedelta, timezone
from functools import wraps
from zoneinfo import ZoneInfo

from flask import Flask, Response, g, jsonify, request, send_from_directory, stream_with_context
from werkzeug.security import check_password_hash, generate_password_hash

import db
import logic as L
import reports

app = Flask(__name__, static_folder=None)
app.json.ensure_ascii = False
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024
app.teardown_appcontext(db.close_db)
L.TESTING = os.environ.get("AFH_TESTING") == "1"
if os.environ.get("AFH_TRUST_PROXY") == "1":
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

STATIC = os.path.join(db.BASE_DIR, "static")
COOKIE = "afh_session"
ENG_PERMS = {"approve_leave": True, "manage_balances": True, "edit_schedule": True,
             "view_reports": True, "edit_attendance": False}
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,32}$")
HHMM_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


# ------------------------------------------------------------------ errors
class ApiError(Exception):
    def __init__(self, code, message, status=400, **extra):
        self.code, self.message, self.status, self.extra = code, message, status, extra


@app.errorhandler(ApiError)
def _api_error(e):
    return jsonify({"error": e.code, "message": e.message, **e.extra}), e.status


@app.errorhandler(404)
def _404(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "not_found", "message": "Not found"}), 404
    return send_from_directory(STATIC, "index.html")


@app.errorhandler(405)
def _405(e):
    return jsonify({"error": "method_not_allowed", "message": "Method not allowed"}), 405


@app.errorhandler(Exception)
def _500(e):
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        return jsonify({"error": "http_error", "message": e.description}), e.code
    app.logger.exception("Unhandled error")
    return jsonify({"error": "server_error", "message": "Unexpected server error"}), 500


def bad(msg, code="validation", **extra):
    return ApiError(code, msg, 400, **extra)


# ------------------------------------------------------------------ validation helpers
def body():
    d = request.get_json(silent=True)
    return d if isinstance(d, dict) else {}


def sval(d, key, maxlen=200, required=False, default=""):
    v = d.get(key, default)
    if v is None:
        v = default
    if not isinstance(v, str):
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            v = str(v)
        else:
            raise bad(f"Invalid {key}", field=key)
    v = v.strip()
    if required and not v:
        raise bad(f"{key} is required", field=key)
    if len(v) > maxlen:
        raise bad(f"{key} too long", field=key)
    return v


def dval(d, key, required=True):
    v = d.get(key)
    if not v:
        if required:
            raise bad(f"{key} is required", field=key)
        return None
    try:
        return date.fromisoformat(str(v))
    except ValueError:
        raise bad(f"Invalid date {key}", field=key)


def ival(v, name="id"):
    try:
        return int(v)
    except (TypeError, ValueError):
        raise bad(f"Invalid {name}")


def local_dt(d, key, required=True):
    v = d.get(key)
    if not v:
        if required:
            raise bad(f"{key} is required", field=key)
        return None
    try:
        return L.parse_local(str(v))
    except ValueError:
        raise bad(f"Invalid datetime {key}", field=key)


# ------------------------------------------------------------------ auth
def hash_token(t):
    return hashlib.sha256(t.encode()).hexdigest()


def client_ip():
    return request.remote_addr or ""


def current_user():
    if "user" in g:
        return g.user
    g.user = None
    tok = request.cookies.get(COOKIE)
    if tok:
        r = db.row(
            "SELECT u.*, s.expires_at, s.last_seen FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?",
            (hash_token(tok),))
        if r and r["active"] and r["expires_at"] > db.utcnow_iso():
            g.user = r
            if r["last_seen"] < L.iso(L.now() - timedelta(minutes=30)):
                days = int(L.settings()["session_days"])
                db.run("UPDATE sessions SET last_seen=?, expires_at=? WHERE token_hash=?",
                       (db.utcnow_iso(), L.iso(L.now() + timedelta(days=days)), hash_token(tok)))
    return g.user


def eff_perms(u):
    if u["role"] == "owner":
        return {k: True for k in ENG_PERMS}
    if u["role"] == "engineer":
        p = dict(ENG_PERMS)
        try:
            p.update({k: bool(v) for k, v in json.loads(u["perms"] or "{}").items() if k in ENG_PERMS})
        except ValueError:
            pass
        return p
    return {k: False for k in ENG_PERMS}


def auth(*roles, perm=None, pw_ok=False):
    def deco(f):
        @wraps(f)
        def w(*a, **kw):
            u = current_user()
            if not u:
                raise ApiError("unauthorized", "Authentication required", 401)
            if u["must_change_pw"] and not pw_ok:
                raise ApiError("password_change_required", "You must change your password first", 403)
            if roles and u["role"] not in roles:
                raise ApiError("forbidden", "You do not have permission for this action", 403)
            if perm and not eff_perms(u).get(perm):
                raise ApiError("forbidden", "You do not have permission for this action", 403)
            return f(*a, **kw)
        return w
    return deco


MANAGERS = ("owner", "engineer")


@app.before_request
def _csrf_and_headers():
    if request.path.startswith("/api/") and request.method not in ("GET", "HEAD", "OPTIONS"):
        if request.headers.get("X-Requested-With") != "AFH":
            raise ApiError("csrf", "Missing request header", 403)


@app.after_request
def _security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(self), camera=(), microphone=()"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
    if request.is_secure:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


def audit(action, entity="", entity_id="", details=None):
    u = g.get("user")
    db.run("INSERT INTO audit_log(ts,actor_id,actor_name,action,entity,entity_id,details,ip) VALUES (?,?,?,?,?,?,?,?)",
           (db.utcnow_iso(), u["id"] if u else None, (u["username"] if u else ""), action, entity, str(entity_id),
            json.dumps(details or {}, ensure_ascii=False, default=str), client_ip()))


# ------------------------------------------------------------------ realtime (SSE)
_subs = []
_subs_lock = threading.Lock()


def publish(kind, user_id=None):
    msg = json.dumps({"type": kind, "user_id": user_id})
    with _subs_lock:
        for s in list(_subs):
            if kind in ("schedule", "settings", "shifts") or s["role"] in MANAGERS or s["user_id"] == user_id:
                try:
                    s["q"].put_nowait(msg)
                except queue.Full:
                    pass


@app.get("/api/stream")
@auth()
def stream():
    u = current_user()
    sub = {"q": queue.Queue(maxsize=200), "user_id": u["id"], "role": u["role"]}
    with _subs_lock:
        _subs.append(sub)

    def gen():
        try:
            yield "retry: 5000\n\n: connected\n\n"
            while True:
                try:
                    m = sub["q"].get(timeout=15)
                    yield f"data: {m}\n\n"
                except queue.Empty:
                    yield ": ping\n\n"
        finally:
            with _subs_lock:
                if sub in _subs:
                    _subs.remove(sub)

    return Response(stream_with_context(gen()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ------------------------------------------------------------------ serializers
def user_public(u, full=True):
    d = {k: u[k] for k in ("id", "username", "full_name", "full_name_ar", "role", "active", "employee_no", "phone",
                           "email", "start_date", "must_change_pw", "last_login", "created_at")}
    d["perms"] = eff_perms(u) if u["role"] == "engineer" else None
    return d


def public_settings(full=False):
    s = L.settings()
    keys = ["company_name", "company_name_ar", "timezone", "week_start_day", "gps_required", "gps_radius_m",
            "leave_count_mode", "late_grace_min", "allow_unscheduled"]
    if full:
        return dict(s)
    return {k: s[k] for k in keys}


# ------------------------------------------------------------------ public / auth routes
_login_hits = defaultdict(deque)


@app.get("/api/public")
def public():
    s = L.settings()
    return jsonify({"company_name": s["company_name"], "company_name_ar": s["company_name_ar"]})


@app.get("/api/health")
def health():
    db.row("SELECT 1 x")
    return jsonify({"ok": True})


@app.post("/api/login")
def login():
    ip = client_ip()
    hits = _login_hits[ip]
    nowt = _time.time()
    while hits and hits[0] < nowt - 300:
        hits.popleft()
    if len(hits) >= 40:
        raise ApiError("rate_limited", "Too many attempts, try again later", 429)
    hits.append(nowt)
    d = body()
    username, password = sval(d, "username", 64), d.get("password") if isinstance(d.get("password"), str) else ""
    u = db.row("SELECT * FROM users WHERE username=?", (username,))
    if not u:
        check_password_hash(generate_password_hash("x"), password)
        raise ApiError("invalid_credentials", "Incorrect username or password", 401)
    if u["locked_until"] and u["locked_until"] > db.utcnow_iso():
        mins = max(1, int((L.parse_iso(u["locked_until"]) - L.now()).total_seconds() // 60) + 1)
        raise ApiError("account_locked", f"Account temporarily locked. Try again in {mins} min", 423, minutes=mins)
    if not check_password_hash(u["password_hash"], password):
        fails = u["failed_attempts"] + 1
        lock = L.iso(L.now() + timedelta(minutes=15)) if fails >= 5 else None
        db.run("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?", (0 if lock else fails, lock, u["id"]))
        g.user = u
        audit("login_failed", "user", u["id"], {"locked": bool(lock)})
        raise ApiError("invalid_credentials", "Incorrect username or password", 401)
    if not u["active"]:
        raise ApiError("account_disabled", "This account is deactivated", 403)
    db.run("UPDATE users SET failed_attempts=0, locked_until=NULL, last_login=? WHERE id=?", (db.utcnow_iso(), u["id"]))
    tok = secrets.token_urlsafe(32)
    days = int(L.settings()["session_days"])
    now_s = db.utcnow_iso()
    db.run("DELETE FROM sessions WHERE expires_at<?", (now_s,))
    db.run("INSERT INTO sessions(token_hash,user_id,created_at,expires_at,last_seen,ip,ua) VALUES (?,?,?,?,?,?,?)",
           (hash_token(tok), u["id"], now_s, L.iso(L.now() + timedelta(days=days)), now_s, ip,
            (request.headers.get("User-Agent") or "")[:200]))
    g.user = u
    audit("login", "user", u["id"])
    resp = jsonify({"ok": True})
    resp.set_cookie(COOKIE, tok, max_age=days * 86400, httponly=True, samesite="Strict", secure=request.is_secure, path="/")
    return resp


@app.post("/api/logout")
def logout():
    tok = request.cookies.get(COOKIE)
    if tok:
        db.run("DELETE FROM sessions WHERE token_hash=?", (hash_token(tok),))
    resp = jsonify({"ok": True})
    resp.delete_cookie(COOKIE, path="/")
    return resp


@app.get("/api/me")
@auth(pw_ok=True)
def me():
    u = current_user()
    return jsonify({"user": user_public(u), "settings": public_settings(), "shifts": list(L.shifts_map().values()),
                    "server_time": L.iso(L.now())})


def check_pw_strength(pw, username=""):
    if not isinstance(pw, str) or len(pw) < 8:
        raise bad("Password must be at least 8 characters", "weak_password")
    if not re.search(r"[A-Za-z]", pw) or not re.search(r"\d", pw):
        raise bad("Password must contain letters and digits", "weak_password")
    if username and pw.lower() == username.lower():
        raise bad("Password must differ from the username", "weak_password")


@app.post("/api/change-password")
@auth(pw_ok=True)
def change_password():
    u, d = current_user(), body()
    if not check_password_hash(u["password_hash"], d.get("current_password") or ""):
        raise ApiError("invalid_credentials", "Current password is incorrect", 401)
    check_pw_strength(d.get("new_password"), u["username"])
    if d["new_password"] == d.get("current_password"):
        raise bad("New password must differ from the current one", "weak_password")
    db.run("UPDATE users SET password_hash=?, must_change_pw=0 WHERE id=?", (generate_password_hash(d["new_password"]), u["id"]))
    tok = request.cookies.get(COOKIE)
    db.run("DELETE FROM sessions WHERE user_id=? AND token_hash<>?", (u["id"], hash_token(tok or "")))
    audit("password_changed", "user", u["id"])
    return jsonify({"ok": True})


# ------------------------------------------------------------------ users
def get_target_user(uid, managers_only_tech=True):
    t = db.row("SELECT * FROM users WHERE id=?", (uid,))
    if not t:
        raise ApiError("not_found", "User not found", 404)
    u = current_user()
    if u["role"] == "engineer" and t["role"] != "technician":
        raise ApiError("forbidden", "You do not have permission for this action", 403)
    return t


@app.get("/api/users")
@auth(*MANAGERS)
def users_list():
    u = current_user()
    sql = "SELECT * FROM users"
    if u["role"] == "engineer":
        sql += " WHERE role='technician'"
    role = request.args.get("role")
    if role in ("technician", "engineer", "owner") and u["role"] == "owner":
        sql += (" AND" if "WHERE" in sql else " WHERE") + " role=?"
        args = (role,)
    else:
        args = ()
    return jsonify({"users": [user_public(x) for x in db.rows(sql + " ORDER BY role, full_name COLLATE NOCASE", args)]})


def owners_active_count(exclude=None):
    sql = "SELECT COUNT(*) c FROM users WHERE role='owner' AND active=1"
    args = ()
    if exclude:
        sql += " AND id<>?"; args = (exclude,)
    return db.row(sql, args)["c"]


def clean_perms(p):
    if not isinstance(p, dict):
        return {}
    return {k: bool(v) for k, v in p.items() if k in ENG_PERMS}


@app.post("/api/users")
@auth("owner")
def users_create():
    d = body()
    username = sval(d, "username", 32, True)
    if not USERNAME_RE.match(username):
        raise bad("Username: 3-32 letters, digits, . _ -", field="username")
    role = d.get("role", "technician")
    if role not in ("technician", "engineer", "owner"):
        raise bad("Invalid role", field="role")
    if db.row("SELECT 1 FROM users WHERE username=?", (username,)):
        raise ApiError("username_taken", "Username already exists", 409)
    pw = d.get("password") or secrets.token_urlsafe(8) + "7"
    check_pw_strength(pw, username)
    full_name = sval(d, "full_name", 100, True)
    start = dval(d, "start_date", False) or L.now().astimezone(L.tz()).date()
    shift_id = d.get("shift_id")
    rest = d.get("rest_days") or []
    now_s = db.utcnow_iso()
    with db.tx():
        cur = db.run(
            "INSERT INTO users(username,password_hash,full_name,full_name_ar,role,active,employee_no,phone,email,start_date,perms,must_change_pw,created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (username, generate_password_hash(pw), full_name, sval(d, "full_name_ar", 100), role, 1,
             sval(d, "employee_no", 30), sval(d, "phone", 30), sval(d, "email", 100), start.isoformat(),
             json.dumps(clean_perms(d.get("perms"))), 1, now_s))
        uid = cur.lastrowid
        if role == "technician" and shift_id:
            sid = ival(shift_id, "shift_id")
            if sid not in (1, 2, 3):
                raise bad("Invalid shift", field="shift_id")
            rest_days = {ival(x) for x in rest if 0 <= ival(x) <= 6} if isinstance(rest, list) else set()
            pattern = [0 if i in rest_days else sid for i in range(7)]
            db.run("INSERT INTO schedules(user_id,effective_from,pattern,updated_by,updated_at) VALUES (?,?,?,?,?)",
                   (uid, start.isoformat(), json.dumps(pattern), current_user()["id"], now_s))
        if role == "technician" and d.get("annual_leave") not in (None, ""):
            try:
                tot = float(d["annual_leave"])
            except (TypeError, ValueError):
                raise bad("Invalid annual leave", field="annual_leave")
            if tot < 0 or tot > 366:
                raise bad("Invalid annual leave", field="annual_leave")
            db.run("INSERT INTO leave_balances(user_id,year,total,updated_by,updated_at) VALUES (?,?,?,?,?)",
                   (uid, start.year, tot, current_user()["id"], now_s))
        audit("user_created", "user", uid, {"username": username, "role": role})
    publish("users")
    return jsonify({"id": uid, "temp_password": pw if not d.get("password") else None}), 201


@app.put("/api/users/<int:uid>")
@auth("owner")
def users_update(uid):
    t, d, me_ = get_target_user(uid), body(), current_user()
    upd, before = {}, {}
    for k, ml in (("full_name", 100), ("full_name_ar", 100), ("employee_no", 30), ("phone", 30), ("email", 100)):
        if k in d:
            v = sval(d, k, ml, required=(k == "full_name"))
            if v != t[k]:
                before[k], upd[k] = t[k], v
    if "start_date" in d:
        v = dval(d, "start_date").isoformat()
        if v != t["start_date"]:
            before["start_date"], upd["start_date"] = t["start_date"], v
    new_role = d.get("role", t["role"])
    if new_role not in ("technician", "engineer", "owner"):
        raise bad("Invalid role", field="role")
    new_active = int(bool(d["active"])) if "active" in d else t["active"]
    if t["role"] == "owner" and (new_role != "owner" or not new_active) and owners_active_count(uid) == 0:
        raise ApiError("last_owner", "At least one active owner is required", 409)
    if uid == me_["id"] and not new_active:
        raise ApiError("self_deactivate", "You cannot deactivate your own account", 409)
    if uid == me_["id"] and new_role != me_["role"]:
        raise ApiError("self_role", "You cannot change your own role", 409)
    if new_role != t["role"]:
        before["role"], upd["role"] = t["role"], new_role
    if new_active != t["active"]:
        before["active"], upd["active"] = t["active"], new_active
    if "perms" in d:
        np = json.dumps(clean_perms(d["perms"]))
        if np != t["perms"]:
            before["perms"], upd["perms"] = t["perms"], np
    if "username" in d and sval(d, "username", 32) != t["username"]:
        nu = sval(d, "username", 32, True)
        if not USERNAME_RE.match(nu):
            raise bad("Username: 3-32 letters, digits, . _ -", field="username")
        if db.row("SELECT 1 FROM users WHERE username=? AND id<>?", (nu, uid)):
            raise ApiError("username_taken", "Username already exists", 409)
        before["username"], upd["username"] = t["username"], nu
    if upd:
        sets = ",".join(f"{k}=?" for k in upd)
        db.run(f"UPDATE users SET {sets} WHERE id=?", (*upd.values(), uid))
        if "active" in upd and not new_active:
            db.run("DELETE FROM sessions WHERE user_id=?", (uid,))
        audit("user_updated", "user", uid, {"before": before, "after": upd})
        publish("users", uid)
    return jsonify({"ok": True})


@app.post("/api/users/<int:uid>/reset-password")
@auth("owner")
def users_reset_pw(uid):
    t, d = get_target_user(uid), body()
    pw = d.get("password") or secrets.token_urlsafe(8) + "7"
    check_pw_strength(pw, t["username"])
    db.run("UPDATE users SET password_hash=?, must_change_pw=1, failed_attempts=0, locked_until=NULL WHERE id=?",
           (generate_password_hash(pw), uid))
    db.run("DELETE FROM sessions WHERE user_id=?", (uid,))
    audit("password_reset", "user", uid)
    return jsonify({"temp_password": pw})


# ------------------------------------------------------------------ settings & shifts
def _coerce_setting(key, v):
    default = db.DEFAULT_SETTINGS[key]
    if key in ("factory_lat", "factory_lng"):
        if v in ("", None):
            return ""
        try:
            f = float(v)
        except (TypeError, ValueError):
            raise bad(f"Invalid {key}", field=key)
        if abs(f) > (90 if key == "factory_lat" else 180):
            raise bad(f"Invalid {key}", field=key)
        return f
    if isinstance(default, bool) or key in ("gps_required", "allow_unscheduled"):
        return 1 if v in (True, 1, "1", "true", "on") else 0
    if isinstance(default, int):
        try:
            n = int(float(v))
        except (TypeError, ValueError):
            raise bad(f"Invalid {key}", field=key)
        lo, hi = {"week_start_day": (0, 6), "gps_radius_m": (10, 50000), "gps_max_accuracy_m": (10, 5000),
                  "session_days": (1, 90), "backup_interval_hours": (1, 720), "backup_keep": (1, 365)}.get(key, (0, 100000))
        if not lo <= n <= hi:
            raise bad(f"{key} must be between {lo} and {hi}", field=key)
        return n
    v = str(v if v is not None else "").strip()
    if len(v) > 200:
        raise bad(f"{key} too long", field=key)
    if key == "timezone":
        try:
            ZoneInfo(v)
        except Exception:
            raise bad("Unknown time zone", field=key)
    if key == "leave_count_mode" and v not in ("calendar", "working"):
        raise bad("Invalid leave count mode", field=key)
    if key == "company_name" and not v:
        raise bad("Company name is required", field=key)
    return v


@app.get("/api/settings")
@auth("owner")
def settings_get():
    return jsonify({"settings": public_settings(full=True)})


@app.put("/api/settings")
@auth("owner")
def settings_put():
    d, cur, changed = body(), L.settings(), {}
    for k, v in d.items():
        if k not in db.DEFAULT_SETTINGS:
            continue
        nv = _coerce_setting(k, v)
        if nv != cur.get(k):
            changed[k] = {"from": cur.get(k), "to": nv}
    with db.tx():
        for k, c in changed.items():
            db.run("INSERT INTO settings(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                   (k, json.dumps(c["to"])))
        if changed:
            audit("settings_updated", "settings", "", changed)
    L.invalidate_settings()
    if changed:
        publish("settings")
    return jsonify({"ok": True, "settings": public_settings(full=True)})


@app.get("/api/shifts")
@auth()
def shifts_get():
    return jsonify({"shifts": list(L.shifts_map().values())})


@app.put("/api/shifts/<int:sid>")
@auth("owner")
def shifts_put(sid):
    s = L.shifts_map().get(sid)
    if not s:
        raise ApiError("not_found", "Shift not found", 404)
    d = body()
    new = {"name": sval(d, "name", 50, True, s["name"]), "name_ar": sval(d, "name_ar", 50, False, s["name_ar"]),
           "start_time": sval(d, "start_time", 5, True, s["start_time"]),
           "end_time": sval(d, "end_time", 5, True, s["end_time"]),
           "color": sval(d, "color", 9, True, s["color"])}
    for k in ("start_time", "end_time"):
        if not HHMM_RE.match(new[k]):
            raise bad("Time must be HH:MM", field=k)
    if new["start_time"] == new["end_time"]:
        raise bad("Start and end time must differ", field="end_time")
    if not re.match(r"^#[0-9A-Fa-f]{6}$", new["color"]):
        raise bad("Invalid colour", field="color")
    db.run("UPDATE shifts SET name=?,name_ar=?,start_time=?,end_time=?,color=? WHERE id=?",
           (new["name"], new["name_ar"], new["start_time"], new["end_time"], new["color"], sid))
    audit("shift_updated", "shift", sid, {"before": {k: s[k] for k in new}, "after": new})
    publish("shifts")
    return jsonify({"ok": True})


# ------------------------------------------------------------------ schedules
def _week_param():
    v = request.args.get("week_start") or request.args.get("date")
    d = date.fromisoformat(v) if v else L.now().astimezone(L.tz()).date()
    return L.week_start_of(d)


@app.get("/api/schedule")
@auth()
def schedule_get():
    u = current_user()
    try:
        ws = _week_param()
    except ValueError:
        raise bad("Invalid date")
    sched = L.Sched()
    days = [ws + timedelta(days=i) for i in range(7)]
    if u["role"] == "technician":
        users = [u]
    else:
        users = db.rows("SELECT * FROM users WHERE role='technician' AND active=1 ORDER BY full_name COLLATE NOCASE")
    leaves = L.Leaves(days[0], days[-1])
    out = []
    for x in users:
        out.append({"id": x["id"], "full_name": x["full_name"], "full_name_ar": x["full_name_ar"],
                    "employee_no": x["employee_no"], "pattern": [sched.shift(x["id"], dd) for dd in days],
                    "leave": [bool(leaves.on(x["id"], dd)) for dd in days]})
    cur_ws = L.week_start_of(L.now().astimezone(L.tz()).date())
    return jsonify({"week_start": ws.isoformat(), "days": [dd.isoformat() for dd in days], "users": out,
                    "editable_past": u["role"] == "owner", "current_week_start": cur_ws.isoformat()})


@app.put("/api/schedule")
@auth(*MANAGERS, perm="edit_schedule")
def schedule_put():
    me_, d = current_user(), body()
    ws = L.week_start_of(dval(d, "week_start"))
    cur_ws = L.week_start_of(L.now().astimezone(L.tz()).date())
    if ws < cur_ws and me_["role"] != "owner":
        raise ApiError("forbidden", "Only the owner can change past weeks", 403)
    mode = d.get("mode", "week")
    if mode not in ("week", "onward"):
        raise bad("Invalid mode", field="mode")
    entries = d.get("entries")
    if not isinstance(entries, list) or not entries:
        raise bad("No entries", field="entries")
    nxt = ws + timedelta(days=7)
    changes = []
    with db.tx():
        sched = L.Sched()
        now_s = db.utcnow_iso()
        for e in entries:
            uid = ival(e.get("user_id"), "user_id")
            if not db.row("SELECT 1 FROM users WHERE id=? AND role='technician'", (uid,)):
                raise bad("Unknown technician", field="user_id")
            pat_in = e.get("pattern")
            if not isinstance(pat_in, list) or len(pat_in) != 7 or any(
                    isinstance(x, bool) or not isinstance(x, int) or x not in (0, 1, 2, 3) for x in pat_in):
                raise bad("Pattern must be 7 values 0-3", field="pattern")
            # API patterns are aligned with the week's days (starting at week_start); storage is indexed by weekday
            pat = [0] * 7
            for i, v in enumerate(pat_in):
                pat[(ws + timedelta(days=i)).weekday()] = v
            old = sched.pattern(uid, ws) or [0] * 7
            if old == pat:
                continue
            if mode == "week":
                has_next = db.row("SELECT 1 FROM schedules WHERE user_id=? AND effective_from=?", (uid, nxt.isoformat()))
                if not has_next:
                    after_old = sched.pattern(uid, nxt)
                    if after_old is not None and after_old != pat:
                        db.run("INSERT INTO schedules(user_id,effective_from,pattern,updated_by,updated_at) VALUES (?,?,?,?,?)",
                               (uid, nxt.isoformat(), json.dumps(after_old), me_["id"], now_s))
            db.run("INSERT INTO schedules(user_id,effective_from,pattern,updated_by,updated_at) VALUES (?,?,?,?,?) "
                   "ON CONFLICT(user_id,effective_from) DO UPDATE SET pattern=excluded.pattern, updated_by=excluded.updated_by, updated_at=excluded.updated_at",
                   (uid, ws.isoformat(), json.dumps(pat), me_["id"], now_s))
            changes.append({"user_id": uid, "before": [old[(ws + timedelta(days=i)).weekday()] for i in range(7)],
                            "after": pat_in})
        if changes:
            audit("schedule_updated", "schedule", ws.isoformat(), {"mode": mode, "changes": changes})
    if changes:
        publish("schedule")
    return jsonify({"ok": True, "changed": len(changes)})


# ------------------------------------------------------------------ attendance
def check_gps(d, action):
    st = L.settings()
    if not st["gps_required"]:
        out = {}
        for k in ("lat", "lng", "accuracy"):
            try:
                out[k] = float(d[k]) if d.get(k) is not None else None
            except (TypeError, ValueError):
                out[k] = None
        out["dist"] = None
        if out["lat"] is not None and out["lng"] is not None and st["factory_lat"] != "" and st["factory_lng"] != "":
            out["dist"] = L.haversine_m(out["lat"], out["lng"], float(st["factory_lat"]), float(st["factory_lng"]))
        return out
    if st["factory_lat"] == "" or st["factory_lng"] == "":
        raise ApiError("gps_not_configured", "Factory location has not been configured by the owner", 409)
    try:
        lat, lng = float(d.get("lat")), float(d.get("lng"))
        acc = float(d.get("accuracy")) if d.get("accuracy") is not None else None
    except (TypeError, ValueError):
        raise ApiError("gps_required", "Location is required to record attendance", 400)
    if not (-90 <= lat <= 90 and -180 <= lng <= 180):
        raise ApiError("gps_required", "Location is required to record attendance", 400)
    if acc is not None and acc > float(st["gps_max_accuracy_m"]):
        raise ApiError("gps_inaccurate", "Location accuracy is too low. Move to an open area and retry.", 400,
                       accuracy=round(acc), max=st["gps_max_accuracy_m"])
    dist = L.haversine_m(lat, lng, float(st["factory_lat"]), float(st["factory_lng"]))
    if dist > float(st["gps_radius_m"]):
        raise ApiError("gps_out_of_range", "You are outside the authorized factory area", 403,
                       distance=round(dist), radius=st["gps_radius_m"])
    return {"lat": lat, "lng": lng, "accuracy": acc, "dist": dist}


def resolve_day(uid, ln, sched, shifts):
    """Find which shift-day a punch at local time `ln` belongs to (handles overnight shifts)."""
    early = timedelta(minutes=int(L.settings()["checkin_early_min"]))
    best = None
    for d in (ln.date(), ln.date() - timedelta(days=1)):
        sid = sched.shift(uid, d)
        if not sid:
            continue
        s, e = L.shift_start(d, shifts[sid]), L.shift_end(d, shifts[sid])
        if s - early <= ln <= e:
            score = abs((ln - s).total_seconds())
            if best is None or score < best[0]:
                best = (score, d, sid)
    return (best[1], best[2]) if best else (None, None)


def open_record(uid, nowdt):
    hours = int(L.settings()["max_open_hours"])
    return db.row("SELECT * FROM attendance WHERE user_id=? AND check_in IS NOT NULL AND check_out IS NULL AND check_in>=? "
                  "ORDER BY check_in DESC LIMIT 1", (uid, L.iso(nowdt - timedelta(hours=hours))))


def next_shift_info(uid, ln, sched, shifts):
    for i in range(0, 8):
        d = ln.date() + timedelta(days=i)
        sid = sched.shift(uid, d)
        if sid:
            s = L.shift_start(d, shifts[sid])
            if s > ln:
                return {"date": d.isoformat(), "shift_id": sid, "start": L.iso(s)}
    return None


def today_state(u):
    nowdt = L.now()
    ln = nowdt.astimezone(L.tz())
    shifts, sched, leaves = L.shifts_map(), L.Sched(), L.Leaves(ln.date() - timedelta(days=1), ln.date())
    st = L.settings()
    out = {"now": L.iso(nowdt), "shift": None, "record": None, "state": "no_shift", "shift_date": None,
           "next_shift": next_shift_info(u["id"], ln, sched, shifts)}
    rec = open_record(u["id"], nowdt)
    if rec:
        out.update(state="can_check_out", record=rec, shift_date=rec["shift_date"],
                   shift=shifts.get(rec["shift_id"]))
        return out
    d, sid = resolve_day(u["id"], ln, sched, shifts)
    if d:
        out.update(shift_date=d.isoformat(), shift=shifts[sid])
        r = db.row("SELECT * FROM attendance WHERE user_id=? AND shift_date=?", (u["id"], d.isoformat()))
        if r:
            out.update(state="done", record=r)
        elif leaves.on(u["id"], d):
            out["state"] = "on_leave"
        else:
            out["state"] = "can_check_in"
        return out
    today = ln.date()
    r = db.row("SELECT * FROM attendance WHERE user_id=? AND shift_date=?", (u["id"], today.isoformat()))
    if r:
        out.update(state="done", record=r, shift_date=today.isoformat(), shift=shifts.get(r["shift_id"]))
        return out
    if leaves.on(u["id"], today):
        out["state"] = "on_leave"
        return out
    sid_today = sched.shift(u["id"], today)
    if sid_today:
        s, e = L.shift_start(today, shifts[sid_today]), L.shift_end(today, shifts[sid_today])
        out.update(shift=shifts[sid_today], shift_date=today.isoformat())
        out["state"] = "too_early" if ln < s else "shift_ended"
        return out
    if st["allow_unscheduled"]:
        out.update(state="can_check_in", shift_date=today.isoformat(), unscheduled=True)
    return out


@app.get("/api/attendance/today")
@auth("technician")
def att_today():
    return jsonify(today_state(current_user()))


@app.post("/api/attendance/check-in")
@auth("technician")
def att_checkin():
    u, d = current_user(), body()
    gps = check_gps(d, "in")
    nowdt = L.now()
    ln = nowdt.astimezone(L.tz())
    st = L.settings()
    with db.tx():
        shifts, sched = L.shifts_map(), L.Sched()
        if open_record(u["id"], nowdt):
            raise ApiError("already_checked_in", "You are already checked in. Please check out first.", 409)
        sd, sid = resolve_day(u["id"], ln, sched, shifts)
        if not sd:
            today = ln.date()
            sid_today = sched.shift(u["id"], today)
            if sid_today:
                raise ApiError("outside_shift_window", "Check-in is not available now for your scheduled shift", 409)
            if not st["allow_unscheduled"]:
                raise ApiError("no_shift", "You have no shift scheduled right now", 409)
            sd, sid = today, None
        if L.Leaves(sd, sd).on(u["id"], sd):
            raise ApiError("on_leave", "You are on approved leave on this day", 409)
        if db.row("SELECT 1 FROM attendance WHERE user_id=? AND shift_date=?", (u["id"], sd.isoformat())):
            raise ApiError("already_checked_in", "Attendance for this shift is already recorded", 409)
        late = 0
        if sid:
            late = max(0, int((ln - L.shift_start(sd, shifts[sid])).total_seconds() // 60))
        is_late = int(late > int(st["late_grace_min"]))
        now_s = L.iso(nowdt)
        cur = db.run(
            "INSERT INTO attendance(user_id,shift_date,shift_id,check_in,late_minutes,is_late,in_lat,in_lng,in_dist,in_acc,source,created_at,updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (u["id"], sd.isoformat(), sid, now_s, late, is_late, gps["lat"], gps["lng"], gps["dist"], gps["accuracy"],
             "self", now_s, now_s))
    publish("attendance", u["id"])
    return jsonify({"ok": True, "id": cur.lastrowid, "late": bool(is_late), "late_minutes": late})


@app.post("/api/attendance/check-out")
@auth("technician")
def att_checkout():
    u, d = current_user(), body()
    gps = check_gps(d, "out")
    nowdt = L.now()
    with db.tx():
        rec = open_record(u["id"], nowdt)
        if not rec:
            raise ApiError("not_checked_in", "You have no open check-in", 409)
        gap = (nowdt - L.parse_iso(rec["check_in"])).total_seconds()
        if gap < int(L.settings()["min_punch_gap_sec"]):
            raise ApiError("punch_too_fast", "Please wait a moment before checking out", 429)
        db.run("UPDATE attendance SET check_out=?, out_lat=?, out_lng=?, out_dist=?, out_acc=?, updated_at=? WHERE id=?",
               (L.iso(nowdt), gps["lat"], gps["lng"], gps["dist"], gps["accuracy"], L.iso(nowdt), rec["id"]))
    publish("attendance", u["id"])
    return jsonify({"ok": True})


def rec_public(r):
    if not r:
        return None
    return {k: r[k] for k in ("id", "user_id", "shift_date", "shift_id", "check_in", "check_out", "late_minutes",
                              "is_late", "in_dist", "out_dist", "source", "note")}


def rows_public(rs):
    out = []
    for r in rs:
        rec = r["record"]
        u = r["user"]
        out.append({
            "date": r["date"], "user_id": u["id"], "full_name": u["full_name"], "full_name_ar": u["full_name_ar"],
            "employee_no": u["employee_no"], "shift_id": r["shift_id"], "status": r["status"],
            "leave_type": r["leave_type"], "record": rec_public(rec), "hours": L.rec_hours(rec) if rec else None,
        })
    return out


def _range_args(default_days=30):
    today = L.now().astimezone(L.tz()).date()
    try:
        d2 = date.fromisoformat(request.args["to"]) if request.args.get("to") else today
        d1 = date.fromisoformat(request.args["from"]) if request.args.get("from") else d2 - timedelta(days=default_days)
    except ValueError:
        raise bad("Invalid date")
    if d1 > d2:
        raise bad("Invalid range")
    if (d2 - d1).days > 366:
        raise bad("Range too long (max 366 days)")
    return d1, d2


@app.get("/api/attendance/me")
@auth("technician")
def att_me():
    d1, d2 = _range_args(30)
    u = current_user()
    rs = [r for r in L.day_rows(d1, d2, [u["id"]]) if r["status"] != "na"]
    rs.sort(key=lambda r: r["date"], reverse=True)
    return jsonify({"rows": rows_public(rs)})


@app.get("/api/attendance/records")
@auth(*MANAGERS)
def att_records():
    d1, d2 = _range_args(7)
    uid = request.args.get("user_id")
    sid = request.args.get("shift_id")
    status = request.args.get("status")
    rs = L.day_rows(d1, d2, [ival(uid, "user_id")] if uid else None, ival(sid, "shift_id") if sid else None)
    if status:
        rs = [r for r in rs if r["status"] == status]
    rs = [r for r in rs if r["status"] != "off" or r["record"]]
    rs.sort(key=lambda r: (r["date"], r["user"]["full_name"].lower()), reverse=True)
    return jsonify({"rows": rows_public(rs)})


@app.get("/api/attendance/board")
@auth(*MANAGERS)
def att_board():
    try:
        d = date.fromisoformat(request.args["date"]) if request.args.get("date") else L.now().astimezone(L.tz()).date()
    except ValueError:
        raise bad("Invalid date")
    rs = L.day_rows(d, d)
    return jsonify({"date": d.isoformat(), "rows": rows_public(rs)})


def _recompute_late(rec_in_iso, shift_date, shift_id):
    if not shift_id:
        return 0, 0
    sh = L.shifts_map()[shift_id]
    ln = L.to_local(rec_in_iso)
    late = max(0, int((ln - L.shift_start(shift_date, sh)).total_seconds() // 60))
    return late, int(late > int(L.settings()["late_grace_min"]))


def _need_reason(d):
    r = sval(d, "reason", 500, True)
    if len(r) < 3:
        raise bad("A reason is required", field="reason")
    return r


@app.put("/api/attendance/<int:aid>")
@auth(*MANAGERS, perm="edit_attendance")
def att_edit(aid):
    d = body()
    reason = _need_reason(d)
    with db.tx():
        rec = db.row("SELECT a.*, u.role FROM attendance a JOIN users u ON u.id=a.user_id WHERE a.id=?", (aid,))
        if not rec:
            raise ApiError("not_found", "Record not found", 404)
        cin = local_dt(d, "check_in", True)
        cout = local_dt(d, "check_out", False)
        if cout and cout <= cin:
            raise bad("Check-out must be after check-in", field="check_out")
        ci_iso, co_iso = L.iso(cin), (L.iso(cout) if cout else None)
        late, is_late = _recompute_late(ci_iso, date.fromisoformat(rec["shift_date"]), rec["shift_id"])
        db.run("UPDATE attendance SET check_in=?,check_out=?,late_minutes=?,is_late=?,source='manual',note=?,edited_by=?,updated_at=? WHERE id=?",
               (ci_iso, co_iso, late, is_late, reason, current_user()["id"], db.utcnow_iso(), aid))
        audit("attendance_corrected", "attendance", aid, {
            "user_id": rec["user_id"], "shift_date": rec["shift_date"], "reason": reason,
            "before": {"check_in": rec["check_in"], "check_out": rec["check_out"]},
            "after": {"check_in": ci_iso, "check_out": co_iso}})
    publish("attendance", rec["user_id"])
    return jsonify({"ok": True})


@app.post("/api/attendance/manual")
@auth(*MANAGERS, perm="edit_attendance")
def att_manual():
    d = body()
    reason = _need_reason(d)
    uid = ival(d.get("user_id"), "user_id")
    sd = dval(d, "shift_date")
    if not db.row("SELECT 1 FROM users WHERE id=? AND role='technician'", (uid,)):
        raise bad("Unknown technician", field="user_id")
    cin, cout = local_dt(d, "check_in"), local_dt(d, "check_out", False)
    if cout and cout <= cin:
        raise bad("Check-out must be after check-in", field="check_out")
    sid = d.get("shift_id")
    sid = ival(sid, "shift_id") if sid not in (None, "", 0, "0") else L.Sched().shift(uid, sd) or None
    if sid and sid not in (1, 2, 3):
        raise bad("Invalid shift", field="shift_id")
    with db.tx():
        if db.row("SELECT 1 FROM attendance WHERE user_id=? AND shift_date=?", (uid, sd.isoformat())):
            raise ApiError("duplicate_record", "A record already exists for this date. Edit it instead.", 409)
        late, is_late = _recompute_late(L.iso(cin), sd, sid)
        now_s = db.utcnow_iso()
        cur = db.run(
            "INSERT INTO attendance(user_id,shift_date,shift_id,check_in,check_out,late_minutes,is_late,source,note,edited_by,created_at,updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (uid, sd.isoformat(), sid, L.iso(cin), L.iso(cout) if cout else None, late, is_late, "manual", reason,
             current_user()["id"], now_s, now_s))
        audit("attendance_created", "attendance", cur.lastrowid, {
            "user_id": uid, "shift_date": sd.isoformat(), "reason": reason,
            "after": {"check_in": L.iso(cin), "check_out": L.iso(cout) if cout else None}})
    publish("attendance", uid)
    return jsonify({"ok": True, "id": cur.lastrowid}), 201


@app.delete("/api/attendance/<int:aid>")
@auth("owner")
def att_delete(aid):
    d = body()
    reason = _need_reason(d)
    rec = db.row("SELECT * FROM attendance WHERE id=?", (aid,))
    if not rec:
        raise ApiError("not_found", "Record not found", 404)
    with db.tx():
        db.run("DELETE FROM attendance WHERE id=?", (aid,))
        audit("attendance_deleted", "attendance", aid, {"reason": reason, "record": rec})
    publish("attendance", rec["user_id"])
    return jsonify({"ok": True})


@app.get("/api/attendance/<int:aid>/audit")
@auth(*MANAGERS)
def att_audit(aid):
    return jsonify({"rows": db.rows("SELECT * FROM audit_log WHERE entity='attendance' AND entity_id=? ORDER BY id DESC", (str(aid),))})


# ------------------------------------------------------------------ leave
def type_public(t):
    return {k: t[k] for k in ("id", "name", "name_ar", "deducts", "active")}


@app.get("/api/leave/types")
@auth()
def lt_list():
    sql = "SELECT * FROM leave_types"
    if current_user()["role"] == "technician":
        sql += " WHERE active=1"
    return jsonify({"types": [type_public(t) for t in db.rows(sql + " ORDER BY id")]})


@app.post("/api/leave/types")
@auth("owner")
def lt_create():
    d = body()
    cur = db.run("INSERT INTO leave_types(name,name_ar,deducts,active) VALUES (?,?,?,1)",
                 (sval(d, "name", 60, True), sval(d, "name_ar", 60), int(bool(d.get("deducts", True)))))
    audit("leave_type_created", "leave_type", cur.lastrowid, d)
    return jsonify({"id": cur.lastrowid}), 201


@app.put("/api/leave/types/<int:tid>")
@auth("owner")
def lt_update(tid):
    t = db.row("SELECT * FROM leave_types WHERE id=?", (tid,))
    if not t:
        raise ApiError("not_found", "Not found", 404)
    d = body()
    new = (sval(d, "name", 60, True, t["name"]), sval(d, "name_ar", 60, False, t["name_ar"]),
           int(bool(d.get("deducts", t["deducts"]))), int(bool(d.get("active", t["active"]))))
    db.run("UPDATE leave_types SET name=?,name_ar=?,deducts=?,active=? WHERE id=?", (*new, tid))
    audit("leave_type_updated", "leave_type", tid, {"before": type_public(t), "after": dict(zip(("name", "name_ar", "deducts", "active"), new))})
    return jsonify({"ok": True})


@app.get("/api/leave/balance")
@auth("technician")
def my_balance():
    u = current_user()
    year = int(request.args.get("year") or L.now().astimezone(L.tz()).year)
    return jsonify({"balance": L.balance(u["id"], year)})


@app.get("/api/leave/balances")
@auth(*MANAGERS)
def balances_list():
    year = int(request.args.get("year") or L.now().astimezone(L.tz()).year)
    users = db.rows("SELECT * FROM users WHERE role='technician' AND active=1 ORDER BY full_name COLLATE NOCASE")
    out = []
    for u in users:
        b = L.balance(u["id"], year)
        b.update(full_name=u["full_name"], full_name_ar=u["full_name_ar"], employee_no=u["employee_no"])
        out.append(b)
    return jsonify({"year": year, "balances": out})


@app.put("/api/leave/balances/<int:uid>")
@auth(*MANAGERS, perm="manage_balances")
def balance_set(uid):
    t = get_target_user(uid)
    if t["role"] != "technician":
        raise bad("Balances apply to technicians only")
    d = body()
    year = ival(d.get("year"), "year")
    try:
        total = float(d.get("total"))
    except (TypeError, ValueError):
        raise bad("Invalid total", field="total")
    if not 0 <= total <= 366 or not 2000 <= year <= 2100:
        raise bad("Invalid value", field="total")
    reason = sval(d, "reason", 300)
    old = L.year_total(uid, year)
    with db.tx():
        db.run("INSERT INTO leave_balances(user_id,year,total,updated_by,updated_at) VALUES (?,?,?,?,?) "
               "ON CONFLICT(user_id,year) DO UPDATE SET total=excluded.total, updated_by=excluded.updated_by, updated_at=excluded.updated_at",
               (uid, year, total, current_user()["id"], db.utcnow_iso()))
        audit("leave_balance_set", "user", uid, {"year": year, "before": old, "after": total, "reason": reason})
    publish("leave", uid)
    return jsonify({"ok": True})


def req_public(r):
    return {k: r[k] for k in ("id", "user_id", "type_id", "start_date", "end_date", "days", "reason", "status",
                              "decided_by", "decided_at", "decision_comment", "created_at")}


@app.get("/api/leave/calc")
@auth("technician")
def leave_calc():
    u = current_user()
    s, e = dval(request.args, "start"), dval(request.args, "end")
    if e < s:
        raise bad("End date must not be before start date")
    if (e - s).days > 366:
        raise bad("Leave period too long")
    total, by_year = L.count_days(u["id"], s, e)
    return jsonify({"days": total, "by_year": by_year})


@app.post("/api/leave/requests")
@auth("technician")
def leave_create():
    u, d = current_user(), body()
    s, e = dval(d, "start_date"), dval(d, "end_date")
    if e < s:
        raise ApiError("invalid_range", "End date must not be before start date", 400)
    if (e - s).days > 366:
        raise ApiError("invalid_range", "Leave period too long", 400)
    today = L.now().astimezone(L.tz()).date()
    if s < today - timedelta(days=int(L.settings()["leave_past_days_allowed"])):
        raise ApiError("date_in_past", "Start date is too far in the past", 400)
    t = db.row("SELECT * FROM leave_types WHERE id=? AND active=1", (ival(d.get("type_id"), "type_id"),))
    if not t:
        raise bad("Invalid leave type", field="type_id")
    reason = sval(d, "reason", 500)
    with db.tx():
        total, by_year = L.count_days(u["id"], s, e)
        if total <= 0:
            raise ApiError("no_working_days", "The selected period has no working days", 400)
        if db.row("SELECT 1 FROM leave_requests WHERE user_id=? AND status IN ('pending','approved') AND start_date<=? AND end_date>=?",
                  (u["id"], e.isoformat(), s.isoformat())):
            raise ApiError("overlap", "This period overlaps with another leave request", 409)
        if t["deducts"]:
            for y, n in by_year.items():
                b = L.balance(u["id"], y)
                if n > b["remaining"] - b["pending"] + 1e-9:
                    raise ApiError("insufficient_balance", "Insufficient leave balance", 409,
                                   available=b["remaining"] - b["pending"], requested=n, year=y)
        cur = db.run(
            "INSERT INTO leave_requests(user_id,type_id,start_date,end_date,days,days_by_year,reason,status,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (u["id"], t["id"], s.isoformat(), e.isoformat(), total, json.dumps({str(k): v for k, v in by_year.items()}),
             reason, "pending", db.utcnow_iso()))
        audit("leave_requested", "leave_request", cur.lastrowid, {"start": s.isoformat(), "end": e.isoformat(), "days": total})
    publish("leave", u["id"])
    return jsonify({"id": cur.lastrowid, "days": total}), 201


@app.get("/api/leave/requests")
@auth()
def leave_list():
    u = current_user()
    sql = ("SELECT r.*, x.full_name, x.full_name_ar, x.employee_no, t.name type_name, t.name_ar type_name_ar, t.deducts, "
           "dx.full_name decided_by_name FROM leave_requests r JOIN users x ON x.id=r.user_id JOIN leave_types t ON t.id=r.type_id "
           "LEFT JOIN users dx ON dx.id=r.decided_by WHERE 1=1")
    args = []
    if u["role"] == "technician":
        sql += " AND r.user_id=?"; args.append(u["id"])
    else:
        if request.args.get("user_id"):
            sql += " AND r.user_id=?"; args.append(ival(request.args["user_id"], "user_id"))
    if request.args.get("status") in ("pending", "approved", "rejected", "cancelled"):
        sql += " AND r.status=?"; args.append(request.args["status"])
    sql += " ORDER BY CASE r.status WHEN 'pending' THEN 0 ELSE 1 END, r.start_date DESC, r.id DESC LIMIT 500"
    out = []
    for r in db.rows(sql, args):
        x = req_public(r)
        x.update(full_name=r["full_name"], full_name_ar=r["full_name_ar"], employee_no=r["employee_no"],
                 type_name=r["type_name"], type_name_ar=r["type_name_ar"], deducts=r["deducts"],
                 decided_by_name=r["decided_by_name"])
        if u["role"] == "technician":
            x.pop("decided_by", None)
        out.append(x)
    return jsonify({"requests": out})


@app.post("/api/leave/requests/<int:rid>/cancel")
@auth("technician")
def leave_cancel(rid):
    u = current_user()
    with db.tx():
        r = db.row("SELECT * FROM leave_requests WHERE id=? AND user_id=?", (rid, u["id"]))
        if not r:
            raise ApiError("not_found", "Request not found", 404)
        if r["status"] != "pending":
            raise ApiError("request_not_pending", "Only pending requests can be cancelled", 409)
        db.run("UPDATE leave_requests SET status='cancelled', decided_at=? WHERE id=?", (db.utcnow_iso(), rid))
        audit("leave_cancelled", "leave_request", rid)
    publish("leave", u["id"])
    return jsonify({"ok": True})


@app.post("/api/leave/requests/<int:rid>/decide")
@auth(*MANAGERS, perm="approve_leave")
def leave_decide(rid):
    me_, d = current_user(), body()
    decision = d.get("decision")
    if decision not in ("approve", "reject"):
        raise bad("Invalid decision", field="decision")
    comment = sval(d, "comment", 500)
    if decision == "reject" and not comment:
        raise ApiError("comment_required", "A comment is required when rejecting", 400)
    override = bool(d.get("override")) and me_["role"] == "owner"
    new_status = "approved" if decision == "approve" else "rejected"
    with db.tx():
        r = db.row("SELECT r.*, t.deducts FROM leave_requests r JOIN leave_types t ON t.id=r.type_id WHERE r.id=?", (rid,))
        if not r:
            raise ApiError("not_found", "Request not found", 404)
        if r["status"] == "cancelled":
            raise ApiError("request_not_pending", "This request was cancelled", 409)
        if r["status"] != "pending" and me_["role"] != "owner":
            raise ApiError("request_not_pending", "This request has already been decided", 409)
        if r["status"] == new_status:
            raise ApiError("request_not_pending", f"Request is already {new_status}", 409)
        if new_status == "approved":
            if db.row("SELECT 1 FROM leave_requests WHERE user_id=? AND id<>? AND status IN ('approved','pending') AND start_date<=? AND end_date>=?",
                      (r["user_id"], rid, r["end_date"], r["start_date"])):
                raise ApiError("overlap", "This period overlaps with another leave request", 409)
            if r["deducts"] and not override:
                for y, n in json.loads(r["days_by_year"]).items():
                    b = L.balance(r["user_id"], int(y))
                    avail = b["remaining"]
                    if n > avail + 1e-9:
                        raise ApiError("insufficient_balance", "Insufficient leave balance", 409,
                                       available=avail, requested=n, year=int(y))
        db.run("UPDATE leave_requests SET status=?, decided_by=?, decided_at=?, decision_comment=? WHERE id=?",
               (new_status, me_["id"], db.utcnow_iso(), comment, rid))
        audit("leave_" + new_status, "leave_request", rid,
              {"user_id": r["user_id"], "previous": r["status"], "comment": comment, "override": override,
               "days": r["days"]})
    publish("leave", r["user_id"])
    return jsonify({"ok": True})


# ------------------------------------------------------------------ dashboard
@app.get("/api/dashboard")
@auth(*MANAGERS)
def dashboard():
    nowdt = L.now()
    today = nowdt.astimezone(L.tz()).date()
    users_all = db.rows("SELECT id FROM users WHERE role='technician' AND active=1")
    rs = L.day_rows(today - timedelta(days=6), today)
    shifts = L.shifts_map()
    todays = [r for r in rs if r["date"] == today.isoformat()]
    cnt = defaultdict(int)
    dist = defaultdict(int)
    for r in todays:
        cnt[r["status"]] += 1
        if r["shift_id"]:
            dist[r["shift_id"]] += 1
    checked = cnt["present"] + cnt["late"]
    due = checked + cnt["absent"] + cnt["pending"]
    trend = []
    for i in range(6, -1, -1):
        ds = (today - timedelta(days=i)).isoformat()
        c = defaultdict(int)
        for r in rs:
            if r["date"] == ds:
                c[r["status"]] += 1
        trend.append({"date": ds, "present": c["present"], "late": c["late"], "absent": c["absent"], "leave": c["leave"]})
    pend = db.row("SELECT COUNT(*) c FROM leave_requests WHERE status='pending'")["c"]
    return jsonify({
        "date": today.isoformat(), "total_technicians": len(users_all),
        "present": checked, "on_time": cnt["present"], "late": cnt["late"], "absent": cnt["absent"], "leave": cnt["leave"],
        "off": cnt["off"], "expected": cnt["upcoming"] + cnt["pending"],
        "attendance_pct": round(100 * checked / due, 1) if due else None,
        "pending_leave": pend,
        "shift_distribution": [{"shift_id": s, "count": dist[s]} for s in sorted(shifts)] + [{"shift_id": 0, "count": cnt["off"]}],
        "trend": trend, "people": rows_public(todays),
    })


# ------------------------------------------------------------------ reports
@app.get("/api/reports/<name>")
@auth(*MANAGERS, perm="view_reports")
def report(name):
    if name not in reports.REPORT_NAMES:
        raise ApiError("not_found", "Unknown report", 404)
    fmt = request.args.get("format", "json")
    lang = request.args.get("lang", "en")
    try:
        rep = reports.generate(name, request.args, lang)
    except reports.ReportError as e:
        raise ApiError(e.code, e.msg, 400 if e.code == "validation" else 404)
    except ValueError as e:
        raise bad(str(e))
    if fmt == "json":
        return jsonify(rep)
    company = L.settings()["company_name_ar" if rep["lang"] == "ar" else "company_name"] or L.settings()["company_name"]
    stamp = L.now().astimezone(L.tz()).strftime("%Y%m%d-%H%M")
    audit("report_exported", "report", name, {"format": fmt, "params": dict(request.args)})
    if fmt == "xlsx":
        data = reports.to_xlsx(rep, company)
        return Response(data, mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        headers={"Content-Disposition": f'attachment; filename="afh-{name}-{stamp}.xlsx"'})
    if fmt == "pdf":
        data = reports.to_pdf(rep, company)
        return Response(data, mimetype="application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="afh-{name}-{stamp}.pdf"'})
    raise bad("Unknown format")


# ------------------------------------------------------------------ audit log
@app.get("/api/audit")
@auth("owner")
def audit_list():
    limit = min(int(request.args.get("limit", 100)), 500)
    offset = max(int(request.args.get("offset", 0)), 0)
    sql, args = "SELECT * FROM audit_log WHERE 1=1", []
    for k, col in (("action", "action"), ("entity", "entity")):
        if request.args.get(k):
            sql += f" AND {col}=?"; args.append(request.args[k])
    if request.args.get("q"):
        like = f"%{request.args['q']}%"
        sql += " AND (actor_name LIKE ? OR details LIKE ? OR action LIKE ? OR entity_id LIKE ?)"
        args += [like] * 4
    total = db.row("SELECT COUNT(*) c FROM (" + sql + ")", args)["c"]
    rs = db.rows(sql + " ORDER BY id DESC LIMIT ? OFFSET ?", (*args, limit, offset))
    return jsonify({"total": total, "rows": rs})


# ------------------------------------------------------------------ backups
BACKUP_RE = re.compile(r"^afh-\d{8}-\d{6}\.db$")


def make_backup():
    os.makedirs(db.BACKUP_DIR, exist_ok=True)
    name = "afh-" + datetime.now().strftime("%Y%m%d-%H%M%S") + ".db"
    path = os.path.join(db.BACKUP_DIR, name)
    src = sqlite3.connect(db.DB_PATH)
    dst = sqlite3.connect(path)
    try:
        src.backup(dst)
    finally:
        dst.close(); src.close()
    keep = 30
    try:
        c = db.connect()
        r = c.execute("SELECT value FROM settings WHERE key='backup_keep'").fetchone()
        keep = int(json.loads(r[0])) if r else 30
        c.close()
    except Exception:
        pass
    files = sorted(f for f in os.listdir(db.BACKUP_DIR) if BACKUP_RE.match(f))
    for f in files[:-keep]:
        try:
            os.remove(os.path.join(db.BACKUP_DIR, f))
        except OSError:
            pass
    return name


def list_backups():
    os.makedirs(db.BACKUP_DIR, exist_ok=True)
    out = []
    for f in sorted((f for f in os.listdir(db.BACKUP_DIR) if BACKUP_RE.match(f)), reverse=True):
        p = os.path.join(db.BACKUP_DIR, f)
        out.append({"name": f, "size": os.path.getsize(p), "created": datetime.fromtimestamp(os.path.getmtime(p), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")})
    return out


@app.get("/api/backups")
@auth("owner")
def backups_list():
    return jsonify({"backups": list_backups()})


@app.post("/api/backups")
@auth("owner")
def backups_create():
    name = make_backup()
    audit("backup_created", "backup", name)
    return jsonify({"name": name}), 201


@app.get("/api/backups/<name>")
@auth("owner")
def backups_download(name):
    if not BACKUP_RE.match(name) or not os.path.exists(os.path.join(db.BACKUP_DIR, name)):
        raise ApiError("not_found", "Backup not found", 404)
    audit("backup_downloaded", "backup", name)
    return send_from_directory(db.BACKUP_DIR, name, as_attachment=True)


_bg_started = False


def backup_loop():
    while True:
        try:
            c = db.connect()
            r = c.execute("SELECT value FROM settings WHERE key='backup_interval_hours'").fetchone()
            hours = int(json.loads(r[0])) if r else 24
            c.close()
            files = list_backups()
            last = max((datetime.strptime(f["created"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) for f in files), default=None)
            if last is None or datetime.now(timezone.utc) - last >= timedelta(hours=hours):
                make_backup()
        except Exception:
            app.logger.exception("Automatic backup failed")
        _time.sleep(300)


def start_background():
    global _bg_started
    if _bg_started or os.environ.get("AFH_NO_BG") == "1":
        return
    _bg_started = True
    threading.Thread(target=backup_loop, daemon=True, name="backup").start()


# ------------------------------------------------------------------ static / PWA
@app.get("/")
def index():
    r = send_from_directory(STATIC, "index.html")
    r.headers["Cache-Control"] = "no-cache"
    return r


@app.get("/sw.js")
def sw():
    r = send_from_directory(STATIC, "sw.js", mimetype="application/javascript")
    r.headers["Cache-Control"] = "no-cache"
    r.headers["Service-Worker-Allowed"] = "/"
    return r


@app.get("/manifest.webmanifest")
def manifest():
    return send_from_directory(STATIC, "manifest.webmanifest", mimetype="application/manifest+json")


@app.get("/static/<path:p>")
def static_files(p):
    r = send_from_directory(STATIC, p)
    r.headers["Cache-Control"] = "no-cache"
    return r


db.init_db()
start_background()
