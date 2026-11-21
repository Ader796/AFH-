"""Business logic: settings, time, schedules, attendance status, leave maths."""
import json
import math
from collections import defaultdict
from datetime import date, datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo

from flask import g, has_app_context, request

import db

TESTING = False  # set by app when AFH_TESTING=1


# ---------------------------------------------------------------- settings / time
def settings():
    if has_app_context() and "settings" in g:
        return g.settings
    out = dict(db.DEFAULT_SETTINGS)
    for r in db.rows("SELECT key,value FROM settings"):
        try:
            out[r["key"]] = json.loads(r["value"])
        except ValueError:
            pass
    if has_app_context():
        g.settings = out
    return out


def invalidate_settings():
    if has_app_context():
        g.pop("settings", None)


def tz():
    try:
        return ZoneInfo(settings()["timezone"])
    except Exception:
        return timezone.utc


def now():
    """Current aware UTC datetime (overridable via header in test mode only)."""
    if TESTING and has_app_context():
        h = request.headers.get("X-Test-Now")
        if h:
            return datetime.strptime(h, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def to_local(s):
    return parse_iso(s).astimezone(tz())


def parse_local(s):
    """'YYYY-MM-DDTHH:MM[:SS]' interpreted in factory time zone -> aware datetime."""
    s = s.replace(" ", "T")
    fmt = "%Y-%m-%dT%H:%M:%S" if s.count(":") == 2 else "%Y-%m-%dT%H:%M"
    return datetime.strptime(s, fmt).replace(tzinfo=tz())


def fmt_local(s, with_date=False):
    if not s:
        return ""
    d = to_local(s)
    return d.strftime("%Y-%m-%d %H:%M") if with_date else d.strftime("%H:%M")


def parse_hhmm(s):
    h, m = s.split(":")
    return time(int(h), int(m))


def shifts_map():
    return {s["id"]: s for s in db.rows("SELECT * FROM shifts ORDER BY id")}


def shift_start(d, shift):
    return datetime.combine(d, parse_hhmm(shift["start_time"]), tzinfo=tz())


def shift_end(d, shift):
    s = shift_start(d, shift)
    e = datetime.combine(d, parse_hhmm(shift["end_time"]), tzinfo=tz())
    if e <= s:
        e += timedelta(days=1)
    return e


def d2s(d):
    return d.isoformat()


def s2d(s):
    return date.fromisoformat(s)


def week_start_of(d):
    wsd = int(settings()["week_start_day"])
    return d - timedelta(days=(d.weekday() - wsd) % 7)


# ---------------------------------------------------------------- GPS
def haversine_m(lat1, lng1, lat2, lng2):
    r = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lng2 - lng1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


# ---------------------------------------------------------------- schedule index
class Sched:
    def __init__(self):
        self.m = defaultdict(list)
        for r in db.rows("SELECT user_id,effective_from,pattern FROM schedules ORDER BY user_id,effective_from"):
            self.m[r["user_id"]].append((s2d(r["effective_from"]), json.loads(r["pattern"])))

    def pattern(self, uid, d):
        p = None
        for eff, pat in self.m.get(uid, []):
            if eff <= d:
                p = pat
            else:
                break
        return p

    def shift(self, uid, d):
        p = self.pattern(uid, d)
        return int(p[d.weekday()]) if p else 0

    def has_any(self, uid):
        return bool(self.m.get(uid))


class Leaves:
    """Approved leave lookup."""
    def __init__(self, d_from=None, d_to=None):
        sql = "SELECT r.user_id,r.start_date,r.end_date,r.type_id FROM leave_requests r WHERE r.status='approved'"
        args = []
        if d_from:
            sql += " AND r.end_date>=?"; args.append(d2s(d_from))
        if d_to:
            sql += " AND r.start_date<=?"; args.append(d2s(d_to))
        self.m = defaultdict(list)
        for r in db.rows(sql, args):
            self.m[r["user_id"]].append((r["start_date"], r["end_date"], r["type_id"]))

    def on(self, uid, d):
        ds = d2s(d)
        for s, e, t in self.m.get(uid, []):
            if s <= ds <= e:
                return t
        return None


def technicians(d_from, d_to, user_ids=None, include_with_records=True):
    """Active technicians + inactive ones that have records in range."""
    sql = "SELECT * FROM users WHERE role='technician'"
    args = []
    if user_ids is not None:
        sql += " AND id IN (%s)" % ",".join("?" * len(user_ids)) if user_ids else " AND 0"
        args += list(user_ids)
    users = db.rows(sql + " ORDER BY full_name COLLATE NOCASE", args)
    have = {r["user_id"] for r in db.rows(
        "SELECT DISTINCT user_id FROM attendance WHERE shift_date BETWEEN ? AND ?", (d2s(d_from), d2s(d_to)))}
    out = []
    for u in users:
        if u["active"] or (include_with_records and u["id"] in have):
            out.append(u)
    return out


def day_status(att, sched, leaves, shifts, u, d, now_local):
    """Compute the status of technician u on shift-day d."""
    st = settings()
    ds = d2s(d)
    rec = att.get((u["id"], ds))
    sid = sched.shift(u["id"], d)
    out = {"date": ds, "user_id": u["id"], "shift_id": sid, "record": rec, "status": "off", "leave_type": None}
    if rec and rec["check_in"]:
        out["status"] = "late" if rec["is_late"] else "present"
        out["shift_id"] = rec["shift_id"] or sid
        return out
    if ds < u["start_date"]:
        out["status"] = "na"
        return out
    lt = leaves.on(u["id"], d)
    if lt:
        out["status"], out["leave_type"] = "leave", lt
        return out
    if not sid:
        return out
    s = shift_start(d, shifts[sid])
    if now_local < s:
        out["status"] = "upcoming"
    elif now_local < s + timedelta(minutes=int(st["absent_after_min"])):
        out["status"] = "pending"
    else:
        out["status"] = "absent"
    return out


def load_attendance(d_from, d_to, user_ids=None):
    sql = "SELECT * FROM attendance WHERE shift_date BETWEEN ? AND ?"
    args = [d2s(d_from), d2s(d_to)]
    if user_ids:
        sql += " AND user_id IN (%s)" % ",".join("?" * len(user_ids)); args += list(user_ids)
    return {(r["user_id"], r["shift_date"]): r for r in db.rows(sql, args)}


def day_rows(d_from, d_to, user_ids=None, shift_id=None):
    """One row per technician per day with computed status."""
    if (d_to - d_from).days > 400:
        raise ValueError("range_too_long")
    users = technicians(d_from, d_to, user_ids)
    att = load_attendance(d_from, d_to, [u["id"] for u in users] or None)
    sched, leaves, shifts = Sched(), Leaves(d_from, d_to), shifts_map()
    nl = now().astimezone(tz())
    out = []
    d = d_from
    while d <= d_to:
        for u in users:
            r = day_status(att, sched, leaves, shifts, u, d, nl)
            if r["status"] == "na":
                continue
            if shift_id and r["shift_id"] != shift_id:
                continue
            r["user"] = u
            out.append(r)
        d += timedelta(days=1)
    return out


def rec_hours(rec):
    if rec and rec["check_in"] and rec["check_out"]:
        return round((parse_iso(rec["check_out"]) - parse_iso(rec["check_in"])).total_seconds() / 3600, 2)
    return None


# ---------------------------------------------------------------- leave maths
def count_days(uid, start, end, sched=None):
    """Return (total, {year: days}) according to leave_count_mode."""
    mode = settings()["leave_count_mode"]
    sched = sched or Sched()
    use_working = mode == "working" and sched.has_any(uid)
    by_year, total = defaultdict(float), 0.0
    d = start
    while d <= end:
        if not use_working or sched.shift(uid, d):
            by_year[d.year] += 1
            total += 1
        d += timedelta(days=1)
    return total, dict(by_year)


def year_total(uid, year):
    r = db.row("SELECT total FROM leave_balances WHERE user_id=? AND year=?", (uid, year))
    return float(r["total"]) if r else float(settings()["annual_leave_days"])


def used_days(uid, year, statuses=("approved",), exclude_id=None):
    sql = ("SELECT r.days_by_year FROM leave_requests r JOIN leave_types t ON t.id=r.type_id "
           "WHERE r.user_id=? AND t.deducts=1 AND r.status IN (%s)" % ",".join("?" * len(statuses)))
    args = [uid, *statuses]
    if exclude_id:
        sql += " AND r.id<>?"; args.append(exclude_id)
    n = 0.0
    for r in db.rows(sql, args):
        n += float(json.loads(r["days_by_year"]).get(str(year), 0))
    return n


def balance(uid, year):
    total = year_total(uid, year)
    used = used_days(uid, year)
    pending = used_days(uid, year, ("pending",))
    return {"user_id": uid, "year": year, "total": total, "used": used, "pending": pending,
            "remaining": total - used}
