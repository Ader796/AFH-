"""Report generation (JSON / Excel / PDF)."""
import io
import json
from datetime import date, datetime, timedelta

import db
import logic as L
from arabic import visual

LBL = {
    "en": {
        "date": "Date", "day": "Day", "emp_no": "Emp. No.", "name": "Name", "shift": "Shift", "status": "Status",
        "check_in": "Check-in", "check_out": "Check-out", "hours": "Hours", "late_min": "Late (min)",
        "scheduled": "Scheduled days", "present": "Present", "late": "Late", "absent": "Absent", "leave": "On leave",
        "off": "Day off", "upcoming": "Upcoming", "pending": "Awaiting arrival", "att_pct": "Attendance %",
        "type": "Type", "from": "From", "to": "To", "days": "Days", "reason": "Reason", "decided_by": "Decided by",
        "comment": "Comment", "total": "Total", "used": "Used", "remaining": "Remaining", "pending_days": "Pending",
        "year": "Year", "shift_name": "Shift",
        "wd0": "Mon", "wd1": "Tue", "wd2": "Wed", "wd3": "Thu", "wd4": "Fri", "wd5": "Sat", "wd6": "Sun",
        "r_daily": "Daily attendance report", "r_monthly": "Monthly attendance report",
        "r_history": "Employee attendance history", "r_absence": "Absence report", "r_late": "Late arrivals report",
        "r_leave_history": "Leave history", "r_leave_balances": "Leave balances", "r_shifts": "Shift assignments",
        "generated": "Generated", "page": "Page", "approved": "Approved", "rejected": "Rejected",
        "cancelled": "Cancelled", "all": "All",
    },
    "ar": {
        "date": "التاريخ", "day": "اليوم", "emp_no": "رقم الموظف", "name": "الاسم", "shift": "الوردية", "status": "الحالة",
        "check_in": "تسجيل الحضور", "check_out": "تسجيل الانصراف", "hours": "الساعات", "late_min": "التأخير (دقيقة)",
        "scheduled": "أيام العمل", "present": "حاضر", "late": "متأخر", "absent": "غائب", "leave": "في إجازة",
        "off": "يوم راحة", "upcoming": "قادم", "pending": "في انتظار الوصول", "att_pct": "نسبة الحضور",
        "type": "النوع", "from": "من", "to": "إلى", "days": "الأيام", "reason": "السبب", "decided_by": "القرار بواسطة",
        "comment": "ملاحظة", "total": "الإجمالي", "used": "المستخدم", "remaining": "المتبقي", "pending_days": "قيد الانتظار",
        "year": "السنة", "shift_name": "الوردية",
        "wd0": "الإثنين", "wd1": "الثلاثاء", "wd2": "الأربعاء", "wd3": "الخميس", "wd4": "الجمعة", "wd5": "السبت", "wd6": "الأحد",
        "r_daily": "تقرير الحضور اليومي", "r_monthly": "تقرير الحضور الشهري",
        "r_history": "سجل حضور الموظف", "r_absence": "تقرير الغياب", "r_late": "تقرير التأخير",
        "r_leave_history": "سجل الإجازات", "r_leave_balances": "أرصدة الإجازات", "r_shifts": "توزيع الورديات",
        "generated": "تاريخ الإنشاء", "page": "صفحة", "approved": "موافق عليها", "rejected": "مرفوضة",
        "cancelled": "ملغاة", "all": "الكل",
    },
}

REPORT_NAMES = ["daily", "monthly", "history", "absence", "late", "leave_history", "leave_balances", "shifts"]


class ReportError(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code, self.msg = code, msg


def _name(u, lang):
    return (u["full_name_ar"] if lang == "ar" and u["full_name_ar"] else u["full_name"])


def _shift_name(shifts, sid, lang):
    s = shifts.get(sid)
    if not s:
        return ""
    return s["name_ar"] if lang == "ar" and s["name_ar"] else s["name"]


def _d(params, key, default=None):
    v = params.get(key)
    if not v:
        return default
    try:
        return date.fromisoformat(v)
    except ValueError:
        raise ReportError("validation", f"Invalid {key}")


def _int(params, key):
    v = params.get(key)
    if v in (None, "", "0", "all"):
        return None
    try:
        return int(v)
    except ValueError:
        raise ReportError("validation", f"Invalid {key}")


def generate(name, params, lang="en"):
    lang = "ar" if lang == "ar" else "en"
    T = LBL[lang]
    shifts = L.shifts_map()
    uid, sid = _int(params, "user_id"), _int(params, "shift_id")
    uids = [uid] if uid else None
    today = L.now().astimezone(L.tz()).date()
    meta = []
    if uid:
        u = db.row("SELECT * FROM users WHERE id=? AND role='technician'", (uid,))
        if not u:
            raise ReportError("not_found", "Employee not found")
        meta.append(_name(u, lang))
    if sid and sid in shifts:
        meta.append(_shift_name(shifts, sid, lang))

    def status_lbl(r):
        return T.get(r["status"], r["status"])

    def row_of(r):
        rec, u = r["record"], r["user"]
        d = date.fromisoformat(r["date"])
        return {
            "date": r["date"], "day": T[f"wd{d.weekday()}"], "emp_no": u["employee_no"], "name": _name(u, lang),
            "shift": _shift_name(shifts, r["shift_id"], lang), "status": status_lbl(r),
            "check_in": L.fmt_local(rec["check_in"]) if rec else "",
            "check_out": L.fmt_local(rec["check_out"]) if rec else "",
            "hours": L.rec_hours(rec) if rec else "", "late_min": (rec["late_minutes"] if rec and rec["is_late"] else ""),
        }

    cols_day = ["date", "day", "emp_no", "name", "shift", "status", "check_in", "check_out", "hours", "late_min"]

    if name == "daily":
        d = _d(params, "date", today)
        rs = L.day_rows(d, d, uids, sid)
        title, cols, data = T["r_daily"], cols_day, [row_of(r) for r in rs]
        meta.insert(0, d.isoformat())
    elif name in ("monthly",):
        m = params.get("month") or today.strftime("%Y-%m")
        try:
            y, mo = int(m[:4]), int(m[5:7])
            d1 = date(y, mo, 1)
        except (ValueError, IndexError):
            raise ReportError("validation", "Invalid month")
        d2 = (date(y + (mo == 12), (mo % 12) + 1, 1) - timedelta(days=1))
        rs = L.day_rows(d1, min(d2, d2), uids, sid)
        agg = {}
        for r in rs:
            u = r["user"]
            a = agg.setdefault(u["id"], {"emp_no": u["employee_no"], "name": _name(u, lang), "scheduled": 0,
                                         "present": 0, "late": 0, "absent": 0, "leave": 0, "hours": 0.0, "late_min": 0})
            st = r["status"]
            if st in ("present", "late"):
                a["scheduled"] += 1 if r["shift_id"] else 0
                a["present"] += 1
                a["hours"] += L.rec_hours(r["record"]) or 0
                if st == "late":
                    a["late"] += 1
                    a["late_min"] += r["record"]["late_minutes"]
            elif st == "absent":
                a["scheduled"] += 1; a["absent"] += 1
            elif st == "leave":
                a["leave"] += 1
            elif st in ("upcoming", "pending"):
                pass
        for a in agg.values():
            a["hours"] = round(a["hours"], 2)
            due = a["present"] + a["absent"]
            a["att_pct"] = round(100 * a["present"] / due, 1) if due else ""
        title = T["r_monthly"]
        cols = ["emp_no", "name", "scheduled", "present", "late", "absent", "leave", "hours", "late_min", "att_pct"]
        data = sorted(agg.values(), key=lambda x: x["name"])
        meta.insert(0, m)
    elif name in ("history", "absence", "late"):
        d1, d2 = _d(params, "date_from"), _d(params, "date_to")
        if not d1 or not d2:
            d2 = d2 or today
            d1 = d1 or (d2 - timedelta(days=30))
        if d1 > d2:
            raise ReportError("validation", "Invalid range")
        if name == "history" and not uid:
            raise ReportError("validation", "Select an employee")
        try:
            rs = L.day_rows(d1, d2, uids, sid)
        except ValueError:
            raise ReportError("validation", "Range too long (max 400 days)")
        if name == "absence":
            rs = [r for r in rs if r["status"] == "absent"]
        elif name == "late":
            rs = [r for r in rs if r["status"] == "late"]
        elif name == "history":
            rs = [r for r in rs if r["status"] != "off" or r["record"]]
        title = {"history": T["r_history"], "absence": T["r_absence"], "late": T["r_late"]}[name]
        cols = cols_day
        data = [row_of(r) for r in rs]
        meta.insert(0, f"{d1} → {d2}")
    elif name == "leave_history":
        d1, d2 = _d(params, "date_from"), _d(params, "date_to")
        sql = ("SELECT r.*, u.full_name, u.full_name_ar, u.employee_no, t.name tname, t.name_ar tname_ar, "
               "du.full_name dname, du.full_name_ar dname_ar FROM leave_requests r JOIN users u ON u.id=r.user_id "
               "JOIN leave_types t ON t.id=r.type_id LEFT JOIN users du ON du.id=r.decided_by WHERE 1=1")
        args = []
        if uid:
            sql += " AND r.user_id=?"; args.append(uid)
        if d1:
            sql += " AND r.end_date>=?"; args.append(d1.isoformat())
        if d2:
            sql += " AND r.start_date<=?"; args.append(d2.isoformat())
        if params.get("status") in ("pending", "approved", "rejected", "cancelled"):
            sql += " AND r.status=?"; args.append(params["status"])
        sql += " ORDER BY r.start_date DESC, r.id DESC"
        data = []
        for r in db.rows(sql, args):
            data.append({
                "emp_no": r["employee_no"], "name": r["full_name_ar"] if lang == "ar" and r["full_name_ar"] else r["full_name"],
                "type": r["tname_ar"] if lang == "ar" and r["tname_ar"] else r["tname"],
                "from": r["start_date"], "to": r["end_date"], "days": r["days"],
                "status": T.get(r["status"], r["status"]), "reason": r["reason"],
                "decided_by": (r["dname_ar"] if lang == "ar" and r["dname_ar"] else r["dname"]) or "",
                "comment": r["decision_comment"],
            })
        title = T["r_leave_history"]
        cols = ["emp_no", "name", "type", "from", "to", "days", "status", "reason", "decided_by", "comment"]
        if d1 or d2:
            meta.insert(0, f"{d1 or ''} → {d2 or ''}")
    elif name == "leave_balances":
        year = int(params.get("year") or today.year)
        users = L.technicians(date(year, 1, 1), date(year, 12, 31), uids, include_with_records=False)
        data = []
        for u in users:
            b = L.balance(u["id"], year)
            data.append({"emp_no": u["employee_no"], "name": _name(u, lang), "year": year, "total": b["total"],
                         "used": b["used"], "pending_days": b["pending"], "remaining": b["remaining"]})
        title = T["r_leave_balances"]
        cols = ["emp_no", "name", "year", "total", "used", "pending_days", "remaining"]
        meta.insert(0, str(year))
    elif name == "shifts":
        d = _d(params, "date", today)
        ws = L.week_start_of(d)
        sched = L.Sched()
        users = L.technicians(ws, ws, uids, include_with_records=False)
        order = [(ws + timedelta(days=i)) for i in range(7)]
        data = []
        for u in users:
            row = {"emp_no": u["employee_no"], "name": _name(u, lang)}
            n_work = 0
            for dd in order:
                s = sched.shift(u["id"], dd)
                row[f"wd{dd.weekday()}"] = _shift_name(shifts, s, lang) if s else T["off"]
                n_work += 1 if s else 0
            row["scheduled"] = n_work
            if sid and not any(sched.shift(u["id"], dd) == sid for dd in order):
                continue
            data.append(row)
        title = T["r_shifts"]
        cols = ["emp_no", "name"] + [f"wd{dd.weekday()}" for dd in order] + ["scheduled"]
        meta.insert(0, f"{ws} → {ws + timedelta(days=6)}")
    else:
        raise ReportError("not_found", "Unknown report")

    return {"name": name, "title": title, "subtitle": " · ".join(m for m in meta if m),
            "columns": [{"key": c, "label": T[c]} for c in cols], "rows": data, "lang": lang}


# ------------------------------------------------------------------ exporters
def to_xlsx(rep, company):
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill, Border, Side
    from openpyxl.utils import get_column_letter
    wb = Workbook()
    ws = wb.active
    ws.title = rep["name"][:30]
    rtl = rep["lang"] == "ar"
    ws.sheet_view.rightToLeft = rtl
    ncol = max(1, len(rep["columns"]))
    ws.cell(1, 1, company).font = Font(bold=True, size=14, color="0B2545")
    ws.cell(2, 1, rep["title"]).font = Font(bold=True, size=12)
    ws.cell(3, 1, rep["subtitle"]).font = Font(color="555555")
    ws.cell(4, 1, f'{LBL[rep["lang"]]["generated"]}: {L.now().astimezone(L.tz()).strftime("%Y-%m-%d %H:%M")}').font = Font(color="888888", size=9)
    hdr_row = 6
    fill = PatternFill("solid", fgColor="0B2545")
    thin = Side(style="thin", color="D5DAE1")
    for i, c in enumerate(rep["columns"], 1):
        cell = ws.cell(hdr_row, i, c["label"])
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = fill
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
    zebra = PatternFill("solid", fgColor="F3F6FA")
    for r, row in enumerate(rep["rows"], hdr_row + 1):
        for i, c in enumerate(rep["columns"], 1):
            v = row.get(c["key"], "")
            cell = ws.cell(r, i, v)
            cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
            cell.border = Border(bottom=thin)
            if (r - hdr_row) % 2 == 0:
                cell.fill = zebra
    for i, c in enumerate(rep["columns"], 1):
        width = max([len(str(c["label"]))] + [len(str(rw.get(c["key"], ""))) for rw in rep["rows"][:300]]) + 3
        ws.column_dimensions[get_column_letter(i)].width = min(max(width, 10), 40)
    ws.freeze_panes = ws.cell(hdr_row + 1, 1)
    if rep["rows"]:
        ws.auto_filter.ref = f"A{hdr_row}:{get_column_letter(ncol)}{hdr_row + len(rep['rows'])}"
    bio = io.BytesIO()
    wb.save(bio)
    return bio.getvalue()


def to_pdf(rep, company):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    from xml.sax.saxutils import escape
    import os

    font = "Helvetica"
    for p in ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
              os.path.join(db.BASE_DIR, "static", "fonts", "DejaVuSans.ttf")):
        if os.path.exists(p):
            if "AFHFont" not in pdfmetrics.getRegisteredFontNames():
                pdfmetrics.registerFont(TTFont("AFHFont", p))
            font = "AFHFont"
            break
    ar = rep["lang"] == "ar"
    V = visual if ar else (lambda s: s)
    cols = rep["columns"][::-1] if ar else rep["columns"]
    align = 2 if ar else 0
    cell = ParagraphStyle("c", fontName=font, fontSize=7.5, leading=10, alignment=1)
    head = ParagraphStyle("h", fontName=font, fontSize=7.5, leading=10, alignment=1, textColor=colors.white)
    h1 = ParagraphStyle("t", fontName=font, fontSize=15, leading=19, textColor=colors.HexColor("#0B2545"), alignment=align)
    h2 = ParagraphStyle("s", fontName=font, fontSize=10, leading=14, textColor=colors.HexColor("#333333"), alignment=align)
    h3 = ParagraphStyle("m", fontName=font, fontSize=8, leading=11, textColor=colors.HexColor("#777777"), alignment=align)

    def P(v, st):
        return Paragraph(escape(V(str(v))) if v != "" else "", st)

    data = [[P(c["label"], head) for c in cols]]
    for r in rep["rows"]:
        data.append([P(r.get(c["key"], ""), cell) for c in cols])
    if len(data) == 1:
        data.append([P("—", cell)] + [P("", cell)] * (len(cols) - 1))
    buf = io.BytesIO()
    page = landscape(A4)
    doc = SimpleDocTemplate(buf, pagesize=page, leftMargin=12 * mm, rightMargin=12 * mm, topMargin=14 * mm, bottomMargin=14 * mm,
                            title=rep["title"])
    width = page[0] - 24 * mm
    tbl = Table(data, colWidths=[width / len(cols)] * len(cols), repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0B2545")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F3F6FA")]),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#D5DAE1")),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    gen = f'{LBL[rep["lang"]]["generated"]}: {L.now().astimezone(L.tz()).strftime("%Y-%m-%d %H:%M")}'
    story = [P(company, h1), P(rep["title"], h2), P(rep["subtitle"], h3), P(gen, h3), Spacer(1, 6 * mm), tbl]

    def footer(canvas, d):
        canvas.saveState()
        canvas.setFont(font, 7)
        canvas.setFillColor(colors.HexColor("#777777"))
        txt = V(f'{LBL[rep["lang"]]["page"]} {d.page}')
        canvas.drawCentredString(page[0] / 2, 8 * mm, txt)
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()
