# AFH Factory Attendance Management System

Attendance, leave and 3-shift scheduling for a factory. Arabic/English (RTL/LTR), installable PWA,
role-based access (Technician / Engineer / Owner) enforced on the server, SQLite database with automatic backups.

## Run it (quick start)
```bash
pip install -r requirements.txt     # on Windows: py -m pip install -r requirements.txt
python run.py                       # on Windows: py run.py   -> http://localhost:8000
```
On first start an **owner** account is created. Username `owner`; the password is printed in the console and saved in
`data/INITIAL_OWNER_CREDENTIALS.txt` (or set `AFH_OWNER_PASSWORD` before the first run). You must change it at first sign-in.

## First-time setup (as owner)
1. **Settings → Location (GPS):** stand at the factory, press *Use my current location*, set the allowed radius, save.
   Until this is set, technicians cannot punch (when GPS is required).
2. **Settings → Shifts:** set the start/end of Shift 1–3 (an end earlier than the start = overnight shift).
3. **Settings → Company / Leave policy / Attendance rules:** company info, default annual leave, leave types, grace minutes.
4. **Users → Add user:** create engineers and technicians (initial shift, rest days, annual leave). A temporary password is shown once.
5. **Shift schedule:** adjust weekly assignments per technician (this week only, or this week and following).

## Production (HTTPS is mandatory)
Phones only allow GPS and "Install app" on HTTPS pages. Easiest path:
```bash
AFH_DOMAIN=attendance.example.com docker compose up -d --build
```
Caddy obtains the certificate automatically. Data lives in the `afh_data` volume (`/data`: `afh.db`, `backups/`).
Run **one** application process (several threads is fine): live updates use an in-process broker.

Environment variables: `AFH_DATA_DIR`, `AFH_HOST`, `AFH_PORT`, `AFH_OWNER_PASSWORD`, `AFH_TRUST_PROXY=1` (behind a reverse proxy).

## Backups and restore
Automatic SQLite backups (default every 24 h, last 30 kept) are written to `data/backups/`; the owner can create/download
them under *Settings → Backups*. Copy them off the server regularly. Restore: stop the app, replace `data/afh.db` with a backup, start again.

## How the main rules work
* **GPS:** server checks distance (haversine) to the factory point and the reported accuracy on every check-in/out; distance is stored.
* **Duplicates:** one attendance record per technician per shift-day (database-unique) + an open check-in must be closed first.
* **Overnight shifts:** a punch belongs to the shift-day that started it, so 22:00→06:00 is one record dated by its start day.
* **Late / absent:** late after the grace minutes; absent when scheduled, no check-in and shift start + "absent after" has passed (and no approved leave).
* **Leave:** pending/rejected never deduct; approved deduct automatically (balance is computed from approved requests); overlapping requests are blocked;
  rejection needs a comment; the owner can override decisions (audited). Non-deducting leave types (e.g. sick) are tracked only.
* **Corrections:** engineers need the *Correct attendance records* permission (owner grants it per engineer); a reason is mandatory and every change is audited.
* **Audit log:** user, settings, shift, schedule, attendance, leave and report actions (passwords are never logged).
* **Security:** hashed passwords (scrypt), HttpOnly SameSite=Strict session cookie, CSRF header check, lockout after 5 failed logins, CSP headers.

## Reports
Daily, monthly, employee history, absence, late arrivals, leave history, leave balances, shift assignments —
filter by employee/date/month/shift, preview on screen, download Excel or PDF (Arabic PDFs supported).

## Tests
`python tests/test_api.py` (106 API checks: permissions, GPS, duplicates, overnight, leave, schedules, reports, audit, backups).

## Known limits (please read)
* GPS is reported by the phone. The server validates it, but a rooted/spoofed phone can still fake coordinates; for stricter control add on-site Wi-Fi/QR checks.
* Leave days are counted as calendar days by default; switch to "working days only" under Settings → Leave policy. Public holidays are not modelled.
* SQLite comfortably handles hundreds of employees on one server; for multi-server deployments move to PostgreSQL.
