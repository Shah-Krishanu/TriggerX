# Campus Sentinel

Vendor-independent protection for fictional campus portals.
It watches requests, scores behavior, and explains alerts.

## Start the demo

1. Copy `.env.example` to `.env`.
2. Set private `SALT` and `SENTINEL_ADMIN_TOKEN` values.
3. Optional: add Gemini and Telegram credentials.
4. Run `docker compose up --build`.
5. Open `http://localhost:8501`.

The demo uses fake accounts only.
Never point it at Contineo or real student data.

## Services

| Service | Port | Purpose |
|---|---:|---|
| Reverse proxy | 8000 | Checks each client and routes requests |
| Results portal | 8001 | Fictional USN, DOB, and ID login |
| Library portal | 8002 | Fictional USN and DOB login |
| Sentinel API | 9000 | Risk scoring, alerts, and approvals |
| Dashboard | 8501 | Review alerts and manage blocks |

Open the fictional portals through the proxy at `http://localhost:8000/results/`
and `http://localhost:8000/library/`. Results validates a synthetic USN and DOB,
redirects to a separate demo ID-card step, then opens a sample student dashboard.
The library portal uses synthetic USN and DOB. Neither page uses real institution
branding or accepts real student credentials.

Test accounts use `DEMO0001` through `DEMO0020`.
Their DOB is `2005-01-01`.
Results ID numbers use `DEMO-ID-0001` through `DEMO-ID-0020`.
The `/directory` pages show synthetic Faker names.

## Bounded demo attack

Run `python attacker/attack.py --site results`.
It makes six invalid, fake login attempts.
The last attempt uses a reserved honeypot account.
The Sentinel should show an alert and temporary block.
The script only accepts localhost or private LAN targets.
It never contacts the real college portal.

## Watch modes

- Reverse proxy: `proxy/app.py` protects both demo apps.
- Existing access logs: `python -m adapters.log_reader --file PATH --site results`.
- Passive uptime, TLS, and headers: `python -m adapters.outside_checks --url URL`.

The log adapter understands Apache/Nginx combined logs.
Outside checks make GET requests only.

## Decision and privacy model

Rules score events from 0 to 100.
Scores of 50 trigger a 30-second rate limit.
Scores of 70 trigger a 15-minute IP block.
Permanent blocks require dashboard approval.
Approval and unblock actions require the admin token.
Gemini writes explanations only; rules control actions.
Template explanations work without an API key.

Events store metadata and salted USN hashes only.
Passwords, DOB, ID numbers, and page content are not stored.
The proxy forwards login bodies without logging them.
This demo cannot add OTP to a vendor login.
It detects, limits, blocks, and alerts instead.
