# Campus Hub + Sentinel

An original, fictional campus portal connected to Sentinel's defensive event monitor.
It is a standalone demo, not a Contineo clone and not connected to Contineo.

## Start the demo

1. Copy `.env.example` to `.env`.
2. Replace `SALT` and `SENTINEL_ADMIN_TOKEN` with separate random demo secrets.
3. Optional: add Gemini and Telegram credentials.
4. Run `docker compose up --build`.
5. Open `http://localhost:8000` for Campus Hub and `http://localhost:8501` for the Sentinel dashboard.

To create an alert, open the Results portal, enter `DEMO0001`, and submit an incorrect date of birth three times. Refresh the dashboard; the alert explains that the same synthetic account had three failed sign-ins. For a successful demo sign-in, use DOB `2005-01-01` and Results campus ID `DEMO-ID-0001`.

The demo uses fake accounts only. Never point it at Contineo or real student data.

## Services

| Service | Access | Purpose |
|---|---:|---|
| Campus Hub gateway | `localhost:8000` | Original portal selection page and protected routing |
| Results portal | Internal | Synthetic account, DOB, and campus ID sign-in |
| Library portal | Internal | Synthetic account and DOB sign-in |
| Sentinel API | `localhost:9000` | Risk scoring and alert API |
| Dashboard | `localhost:8501` | Review explainable alerts |

Test accounts use `DEMO0001` through `DEMO0020`.
Their DOB is `2005-01-01`.
Results ID numbers use `DEMO-ID-0001` through `DEMO-ID-0020`.
The `/directory` pages show synthetic Faker names. Results and Library are reachable through the gateway so sign-in events pass through the Sentinel-connected proxy.

## Watch modes

- Reverse proxy: `proxy/app.py` routes `/results/` and `/library/`, then sends sanitized sign-in metadata to Sentinel.
- Existing access logs: `python -m adapters.log_reader --file PATH --site results`.
- Sanitized application events: `python -m adapters.log_reader --file PATH --format jsonl`.
- Passive uptime, TLS, and headers: `python -m adapters.outside_checks --url URL`.

The log adapter understands Apache/Nginx combined logs and JSON Lines. JSONL input
uses the Sentinel event format (`ts`, `site`, `ip`, `path`, `method`, `status`,
and optional `user_hash` and `ua`). Send only sanitized metadata: `user_hash`
must already be a salted account hash; unknown fields such as passwords or
account identifiers are rejected rather than forwarded. Put one event per line,
for example:

```json
{"ts":"2026-11-25T18:07:00Z","site":"results","ip":"192.0.2.10","path":"/login","method":"POST","status":401,"user_hash":"<salted-hash>"}
```

Outside checks make GET requests only.

## Decision and privacy model

Rules score events from 0 to 100.
- Three failed `POST /login` attempts for one hashed account at one site and IP in five minutes add 35 points and create an explanatory alert; this rule alone is below the rate-limit threshold.
- When an event creates an alert, `POST /event` returns it in an `alert` field; the dashboard reads saved alerts from `GET /alerts`.
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
