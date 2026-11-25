# Campus Sentinel — Team Contract
Do not change without telling the whole team.

## Ports
| Service        | Port |
|----------------|------|
| Proxy          | 8000 |
| Results app    | 8001 |
| Library app    | 8002 |
| Sentinel API   | 9000 |
| Dashboard      | 8501 |

## Folders (each person edits only their own)
| Folder                         | Owner  |
|--------------------------------|--------|
| core/                          | Role 1 |
| proxy/, adapters/              | Role 2 |
| apps/, attacker/, data/        | Role 3 |
| dashboard/, notify/, docker-compose.yml, demo/ | Role 4 |

## Proxy routing
- /results/*  -> http://localhost:8001
- /library/*  -> http://localhost:8002

## Apps (Role 3)
- Results login: POST /login, form fields: usn, dob, id_no
- Library login: POST /login, form fields: usn, dob
- Success = HTTP 200. Failure = HTTP 401.
- Fake data only (Faker). Never real students.
- data/honeypots.txt = fake USNs, one per line. No real student has these.

## Event format (proxy -> Sentinel)
{
  "ts": "2026-11-26T01:23:45",   ISO time
  "site": "results",             "results" or "library"
  "ip": "192.168.1.20",
  "user_hash": "ab12...",        SHA-256(SALT + USN), or "" if no USN
  "path": "/login",
  "method": "POST",
  "status": 401,
  "ua": "Mozilla/5.0 ..."
}

## Privacy rules
- Never store passwords, DOB, ID number, or page content.
- Store USN only as hash.

## Sentinel API (Role 1 builds, port 9000)
- POST /event            body: event JSON          -> {"ok": true}
- GET  /check?ip=X       -> {"action": "allow" | "rate_limit" | "block"}
- GET  /alerts           -> list of {id, ts, ip, site, score, reasons, explanation}
- GET  /blocked          -> list of {ip, until, reason}
- GET  /pending          -> list of {id, action, ip, reason}
- POST /approve/{id}     header X-Admin-Token    -> {"ok": true}
- POST /unblock          body: {"ip": "X"}        -> {"ok": true}; requires X-Admin-Token

## Risk scoring (0-100)
- Many USNs from one IP (5+ in 5 min)   +40
- 3+ fails then success                 +35
- Honeypot USN tried                    +80
- Flood (30+ requests in 10 sec)        +50
- New device for a USN                  +15
- Odd hours (00:00-05:00)               +10
Actions:
- score >= 50  -> rate_limit
- score >= 70  -> block 15 min + Telegram alert
- permanent block / student alert -> needs admin approval (dashboard)

## LLM
- Gemini writes the explanation only. Rules decide the score.
- If Gemini fails -> template text.

## Telegram (Role 4)
- One function: send_alert(text). Role 1 calls it.

## Shared .env (NEVER commit)
SALT=choose-a-secret-word
SENTINEL_ADMIN_TOKEN=choose-a-separate-admin-secret
GEMINI_API_KEY=...
TELEGRAM_BOT_TOKEN=...
TELEGRAM_CHAT_ID=...
SENTINEL_URL=http://localhost:9000

## Git rules
- Pull before you start. Commit small. Push often.
- Only edit your own folder.
- Never commit .env.