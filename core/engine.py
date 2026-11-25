import json
import logging
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from core.config import user_hash

logger = logging.getLogger(__name__)
DB_PATH = os.getenv("SENTINEL_DB", "data/sentinel.sqlite")


@contextmanager
def _connection():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def initialize() -> None:
    with _connection() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY,
                ts TEXT NOT NULL,
                site TEXT NOT NULL,
                ip TEXT NOT NULL,
                user_hash TEXT NOT NULL,
                path TEXT NOT NULL,
                method TEXT NOT NULL,
                status INTEGER NOT NULL,
                ua TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY,
                ts TEXT NOT NULL,
                ip TEXT NOT NULL,
                site TEXT NOT NULL,
                score INTEGER NOT NULL,
                reasons TEXT NOT NULL,
                explanation TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS blocked (
                ip TEXT PRIMARY KEY,
                until TEXT,
                reason TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS pending (
                id INTEGER PRIMARY KEY,
                action TEXT NOT NULL,
                ip TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )


def _parse_ts(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _honeypot_hashes() -> set[str]:
    path = Path(os.getenv("HONEYPOT_FILE", "data/honeypots.txt"))
    try:
        return {user_hash(line.strip()) for line in path.read_text().splitlines() if line.strip()}
    except FileNotFoundError:
        return set()


def _is_login_path(path: str) -> bool:
    return path.endswith(("/login", "/login/start"))


def _signals(db: sqlite3.Connection, event: dict) -> list[tuple[int, str]]:
    current = _parse_ts(event["ts"])
    ip = event["ip"]
    user = event["user_hash"]
    recent = db.execute(
        "SELECT ts, user_hash, status, ua, path FROM events WHERE ip = ?",
        (ip,),
    ).fetchall()
    window_5m = current - timedelta(minutes=5)
    window_10s = current - timedelta(seconds=10)
    recent_5m = [row for row in recent if _parse_ts(row["ts"]) >= window_5m]
    recent_10s = [row for row in recent if _parse_ts(row["ts"]) >= window_10s]

    signals = []
    distinct_users = {
        row["user_hash"] for row in recent_5m
        if row["user_hash"] and _is_login_path(row["path"])
    }
    if len(distinct_users) >= 5:
        signals.append((40, "Five or more different accounts from one IP within five minutes"))

    if (
        user
        and event["method"] == "POST"
        and 200 <= event["status"] < 400
        and event["path"].endswith("/login")
    ):
        failures = [
            row for row in recent_5m
            if row["user_hash"] == user and row["status"] == 401
            and _is_login_path(row["path"])
        ]
        if len(failures) >= 3:
            signals.append((35, "Successful login followed at least three failures for the same account"))

    if user and user in _honeypot_hashes():
        signals.append((80, "A reserved honeypot account was used"))

    if len(recent_10s) >= 30:
        signals.append((50, "Thirty or more requests from one IP within ten seconds"))

    if user:
        previous_agents = {
            row["ua"] for row in recent
            if row["user_hash"] == user and row["ua"] and row["ts"] != event["ts"]
        }
        if previous_agents and event["ua"] not in previous_agents:
            signals.append((15, "A previously unseen browser or device was observed for this account"))

    if 0 <= current.hour < 5:
        signals.append((10, "Request occurred between midnight and 5 AM"))
    return signals


async def record_event(event: dict, explanation_fn) -> dict | None:
    with _connection() as db:
        db.execute(
            """INSERT INTO events(ts, site, ip, user_hash, path, method, status, ua)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event["ts"], event["site"], event["ip"], event["user_hash"],
                event["path"], event["method"], event["status"], event["ua"],
            ),
        )
        signals = _signals(db, event)
        score = min(100, sum(points for points, _ in signals))
        if not signals:
            return None
        reasons = [reason for _, reason in signals]
        explanation = f"Risk score {score}: " + "; ".join(reasons)
        cursor = db.execute(
            "INSERT INTO alerts(ts, ip, site, score, reasons, explanation) VALUES (?, ?, ?, ?, ?, ?)",
            (event["ts"], event["ip"], event["site"], score, json.dumps(reasons), explanation),
        )
        if score >= 70:
            until = (_parse_ts(event["ts"]) + timedelta(minutes=15)).isoformat()
            db.execute(
                "INSERT OR REPLACE INTO blocked(ip, until, reason) VALUES (?, ?, ?)",
                (event["ip"], until, "; ".join(reasons)),
            )
            db.execute(
                "INSERT INTO pending(action, ip, reason, created_at) VALUES (?, ?, ?, ?)",
                ("permanent_block", event["ip"], "; ".join(reasons), event["ts"]),
            )
        alert = {
            "id": cursor.lastrowid,
            "ts": event["ts"],
            "ip": event["ip"],
            "site": event["site"],
            "score": score,
            "reasons": reasons,
            "explanation": explanation,
        }
    explanation = await explanation_fn(event["site"], score, reasons)
    with _connection() as db:
        db.execute(
            "UPDATE alerts SET explanation = ? WHERE id = ?",
            (explanation, alert["id"]),
        )
    alert["explanation"] = explanation
    return alert


def decision_for_ip(ip: str) -> dict:
    with _connection() as db:
        row = db.execute("SELECT until FROM blocked WHERE ip = ?", (ip,)).fetchone()
        if row:
            until = row["until"]
            if until is None or _parse_ts(until) > datetime.now(timezone.utc):
                return {"action": "block"}
            db.execute("DELETE FROM blocked WHERE ip = ?", (ip,))
        row = db.execute(
            "SELECT ts, score FROM alerts WHERE ip = ? ORDER BY id DESC LIMIT 1", (ip,)
        ).fetchone()
        recent_alert = (
            row
            and row["score"] >= 50
            and _parse_ts(row["ts"]) + timedelta(seconds=30) > datetime.now(timezone.utc)
        )
        return {"action": "rate_limit" if recent_alert else "allow"}


def list_alerts() -> list[dict]:
    with _connection() as db:
        rows = db.execute(
            "SELECT id, ts, ip, site, score, reasons, explanation FROM alerts ORDER BY id DESC LIMIT 100"
        ).fetchall()
    return [
        {**dict(row), "reasons": json.loads(row["reasons"])}
        for row in rows
    ]


def list_blocked() -> list[dict]:
    with _connection() as db:
        rows = db.execute("SELECT ip, until, reason FROM blocked ORDER BY ip").fetchall()
    return [dict(row) for row in rows]


def list_pending() -> list[dict]:
    with _connection() as db:
        rows = db.execute(
            "SELECT id, action, ip, reason FROM pending ORDER BY id DESC"
        ).fetchall()
    return [dict(row) for row in rows]


def approve_pending(pending_id: int) -> bool:
    with _connection() as db:
        row = db.execute("SELECT ip, reason FROM pending WHERE id = ?", (pending_id,)).fetchone()
        if not row:
            return False
        db.execute(
            "INSERT OR REPLACE INTO blocked(ip, until, reason) VALUES (?, NULL, ?)",
            (row["ip"], row["reason"]),
        )
        db.execute("DELETE FROM pending WHERE id = ?", (pending_id,))
    return True


def unblock(ip: str) -> None:
    with _connection() as db:
        db.execute("DELETE FROM blocked WHERE ip = ?", (ip,))
