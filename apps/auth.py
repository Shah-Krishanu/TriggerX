import hashlib
import hmac
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from core.config import user_hash

DB_PATH = os.getenv("CAMPUS_AUTH_DB", "data/campus-auth.sqlite")
OTP_TTL_SECONDS = 5 * 60
OTP_MAX_ATTEMPTS = 5
OTP_MAX_CHALLENGES_PER_HOUR = 3
TRUSTED_DEVICE_SECONDS = 30 * 24 * 60 * 60
CHALLENGE_COOKIE = "campus_otp_challenge"
TRUSTED_DEVICE_COOKIE = "campus_trusted_device"


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
            CREATE TABLE IF NOT EXISTS otp_challenges (
                token_hash TEXT PRIMARY KEY,
                account_hash TEXT NOT NULL,
                otp_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS trusted_devices (
                token_hash TEXT PRIMARY KEY,
                account_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS otp_rate_limits (
                account_hash TEXT PRIMARY KEY,
                window_started INTEGER NOT NULL,
                request_count INTEGER NOT NULL
            );
            """
        )


def _now() -> int:
    return int(time.time())


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _otp_hash(account_hash: str, code: str) -> str:
    secret = os.getenv("SALT", "local-demo-only-change-me").encode("utf-8")
    message = f"{account_hash}:{code}".encode("utf-8")
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def create_challenge(usn: str, now: int | None = None) -> tuple[str, str] | None:
    initialize()
    current = _now() if now is None else now
    account_hash = user_hash(usn)
    with _connection() as db:
        db.execute("BEGIN IMMEDIATE")
        db.execute("DELETE FROM otp_challenges WHERE expires_at <= ?", (current,))
        db.execute("DELETE FROM trusted_devices WHERE expires_at <= ?", (current,))
        row = db.execute(
            "SELECT window_started, request_count FROM otp_rate_limits WHERE account_hash = ?",
            (account_hash,),
        ).fetchone()
        if row and current - row["window_started"] < 60 * 60:
            if row["request_count"] >= OTP_MAX_CHALLENGES_PER_HOUR:
                return None
            db.execute(
                "UPDATE otp_rate_limits SET request_count = request_count + 1 WHERE account_hash = ?",
                (account_hash,),
            )
        else:
            db.execute(
                """INSERT OR REPLACE INTO otp_rate_limits(account_hash, window_started, request_count)
                   VALUES (?, ?, 1)""",
                (account_hash, current),
            )

        raw_token = secrets.token_urlsafe(32)
        code = f"{secrets.randbelow(1_000_000):06d}"
        db.execute(
            """INSERT INTO otp_challenges(token_hash, account_hash, otp_hash, created_at, expires_at)
               VALUES (?, ?, ?, ?, ?)""",
            (
                _token_hash(raw_token),
                account_hash,
                _otp_hash(account_hash, code),
                current,
                current + OTP_TTL_SECONDS,
            ),
        )
    return raw_token, code


def verify_challenge(
    raw_token: str | None,
    code: str,
    now: int | None = None,
) -> tuple[str, str | None]:
    initialize()
    if not raw_token:
        return "missing", None

    current = _now() if now is None else now
    token_hash = _token_hash(raw_token)
    with _connection() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            "SELECT account_hash, otp_hash, expires_at, attempts FROM otp_challenges WHERE token_hash = ?",
            (token_hash,),
        ).fetchone()
        if row is None:
            return "missing", None
        if row["expires_at"] <= current:
            db.execute("DELETE FROM otp_challenges WHERE token_hash = ?", (token_hash,))
            return "expired", row["account_hash"]
        if row["attempts"] >= OTP_MAX_ATTEMPTS:
            db.execute("DELETE FROM otp_challenges WHERE token_hash = ?", (token_hash,))
            return "locked", row["account_hash"]

        candidate = _otp_hash(row["account_hash"], code)
        if not hmac.compare_digest(candidate, row["otp_hash"]):
            attempts = row["attempts"] + 1
            if attempts >= OTP_MAX_ATTEMPTS:
                db.execute("DELETE FROM otp_challenges WHERE token_hash = ?", (token_hash,))
                return "locked", row["account_hash"]
            db.execute(
                "UPDATE otp_challenges SET attempts = ? WHERE token_hash = ?",
                (attempts, token_hash),
            )
            return "invalid", None

        db.execute("DELETE FROM otp_challenges WHERE token_hash = ?", (token_hash,))
        return "verified", row["account_hash"]


def is_trusted_device(
    usn: str,
    raw_token: str | None,
    now: int | None = None,
) -> bool:
    initialize()
    if not raw_token:
        return False

    current = _now() if now is None else now
    token_hash = _token_hash(raw_token)
    account_hash = user_hash(usn)
    with _connection() as db:
        row = db.execute(
            "SELECT account_hash, expires_at FROM trusted_devices WHERE token_hash = ?",
            (token_hash,),
        ).fetchone()
        if row is None:
            return False
        if row["expires_at"] <= current:
            db.execute("DELETE FROM trusted_devices WHERE token_hash = ?", (token_hash,))
            return False
        return hmac.compare_digest(row["account_hash"], account_hash)


def trust_device(usn: str, now: int | None = None) -> str:
    return trust_account_hash(user_hash(usn), now)


def trust_account_hash(account_hash: str, now: int | None = None) -> str:
    initialize()
    current = _now() if now is None else now
    raw_token = secrets.token_urlsafe(32)
    with _connection() as db:
        db.execute(
            """INSERT INTO trusted_devices(token_hash, account_hash, created_at, expires_at)
               VALUES (?, ?, ?, ?)""",
            (
                _token_hash(raw_token),
                account_hash,
                current,
                current + TRUSTED_DEVICE_SECONDS,
            ),
        )
    return raw_token


def forget_device(raw_token: str | None) -> None:
    initialize()
    if not raw_token:
        return
    with _connection() as db:
        db.execute(
            "DELETE FROM trusted_devices WHERE token_hash = ?",
            (_token_hash(raw_token),),
        )
