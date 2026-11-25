import hashlib
import os


def user_hash(usn: str) -> str:
    salt = os.getenv("SALT", "local-demo-only-change-me")
    return hashlib.sha256(f"{salt}{usn.strip().upper()}".encode("utf-8")).hexdigest()
