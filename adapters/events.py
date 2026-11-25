from datetime import datetime, timezone

from core.config import user_hash


def make_event(site: str, ip: str, path: str, method: str, status: int, ua: str, usn: str) -> dict:
    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "site": site,
        "ip": ip,
        "user_hash": user_hash(usn) if usn else "",
        "path": path,
        "method": method.upper(),
        "status": status,
        "ua": ua[:512],
    }
