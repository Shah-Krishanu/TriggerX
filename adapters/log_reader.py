import argparse
import json
import re
import time
from datetime import datetime
from pathlib import Path

import httpx

from adapters.events import make_event

ACCESS_LOG = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) [^"]*" (?P<status>\d{3}) \S+ '
    r'"[^"]*" "(?P<ua>[^"]*)"'
)


def event_from_line(line: str, site: str) -> dict | None:
    match = ACCESS_LOG.search(line)
    if not match:
        return None
    fields = match.groupdict()
    try:
        parsed = datetime.strptime(fields["ts"], "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None
    event = make_event(
        site=site,
        ip=fields["ip"],
        path=fields["path"],
        method=fields["method"],
        status=int(fields["status"]),
        ua=fields["ua"],
        usn="",
    )
    event["ts"] = parsed.isoformat()
    return event


def event_from_json_line(line: str) -> dict | None:
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(event, dict):
        return None

    required = {"ts", "site", "ip", "path", "method", "status"}
    optional = {"user_hash", "ua"}
    if not required.issubset(event) or not set(event).issubset(required | optional):
        return None
    if any(not isinstance(event[key], str) or not event[key] for key in required - {"status"}):
        return None
    if not 1 <= len(event["site"]) <= 80 or not 1 <= len(event["ip"]) <= 64:
        return None
    if not 1 <= len(event["path"]) <= 2048 or not 1 <= len(event["method"]) <= 16:
        return None
    if isinstance(event["status"], bool) or not isinstance(event["status"], int):
        return None
    if not 100 <= event["status"] <= 599:
        return None
    event.setdefault("user_hash", "")
    event.setdefault("ua", "")
    if not isinstance(event["user_hash"], str) or len(event["user_hash"]) > 128:
        return None
    if not isinstance(event["ua"], str) or len(event["ua"]) > 512:
        return None
    try:
        datetime.fromisoformat(event["ts"].replace("Z", "+00:00"))
    except ValueError:
        return None

    event["method"] = event["method"].upper()
    return event


def main() -> None:
    parser = argparse.ArgumentParser(description="Adapt Apache/Nginx combined access logs")
    parser.add_argument("--file", required=True, help="Access log file to read")
    parser.add_argument("--site", help="Short site name; required for combined access logs")
    parser.add_argument(
        "--format",
        choices=("combined", "jsonl"),
        default="combined",
        help="Input format (default: combined)",
    )
    parser.add_argument("--sentinel", default="http://127.0.0.1:9000")
    parser.add_argument("--follow", action="store_true", help="Continue reading appended lines")
    args = parser.parse_args()
    if args.format == "combined" and not args.site:
        parser.error("--site is required for combined access logs")
    path = Path(args.file)
    if not path.is_file():
        raise SystemExit(f"Access log not found: {path}")

    with path.open("r", encoding="utf-8", errors="replace") as log, httpx.Client(timeout=4.0) as client:
        while True:
            line = log.readline()
            if not line:
                if not args.follow:
                    break
                time.sleep(0.5)
                continue
            if args.format == "jsonl":
                event = event_from_json_line(line)
            else:
                event = event_from_line(line, args.site)
            if event is None:
                continue
            response = client.post(f"{args.sentinel.rstrip('/')}/event", json=event)
            response.raise_for_status()
            print(f"Recorded {event['method']} {event['path']} ({event['status']}) from {event['ip']}")


if __name__ == "__main__":
    main()
