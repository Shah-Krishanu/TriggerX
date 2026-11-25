import argparse
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
    parsed = datetime.strptime(fields["ts"], "%d/%b/%Y:%H:%M:%S %z")
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Adapt Apache/Nginx combined access logs")
    parser.add_argument("--file", required=True, help="Access log file to read")
    parser.add_argument("--site", required=True, help="Short site name, such as results")
    parser.add_argument("--sentinel", default="http://127.0.0.1:9000")
    parser.add_argument("--follow", action="store_true", help="Continue reading appended lines")
    args = parser.parse_args()
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
            event = event_from_line(line, args.site)
            if event is None:
                continue
            response = client.post(f"{args.sentinel.rstrip('/')}/event", json=event)
            response.raise_for_status()
            print(f"Recorded {event['method']} {event['path']} ({event['status']}) from {event['ip']}")


if __name__ == "__main__":
    main()
