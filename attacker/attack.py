import argparse
import time

import httpx


def main() -> None:
    parser = argparse.ArgumentParser(description="Bounded Campus Sentinel demo traffic")
    parser.add_argument("--target", default="http://127.0.0.1:8000")
    parser.add_argument("--sentinel", default="")
    parser.add_argument("--site", choices=("results", "library"), default="results")
    args = parser.parse_args()
    parsed = httpx.URL(args.target)
    if parsed.scheme != "http" or parsed.host not in {
        "localhost", "127.0.0.1", "::1"
    } and not _is_private_address(parsed.host):
        raise SystemExit("Demo target must be localhost or a private LAN address.")

    url = f"{args.target.rstrip('/')}/{args.site}/login"
    sentinel_url = args.sentinel or f"{parsed.scheme}://{parsed.host}:9000"
    headers = {"User-Agent": "Campus-Sentinel-Demo/1.0"}
    print(f"Sending six bounded fake login attempts to {url}")
    with httpx.Client(timeout=5.0) as client:
        for number in range(1, 6):
            payload = {"usn": f"DEMO{number:04d}", "dob": "1900-01-01"}
            if args.site == "results":
                payload["id_no"] = "FAKE-INVALID"
            response = client.post(url, data=payload, headers=headers)
            print(f"Attempt {number}: HTTP {response.status_code}")
            time.sleep(0.35)
        payload = {"usn": "DEMOHONEYPOT01", "dob": "1900-01-01"}
        if args.site == "results":
            payload["id_no"] = "FAKE-INVALID"
        response = client.post(url, data=payload, headers=headers)
        print(f"Honeypot attempt: HTTP {response.status_code}")
        blocked = client.get(f"{sentinel_url.rstrip('/')}/blocked")
        print(f"Blocked addresses: {blocked.json()}")


def _is_private_address(host: str) -> bool:
    import ipaddress
    try:
        address = ipaddress.ip_address(host)
        return address.is_private and not address.is_unspecified and not address.is_multicast
    except ValueError:
        return False


if __name__ == "__main__":
    main()
