import argparse
import asyncio

import httpx

SECURITY_HEADERS = (
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
)


async def check(url: str) -> None:
    async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
        response = await client.get(url)
    print(f"URL: {response.url}")
    print(f"HTTP status: {response.status_code}")
    print(f"TLS: {'enabled' if response.url.scheme == 'https' else 'not enabled'}")
    for header in SECURITY_HEADERS:
        print(f"{header}: {'present' if header in response.headers else 'missing'}")
    response.raise_for_status()


def main() -> None:
    parser = argparse.ArgumentParser(description="Passive uptime, TLS, and header check")
    parser.add_argument("--url", required=True, help="Your site's public or local URL")
    args = parser.parse_args()
    asyncio.run(check(args.url))


if __name__ == "__main__":
    main()
