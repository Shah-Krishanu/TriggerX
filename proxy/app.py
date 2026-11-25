import json
import logging
import os
from urllib.parse import parse_qs, urlsplit

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import Response

from adapters.events import make_event

logger = logging.getLogger(__name__)
app = FastAPI(title="Campus Sentinel Reverse Proxy")
TARGETS = {
    "results": os.getenv("RESULTS_URL", "http://127.0.0.1:8001"),
    "library": os.getenv("LIBRARY_URL", "http://127.0.0.1:8002"),
}
SENTINEL_URL = os.getenv("SENTINEL_URL", "http://127.0.0.1:9000").rstrip("/")


def _login_usn(content_type: str, body: bytes) -> str:
    try:
        if "application/json" in content_type:
            values = json.loads(body or b"{}")
        else:
            parsed = parse_qs(body.decode("utf-8", errors="replace"))
            values = {key: items[0] for key, items in parsed.items() if items}
        return str(values.get("usn", "")).strip()
    except (json.JSONDecodeError, AttributeError, UnicodeDecodeError):
        return ""


async def _check(ip: str) -> str:
    async with httpx.AsyncClient(timeout=2.0) as client:
        response = await client.get(f"{SENTINEL_URL}/check", params={"ip": ip})
        response.raise_for_status()
        return response.json()["action"]


async def _send_event(event: dict) -> None:
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(f"{SENTINEL_URL}/event", json=event)
        response.raise_for_status()


@app.get("/health")
def health() -> dict:
    return {"ok": True}


@app.api_route("/{site}/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def proxy_request(site: str, path: str, request: Request) -> Response:
    if site not in TARGETS:
        return Response("Unknown demo site", status_code=404)
    client_ip = request.client.host if request.client else "unknown"
    try:
        decision = await _check(client_ip)
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        logger.error("Sentinel check failed; request denied: %s", exc)
        return Response("Security check unavailable", status_code=503)
    if decision == "block":
        return Response("Request blocked by Campus Sentinel", status_code=403)
    if decision == "rate_limit":
        return Response("Rate limited by Campus Sentinel", status_code=429)

    body = await request.body()
    target_url = f"{TARGETS[site].rstrip('/')}/{path}"
    if request.url.query:
        target_url += f"?{request.url.query}"
    forwarded_headers = {
        key: value for key, value in request.headers.items()
        if key.lower() not in {"host", "content-length", "connection"}
    }
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            upstream = await client.request(
                request.method,
                target_url,
                content=body,
                headers=forwarded_headers,
            )
    except httpx.HTTPError as exc:
        logger.error("Upstream app request failed: %s", exc)
        return Response("Demo application unavailable", status_code=502)

    usn = _login_usn(request.headers.get("content-type", ""), body) if path.endswith("login") else ""
    event = make_event(
        site=site,
        ip=client_ip,
        path=f"/{path}",
        method=request.method,
        status=upstream.status_code,
        ua=request.headers.get("user-agent", ""),
        usn=usn,
    )
    try:
        await _send_event(event)
    except httpx.HTTPError as exc:
        logger.error("Sentinel event delivery failed: %s", exc)

    response_headers = {
        key: value for key, value in upstream.headers.items()
        if key.lower() not in {"content-length", "transfer-encoding", "connection"}
    }
    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=response_headers,
    )
