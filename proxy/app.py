import json
import logging
import os
from urllib.parse import parse_qs, urlsplit

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, Response

from adapters.events import make_event

logger = logging.getLogger(__name__)
app = FastAPI(title="Campus Sentinel Reverse Proxy")
TARGETS = {
    "results": os.getenv("RESULTS_URL", "http://127.0.0.1:8001"),
    "library": os.getenv("LIBRARY_URL", "http://127.0.0.1:8002"),
}
SENTINEL_URL = os.getenv("SENTINEL_URL", "http://127.0.0.1:9000").rstrip("/")


@app.get("/", response_class=HTMLResponse)
def home() -> HTMLResponse:
    return HTMLResponse("""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Campus Hub | Sentinel Demo</title>
<style>
body{margin:0;background:#f3f6fb;color:#17243b;font:16px/1.5 system-ui,sans-serif}
header{background:#102a56;color:#fff;padding:22px max(24px,calc((100% - 1040px)/2));font-weight:700}
main{max-width:1040px;margin:56px auto;padding:0 24px}
.tag{color:#54709a;font-size:.75rem;font-weight:700;letter-spacing:.15em;text-transform:uppercase}
h1{font-size:clamp(2rem,5vw,3rem);margin:8px 0}
.intro{max-width:650px;color:#53627a}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:20px;margin-top:30px}
article{background:#fff;border:1px solid #dce4f0;border-radius:14px;padding:24px}
a{color:#185adb;font-weight:650}
.note{margin-top:24px;color:#53627a}
</style></head>
<body><header>Campus Hub <span style="float:right;color:#c4d6ff;font-size:.75rem;letter-spacing:.12em">SENTINEL DEMO</span></header>
<main><div class="tag">Fictional student services</div><h1>A safer sign-in, demonstrated</h1>
<p class="intro">Explore two original sample portals. All accounts and records are synthetic;
Sentinel receives only sanitized sign-in metadata.</p>
<section class="grid">
<article><h2>Results portal</h2><p>Sign in with a demo account and campus ID.</p><a href="/results/">Open Results</a></article>
<article><h2>Library portal</h2><p>Try the same synthetic account without the campus ID field.</p><a href="/library/">Open Library</a></article>
</section>
<p class="note">Operator view: <a href="http://localhost:8501">open Sentinel dashboard</a>.
Use a wrong demo date of birth three times to produce a rule-based alert.</p></main></body></html>""")


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
    forwarded_headers["x-forwarded-prefix"] = f"/{site}"
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
