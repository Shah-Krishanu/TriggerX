import html
import hmac
import json
import time
from contextlib import asynccontextmanager
from datetime import date
from secrets import token_urlsafe
from urllib.parse import parse_qs

from apps import auth
from apps.email_delivery import (
    demo_inbox_enabled,
    demo_outbox,
    get_otp_email_sender,
)
from core.config import user_hash
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from faker import Faker

DEMO_ACCOUNTS = {
    f"DEMO{number:04d}": {
        "dob": "2005-01-01",
        "id_no": f"DEMO-ID-{number:04d}",
    }
    for number in range(1, 21)
}
DEMO_EMAILS = {
    usn: f"{usn.lower()}@students.campus.test"
    for usn in DEMO_ACCOUNTS
}
fake = Faker()
Faker.seed(4810)
DEMO_NAMES = {usn: fake.name() for usn in DEMO_ACCOUNTS}


async def _request_values(request: Request) -> dict | None:
    body = await request.body()
    if "application/json" in request.headers.get("content-type", ""):
        try:
            values = json.loads(body or b"{}")
        except json.JSONDecodeError:
            return None
        return values if isinstance(values, dict) else None
    parsed = parse_qs(body.decode("utf-8", errors="replace"))
    return {key: items[0] for key, items in parsed.items() if items}


def _birth_date(values: dict) -> str:
    if values.get("dob"):
        return str(values["dob"])
    try:
        return date(
            int(values["dob_year"]),
            int(values["dob_month"]),
            int(values["dob_day"]),
        ).isoformat()
    except (KeyError, TypeError, ValueError):
        return ""


def create_app(site: str) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        auth.initialize()
        yield

    app = FastAPI(title=f"Campus Hub {site.title()} Demo", lifespan=lifespan)
    pending_flows: dict[str, tuple[str, float]] = {}
    active_sessions: dict[str, tuple[str, float]] = {}
    site_name = "Results" if site == "results" else "Library"

    def secure_cookie(request: Request) -> bool:
        return request.headers.get("x-forwarded-proto", request.url.scheme) == "https"

    def request_prefix(request: Request) -> str:
        return request.headers.get("x-forwarded-prefix", "").rstrip("/")

    def sign_in_success(request: Request, usn: str):
        route_prefix = request_prefix(request)
        if site == "results":
            session_token = token_urlsafe(32)
            active_sessions[session_token] = (usn, time.monotonic() + 3600)
            response = RedirectResponse(
                f"{route_prefix}/dashboard" if route_prefix else "/dashboard",
                status_code=303,
            )
            response.set_cookie(
                "campus_demo_access",
                session_token,
                max_age=3600,
                httponly=True,
                samesite="lax",
                secure=secure_cookie(request),
                path="/",
            )
            return response
        content = f"""
<main><h1>Demo sign-in successful</h1>
<p>You are signed in to this fictional campus service.</p>
<form method="post" action="{route_prefix}/forget-device">
  <button type="submit">Forget this trusted device</button>
</form></main>"""
        return HTMLResponse(content)

    def otp_challenge_page(request: Request, usn: str, message: str = "") -> HTMLResponse:
        route_prefix = request_prefix(request)
        inbox_url = f"{route_prefix}/demo-inbox/{usn}"
        error = f"<p role=\"alert\">{html.escape(message)}</p>" if message else ""
        content = f"""
<main><h1>Verify this new device</h1>
<p>We sent a one-time code to {html.escape(DEMO_EMAILS[usn])}.</p>
{error}
<form method="post" action="{route_prefix}/verify-otp">
  <label for="code">Email verification code</label>
  <input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" required>
  <button type="submit">Verify and trust this device</button>
</form>
<p><a href="{inbox_url}">Open the demo inbox</a> (local demonstration only).</p>
</main>"""
        return HTMLResponse(content, status_code=202 if not message else 401)

    def start_otp_challenge(request: Request, usn: str):
        if not demo_inbox_enabled():
            return JSONResponse(
                {"ok": False, "message": "Demo email inbox is disabled"},
                status_code=503,
            )
        try:
            sender = get_otp_email_sender()
        except RuntimeError as exc:
            return JSONResponse({"ok": False, "message": str(exc)}, status_code=503)
        challenge = auth.create_challenge(usn)
        if challenge is None:
            return JSONResponse(
                {"ok": False, "message": "Too many verification codes requested"},
                status_code=429,
            )
        raw_token, code = challenge
        sender.send_otp(DEMO_EMAILS[usn], code)
        if "application/json" in request.headers.get("content-type", ""):
            response = JSONResponse(
                {"ok": True, "requires_otp": True, "message": "Verification code sent"},
                status_code=202,
            )
        else:
            response = otp_challenge_page(request, usn)
        response.set_cookie(
            auth.CHALLENGE_COOKIE,
            raw_token,
            max_age=auth.OTP_TTL_SECONDS,
            httponly=True,
            samesite="lax",
            secure=secure_cookie(request),
            path="/",
        )
        return response

    def finish_sign_in(request: Request, usn: str):
        if auth.is_trusted_device(
            usn,
            request.cookies.get(auth.TRUSTED_DEVICE_COOKIE),
        ):
            if "application/json" in request.headers.get("content-type", ""):
                return JSONResponse(
                    {"ok": True, "message": "Trusted-device sign-in accepted"}
                )
            return sign_in_success(request, usn)
        return start_otp_challenge(request, usn)

    @app.get("/health")
    def health() -> dict:
        return {"ok": True, "site": site}

    @app.get("/directory")
    def directory() -> list[dict]:
        return [{"usn": usn, "name": DEMO_NAMES[usn]} for usn in DEMO_ACCOUNTS]

    @app.get("/demo-inbox/{usn}", response_class=HTMLResponse)
    def demo_inbox(usn: str) -> HTMLResponse:
        normalized_usn = usn.strip().upper()
        email = DEMO_EMAILS.get(normalized_usn)
        if not demo_inbox_enabled() or not email:
            return HTMLResponse("<main><h1>Demo inbox unavailable</h1></main>", status_code=404)
        code = demo_outbox.read(email)
        message = (
            f"<p>Your one-time code is <strong><code>{html.escape(code)}</code></strong>.</p>"
            if code else "<p>No current code. Start a new sign-in to request one.</p>"
        )
        return HTMLResponse(
            "<main><p>This is an in-memory local demo inbox, not a real email account.</p>"
            f"<h1>Fake student inbox</h1><p>To: <code>{html.escape(email)}</code></p>"
            f"{message}</main>"
        )

    def render_portal_page(
        step: str = "credentials",
        error: str = "",
        flow_usn: str = "",
    ) -> HTMLResponse:
        site_title = "Results" if site == "results" else "Library"
        site_description = (
            "View your academic results in this fictional campus portal."
            if site == "results"
            else "Explore the services in this fictional campus library."
        )
        needs_demo_id = site == "results"
        page = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#171b4b">
  <title>__SITE_TITLE__ | Campus Sentinel Demo</title>
  <style>
    :root {
      color-scheme: light;
      font-family: Inter, "Segoe UI", Arial, sans-serif;
      color: #17213b;
      background: #f0f1f3;
      font-synthesis: none;
      text-rendering: optimizeLegibility;
    }
    * { box-sizing: border-box; }
    body { margin: 0; min-width: 320px; min-height: 100vh; }
    .layout {
      display: grid;
      grid-template-columns: minmax(0, 1.5fr) minmax(390px, 1fr);
      min-height: calc(100vh - 42px);
    }
    .welcome {
      padding: 38px clamp(28px, 5vw, 72px) 48px;
      background: #f0f1f3;
    }
    .brand { display: flex; align-items: center; gap: 12px; }
    .brand-mark {
      display: grid;
      width: 44px;
      height: 44px;
      place-items: center;
      border: 2px solid #343b86;
      border-radius: 50%;
      color: #343b86;
      font-size: 13px;
      font-weight: 800;
      letter-spacing: .04em;
    }
    .brand-name { font-size: 14px; font-weight: 800; letter-spacing: .09em; }
    .brand-caption {
      display: block;
      margin-top: 3px;
      color: #69718a;
      font-size: 10px;
      font-weight: 700;
      letter-spacing: .12em;
    }
    .intro { max-width: 760px; margin: clamp(62px, 12vh, 112px) 0 36px; }
    h1 { margin: 0 0 14px; color: #1b2b50; font-size: clamp(25px, 3vw, 34px); font-weight: 400; }
    .intro p { max-width: 710px; margin: 0; color: #354158; font-size: 15px; line-height: 1.7; }
    .notice {
      max-width: 820px;
      min-height: 220px;
      padding: 26px 30px;
      border-left: 6px solid #24285f;
      border-radius: 6px;
      background: #fff;
      box-shadow: 0 10px 28px #17213b12;
    }
    .notice h2 { margin: 0 0 20px; font-size: 22px; font-weight: 400; }
    .notice-message {
      display: flex;
      gap: 12px;
      min-height: 112px;
      padding: 17px;
      border: 1px solid #e0e2e7;
      color: #354158;
      font-size: 14px;
      line-height: 1.6;
    }
    .notice-icon {
      display: grid;
      flex: 0 0 20px;
      width: 20px;
      height: 20px;
      place-items: center;
      border: 1px solid currentColor;
      border-radius: 50%;
      font-size: 12px;
    }
    .demo-note { margin: 18px 0 0; color: #687087; font-size: 12px; line-height: 1.6; }
    .login-panel {
      display: flex;
      flex-direction: column;
      justify-content: center;
      padding: 42px clamp(28px, 5vw, 72px);
      background: #171b4b;
      color: #fff;
    }
    .back-link { min-height: 24px; color: #d7ddff; font-size: 14px; text-decoration: none; }
    .back-link:hover { color: #fff; text-decoration: underline; }
    .login-card {
      width: 100%;
      max-width: 430px;
      margin: 38px auto 0;
      padding: clamp(28px, 4vw, 48px);
      border: 1px solid #ffffff12;
      background: #151943;
      box-shadow: 0 18px 40px #080b2b40;
    }
    .eyebrow { color: #aab4f5; font-size: 10px; font-weight: 800; letter-spacing: .15em; }
    h2 { margin: 12px 0 9px; font-size: 23px; }
    .login-description { margin: 0 0 26px; color: #c7cbea; font-size: 13px; line-height: 1.6; }
    label { display: block; margin: 16px 0 7px; color: #f1f2ff; font-size: 13px; }
    input, select {
      width: 100%;
      min-height: 43px;
      padding: 10px 12px;
      border: 1px solid #d5d8e2;
      border-radius: 2px;
      background: #fff;
      color: #202842;
      font: inherit;
      font-size: 14px;
    }
    input:focus, select:focus { outline: 3px solid #9faaff; outline-offset: 2px; }
    .date-row { display: grid; grid-template-columns: .8fr 1.2fr 1fr; gap: 8px; }
    .date-row label { margin-top: 0; }
    .date-help { margin: 8px 0 0; color: #aeb5d8; font-size: 11px; }
    .form-error {
      margin: 0 0 16px;
      padding: 11px 12px;
      border-left: 3px solid #ff9a9a;
      background: #522b42;
      color: #fff0f0;
      font-size: 12px;
      line-height: 1.5;
    }
    .sr-only {
      position: absolute;
      width: 1px;
      height: 1px;
      padding: 0;
      margin: -1px;
      overflow: hidden;
      clip: rect(0, 0, 0, 0);
      white-space: nowrap;
      border: 0;
    }
    .primary-button {
      width: 100%;
      min-height: 44px;
      margin-top: 24px;
      border: 0;
      border-radius: 2px;
      background: #f5f6fa;
      color: #17213b;
      cursor: pointer;
      font: inherit;
      font-size: 13px;
      font-weight: 800;
      letter-spacing: .03em;
    }
    .primary-button:hover { background: #dfe3ff; }
    .primary-button:focus-visible, .back-link:focus-visible { outline: 3px solid #aab4f5; outline-offset: 3px; }
    .account-help {
      margin: 22px 0 0;
      padding-top: 17px;
      border-top: 1px solid #ffffff20;
      color: #c7cbea;
      font-size: 11px;
      line-height: 1.7;
    }
    .account-help strong { color: #fff; }
    .footer {
      display: flex;
      min-height: 42px;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 8px 18px;
      background: #343638;
      color: #fff;
      font-size: 12px;
    }
    @media (max-width: 820px) {
      .layout { grid-template-columns: 1fr; }
      .welcome { padding: 26px 24px 32px; }
      .intro { margin: 48px 0 28px; }
      .notice { min-height: auto; }
      .login-panel { padding: 30px 24px 42px; }
      .login-card { margin-top: 22px; }
    }
    @media (max-width: 420px) {
      .footer { align-items: flex-start; flex-direction: column; }
      .notice { padding: 22px 18px; }
    }
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after { scroll-behavior: auto !important; }
    }
  </style>
</head>
<body>
  <main class="layout">
    <section class="welcome" aria-labelledby="welcome-title">
      <header class="brand">
        <span class="brand-mark" aria-hidden="true">CS</span>
        <span>
          <span class="brand-name">CAMPUS SENTINEL</span>
          <span class="brand-caption">FICTIONAL COLLEGE PORTAL</span>
        </span>
      </header>
      <div class="intro">
        <h1 id="welcome-title">Welcome to Demo Campus</h1>
        <p>__SITE_DESCRIPTION__ This independent demo uses made-up student accounts and sample information.</p>
      </div>
      <section class="notice" aria-labelledby="notice-title">
        <h2 id="notice-title">Notice Board</h2>
        <div class="notice-message">
          <span class="notice-icon" aria-hidden="true">i</span>
          <span>Welcome to the Campus Sentinel portal preview. Explore the fictional student experience using the demo accounts below.</span>
        </div>
        <p class="demo-note">This is a fictional security demonstration, not an official college website. Do not enter real passwords, personal information, or student records.</p>
      </section>
    </section>
    <section class="login-panel" aria-label="Demo student sign in">
      <a class="back-link" href="./">← Home</a>
      <div class="login-card">
        <span class="eyebrow">FICTIONAL DATA ONLY</span>
        <h2>Student sign in</h2>
        <p class="login-description">Sign in to the demo __SITE_TITLE__ portal with a synthetic account.</p>
        <p class="form-error" __ERROR_HIDDEN__ role="alert">__ERROR_MESSAGE__</p>
        <form method="post" action="__FORM_ACTION__" id="login-form">
          <input type="hidden" name="usn" value="__FLOW_USN__" __FLOW_USN_DISABLED__>
          <div id="credentials-step" __CREDENTIALS_HIDDEN__>
            <label for="usn">Demo username (USN)</label>
            <input id="usn" name="usn" placeholder="e.g. DEMO0001" autocomplete="off" __CREDENTIALS_DISABLED__ required>
            <fieldset style="margin: 18px 0 0; padding: 0; border: 0;">
              <legend style="margin-bottom: 7px; color: #f1f2ff; font-size: 13px;">Date of birth</legend>
              <div class="date-row">
                <label><span class="sr-only">Day</span><select id="dob-day" name="dob_day" aria-label="Day" __CREDENTIALS_DISABLED__ required>__DAY_OPTIONS__</select></label>
                <label><span class="sr-only">Month</span><select id="dob-month" name="dob_month" aria-label="Month" __CREDENTIALS_DISABLED__ required>__MONTH_OPTIONS__</select></label>
                <label><span class="sr-only">Year</span><select id="dob-year" name="dob_year" aria-label="Year" __CREDENTIALS_DISABLED__ required>__YEAR_OPTIONS__</select></label>
              </div>
            </fieldset>
            <p class="date-help">Use the published synthetic demo date.</p>
            <button class="primary-button" type="submit">__BUTTON_LABEL__</button>
          </div>
          <div id="demo-id-step" __ID_STEP_HIDDEN__>
            <label for="id-no">Enter the demo ID card number</label>
            <input id="id-no" name="id_no" placeholder="e.g. DEMO-ID-0001" autocomplete="off" __ID_DISABLED__ __ID_REQUIRED__>
            <p class="date-help">Only the synthetic IDs listed below are accepted.</p>
            <button class="primary-button" type="submit">Submit demo login</button>
          </div>
        </form>
        <p class="account-help">
          Demo usernames: <strong>DEMO0001–DEMO0020</strong><br>
          Date of birth: <strong>01 Jan 2005</strong>
          __ID_HINT__
        </p>
      </div>
    </section>
  </main>
  <footer class="footer">
    <span>Campus Sentinel · Fictional demo portal</span>
    <span>No real college credentials are collected.</span>
  </footer>
</body>
</html>"""
        day_options = "".join(
            f'<option value="{day:02d}"{" selected" if day == 1 else ""}>{day:02d}</option>'
            for day in range(1, 32)
        )
        month_names = (
            "January", "February", "March", "April", "May", "June",
            "July", "August", "September", "October", "November", "December",
        )
        month_options = "".join(
            f'<option value="{month:02d}"{" selected" if month == 1 else ""}>{name}</option>'
            for month, name in enumerate(month_names, start=1)
        )
        year_options = "".join(
            f'<option value="{year}"{" selected" if year == 2005 else ""}>{year}</option>'
            for year in range(1995, 2027)
        )
        page = (
            page.replace("__SITE_TITLE__", site_title)
            .replace("__SITE_DESCRIPTION__", site_description)
            .replace(
                "__BUTTON_LABEL__",
                "Continue" if needs_demo_id else "Sign in",
            )
            .replace("__DAY_OPTIONS__", day_options)
            .replace("__MONTH_OPTIONS__", month_options)
            .replace("__YEAR_OPTIONS__", year_options)
            .replace(
                "__ID_HINT__",
                '<br>ID card: <strong>DEMO-ID-0001–DEMO-ID-0020</strong>'
                if needs_demo_id else "",
            )
            .replace(
                "__FORM_ACTION__",
                (
                    "../login/start" if error == "credentials"
                    else "./login" if step == "id-card"
                    else "login/start" if needs_demo_id
                    else "login"
                ),
            )
            .replace(
                "__CREDENTIALS_HIDDEN__",
                "hidden" if step == "id-card" else "",
            )
            .replace(
                "__ID_STEP_HIDDEN__",
                "" if step == "id-card" and needs_demo_id else "hidden",
            )
            .replace(
                "__CREDENTIALS_DISABLED__",
                "disabled" if step == "id-card" else "",
            )
            .replace(
                "__ID_DISABLED__",
                "disabled" if step != "id-card" else "",
            )
            .replace(
                "__ID_REQUIRED__",
                "required" if step == "id-card" else "",
            )
            .replace(
                "__ERROR_HIDDEN__",
                "" if error else "hidden",
            )
            .replace(
                "__ERROR_MESSAGE__",
                "Those demo username and date values did not match."
                if error == "credentials"
                else "That demo ID card number was not accepted."
                if error == "id-card"
                else "",
            )
            .replace(
                "__FLOW_USN__",
                html.escape(flow_usn, quote=True),
            )
            .replace(
                "__FLOW_USN_DISABLED__",
                "" if step == "id-card" and flow_usn else "disabled",
            )
        )
        return HTMLResponse(page)

    @app.get("/")
    def home(error: bool = False) -> HTMLResponse:
        return render_portal_page(
            error="credentials" if error and site == "results" else "",
        )

    @app.post("/login/start")
    async def start_results_login(request: Request):
        if site != "results":
            return Response(status_code=404)
        values = await _request_values(request)
        if values is None:
            return HTMLResponse(
                render_portal_page(error="credentials").body,
                status_code=400,
            )
        usn = str(values.get("usn", "")).strip().upper()
        account = DEMO_ACCOUNTS.get(usn)
        if not account or _birth_date(values) != account["dob"]:
            return HTMLResponse(
                render_portal_page(error="credentials").body,
                status_code=401,
            )

        flow_token = token_urlsafe(24)
        pending_flows[flow_token] = (usn, time.monotonic() + 300)
        response = RedirectResponse("/id-card", status_code=303)
        response.set_cookie(
            "campus_demo_access",
            flow_token,
            max_age=300,
            httponly=True,
            samesite="lax",
            path="/",
        )
        return response

    @app.get("/id-card")
    def id_card(request: Request):
        if site != "results":
            return Response(status_code=404)
        flow_token = request.cookies.get("campus_demo_access", "")
        flow = pending_flows.get(flow_token)
        if not flow or flow[1] <= time.monotonic():
            pending_flows.pop(flow_token, None)
            return RedirectResponse("/", status_code=303)
        return render_portal_page(step="id-card", flow_usn=flow[0])

    @app.post("/login")
    async def login(request: Request):
        values = await _request_values(request)
        if values is None:
            return JSONResponse({"ok": False}, status_code=400)
        if site == "results":
            content_type = request.headers.get("content-type", "")
            if "application/json" in content_type:
                usn = str(values.get("usn", "")).strip().upper()
                account = DEMO_ACCOUNTS.get(usn)
                valid = bool(
                    account
                    and _birth_date(values) == account["dob"]
                    and values.get("id_no") == account["id_no"]
                )
                if not valid:
                    return JSONResponse(
                        {"ok": False, "message": "Invalid demo credentials"},
                        status_code=401,
                    )
                return finish_sign_in(request, usn)

            flow_token = request.cookies.get("campus_demo_access", "")
            flow = pending_flows.get(flow_token)
            usn = str(values.get("usn", "")).strip().upper()
            account = DEMO_ACCOUNTS.get(usn)
            if (
                not flow
                or flow[1] <= time.monotonic()
                or usn != flow[0]
                or not account
                or values.get("id_no") != account["id_no"]
            ):
                if flow and flow[1] > time.monotonic():
                    return HTMLResponse(
                        render_portal_page(
                            step="id-card",
                            error="id-card",
                            flow_usn=flow[0],
                        ).body,
                        status_code=401,
                    )
                pending_flows.pop(flow_token, None)
                return HTMLResponse(
                    render_portal_page(error="credentials").body,
                    status_code=401,
                )

            pending_flows.pop(flow_token, None)
            return finish_sign_in(request, usn)

        usn = str(values.get("usn", "")).strip().upper()
        account = DEMO_ACCOUNTS.get(usn)
        valid = bool(account and _birth_date(values) == account["dob"])
        if not valid:
            if "application/json" in request.headers.get("content-type", ""):
                return JSONResponse(
                    {"ok": False, "message": "Invalid demo credentials"},
                    status_code=401,
                )
            return HTMLResponse(
                render_portal_page(error="credentials").body,
                status_code=401,
            )
        return finish_sign_in(request, usn)

    @app.post("/verify-otp")
    async def verify_otp(request: Request):
        values = await _request_values(request)
        if values is None:
            return JSONResponse({"ok": False}, status_code=400)
        raw_challenge = request.cookies.get(auth.CHALLENGE_COOKIE)
        status, account_hash = auth.verify_challenge(
            raw_challenge,
            str(values.get("code", "")),
        )
        if status != "verified" or account_hash is None:
            message = {
                "expired": "This code has expired. Start sign-in again.",
                "locked": "Too many incorrect codes. Start sign-in again.",
                "missing": "This verification request is no longer valid. Start sign-in again.",
            }.get(status, "Incorrect code. Try again.")
            if "application/json" in request.headers.get("content-type", ""):
                return JSONResponse({"ok": False, "message": message}, status_code=401)
            response = HTMLResponse(
                f"<main><h1>Verify this new device</h1><p role=\"alert\">{html.escape(message)}</p>"
                "<a href=\"/\">Start sign-in again</a></main>",
                status_code=401,
            )
            if status in {"expired", "locked", "missing"}:
                response.delete_cookie(auth.CHALLENGE_COOKIE, path="/")
            return response

        usn = next(
            (
                candidate for candidate in DEMO_ACCOUNTS
                if hmac.compare_digest(user_hash(candidate), account_hash)
            ),
            None,
        )
        if usn is None:
            return JSONResponse(
                {"ok": False, "message": "Synthetic account lookup failed"},
                status_code=500,
            )
        demo_outbox.clear(DEMO_EMAILS[usn])
        trusted_token = auth.trust_account_hash(account_hash)
        response = (
            JSONResponse({"ok": True, "message": "Demo sign-in accepted"})
            if "application/json" in request.headers.get("content-type", "")
            else sign_in_success(request, usn)
        )
        response.set_cookie(
            auth.TRUSTED_DEVICE_COOKIE,
            trusted_token,
            max_age=auth.TRUSTED_DEVICE_SECONDS,
            httponly=True,
            samesite="lax",
            secure=secure_cookie(request),
            path="/",
        )
        response.delete_cookie(auth.CHALLENGE_COOKIE, path="/")
        return response

    @app.post("/forget-device")
    def forget_trusted_device(request: Request):
        auth.forget_device(request.cookies.get(auth.TRUSTED_DEVICE_COOKIE))
        response = HTMLResponse("<main><h1>Trusted device forgotten</h1></main>")
        response.delete_cookie(auth.TRUSTED_DEVICE_COOKIE, path="/")
        return response

    @app.get("/dashboard")
    def dashboard(request: Request):
        if site != "results":
            return Response(status_code=404)
        session_token = request.cookies.get("campus_demo_access", "")
        session = active_sessions.get(session_token)
        if not session or session[1] <= time.monotonic():
            active_sessions.pop(session_token, None)
            return RedirectResponse("/", status_code=303)

        usn = session[0]
        student_name = html.escape(DEMO_NAMES[usn])
        safe_usn = html.escape(usn)
        page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Student Dashboard | Campus Sentinel Demo</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; background: #f0f1f3; color: #17213b; font-family: Inter, "Segoe UI", Arial, sans-serif; }}
  header {{ display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 18px 5vw; background: #171b4b; color: white; }}
  .brand {{ font-weight: 800; letter-spacing: .08em; }}
  .brand small {{ display: block; margin-top: 4px; color: #c7cbea; font-size: 10px; }}
  button {{ padding: 10px 16px; border: 0; background: #f5f6fa; color: #17213b; cursor: pointer; font-weight: 700; }}
  main {{ max-width: 1080px; margin: 0 auto; padding: 42px 24px; }}
  .welcome, .panel, .metric {{ border-radius: 6px; background: white; box-shadow: 0 8px 24px #17213b10; }}
  .welcome {{ padding: 28px; border-left: 5px solid #343b86; }}
  .eyebrow {{ color: #535e91; font-size: 11px; font-weight: 800; letter-spacing: .12em; }}
  h1 {{ margin: 10px 0; font-size: clamp(26px, 4vw, 36px); font-weight: 500; }}
  .subtle {{ color: #69718a; line-height: 1.6; }}
  .metrics {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin: 20px 0; }}
  .metric {{ padding: 20px; }}
  .metric strong {{ display: block; margin-top: 10px; color: #171b4b; font-size: 23px; }}
  .panel {{ margin-top: 20px; padding: 24px; overflow-x: auto; }}
  h2 {{ margin: 0 0 18px; font-size: 20px; }}
  table {{ width: 100%; border-collapse: collapse; text-align: left; }}
  th, td {{ padding: 13px 10px; border-bottom: 1px solid #e5e7ee; }}
  th {{ color: #535e91; font-size: 12px; }}
  .notice {{ margin-top: 18px; color: #69718a; font-size: 12px; }}
  @media (max-width: 620px) {{ .metrics {{ grid-template-columns: 1fr; }} main {{ padding: 24px 16px; }} }}
</style></head>
<body>
  <header><span class="brand">CAMPUS SENTINEL<small>FICTIONAL STUDENT PORTAL</small></span>
    <div>
      <form method="post" action="./forget-device"><button type="submit">Forget this trusted device</button></form>
      <form method="post" action="./logout"><button type="submit">Sign out</button></form>
    </div>
  </header>
  <main>
    <section class="welcome">
      <span class="eyebrow">DEMO STUDENT DASHBOARD</span>
      <h1>Welcome, {student_name}</h1>
      <p class="subtle">Your fictional academic overview. Demo account: <strong>{safe_usn}</strong></p>
    </section>
    <section class="metrics" aria-label="Academic summary">
      <div class="metric">Program<strong>Computer Science</strong></div>
      <div class="metric">Current term<strong>Semester 4</strong></div>
      <div class="metric">Demo GPA<strong>8.7 / 10</strong></div>
    </section>
    <section class="panel">
      <h2>Recent results</h2>
      <table><thead><tr><th>Course</th><th>Term</th><th>Grade</th><th>Status</th></tr></thead>
      <tbody>
        <tr><td>Data Structures</td><td>Semester 3</td><td>A</td><td>Completed</td></tr>
        <tr><td>Digital Systems</td><td>Semester 3</td><td>A-</td><td>Completed</td></tr>
        <tr><td>Discrete Mathematics</td><td>Semester 3</td><td>B+</td><td>Completed</td></tr>
      </tbody></table>
      <p class="notice">All names, grades, courses, and student identifiers on this page are synthetic demo data.</p>
    </section>
  </main>
</body></html>"""
        return HTMLResponse(page)

    @app.post("/logout")
    def logout(request: Request):
        session_token = request.cookies.get("campus_demo_access", "")
        active_sessions.pop(session_token, None)
        response = RedirectResponse("/", status_code=303)
        response.delete_cookie("campus_demo_access", path="/")
        return response

    return app
