import html
import json
from urllib.parse import parse_qs

from faker import Faker
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

DEMO_ACCOUNTS = {
    f"DEMO{number:04d}": {
        "dob": "2005-01-01",
        "id_no": f"DEMO-ID-{number:04d}",
    }
    for number in range(1, 21)
}
fake = Faker()
Faker.seed(4810)
DEMO_NAMES = {usn: fake.name() for usn in DEMO_ACCOUNTS}

STYLES = """
* { box-sizing: border-box; }
body { margin: 0; background: #f3f6fb; color: #17243b; font: 16px/1.5 system-ui, sans-serif; }
a { color: #185adb; }
.topbar { display: flex; align-items: center; justify-content: space-between; padding: 18px max(24px, calc((100% - 1040px) / 2)); background: #102a56; color: #fff; }
.brand { color: #fff; font-size: 1.2rem; font-weight: 700; text-decoration: none; }
.tag { color: #c4d6ff; font-size: .75rem; font-weight: 700; letter-spacing: .12em; }
.shell { max-width: 1040px; margin: 52px auto; padding: 0 24px; }
.eyebrow { color: #54709a; font-size: .75rem; font-weight: 700; letter-spacing: .15em; text-transform: uppercase; }
h1 { margin: 8px 0; font-size: clamp(2rem, 5vw, 3rem); line-height: 1.1; }
.intro { max-width: 650px; color: #53627a; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 20px; margin-top: 30px; }
.card, .sample, .notice { border: 1px solid #dce4f0; border-radius: 14px; background: #fff; padding: 24px; box-shadow: 0 8px 24px #17243b0b; }
.card h2 { margin: 0 0 8px; }
.card p { color: #53627a; }
label { display: block; margin: 14px 0 6px; font-size: .9rem; font-weight: 650; }
input { width: 100%; padding: 12px; border: 1px solid #bdc9da; border-radius: 8px; color: inherit; font: inherit; }
input:focus { outline: 3px solid #b8d0ff; border-color: #185adb; }
button { margin-top: 18px; border: 0; border-radius: 8px; background: #185adb; color: #fff; cursor: pointer; font: inherit; font-weight: 650; padding: 12px 18px; }
.sample { margin-top: 20px; background: #eaf1ff; }
.sample h2 { margin-top: 0; font-size: 1rem; }
.sample code { color: #173c83; }
.notice { max-width: 700px; border-left: 5px solid #2e8b57; }
.notice.failure { border-left-color: #c64b4b; }
.back { display: inline-block; margin-top: 22px; }
.services a { display: inline-block; margin: 8px 14px 0 0; font-weight: 650; }
@media (max-width: 560px) { .shell { margin: 32px auto; } .topbar { padding: 16px 20px; } }
"""


def _document(title: str, content: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)} | Campus Hub</title>
  <style>{STYLES}</style>
</head>
<body>{content}</body>
</html>"""


def create_app(site: str) -> FastAPI:
    app = FastAPI(title=f"Campus Hub {site.title()} Demo")
    site_name = "Results" if site == "results" else "Library"

    @app.get("/health")
    def health() -> dict:
        return {"ok": True, "site": site}

    @app.get("/directory")
    def directory() -> list[dict]:
        return [{"usn": usn, "name": DEMO_NAMES[usn]} for usn in DEMO_ACCOUNTS]

    @app.get("/", response_class=HTMLResponse)
    def home(request: Request) -> HTMLResponse:
        prefix = request.headers.get("x-forwarded-prefix", "").rstrip("/")
        id_field = ""
        if site == "results":
            id_field = """
            <label for="id_no">Demo campus ID</label>
            <input id="id_no" name="id_no" autocomplete="off" required>
            """
        example_id = (
            '<br>Campus ID: <code>DEMO-ID-0001</code>'
            if site == "results" else ""
        )
        content = f"""
<header class="topbar"><a class="brand" href="/">Campus Hub</a><span class="tag">SYNTHETIC DEMO</span></header>
<main class="shell">
  <div class="eyebrow">Student services · {site_name}</div>
  <h1>{site_name} portal</h1>
  <p class="intro">A fictional campus service used to demonstrate safer sign-in monitoring.
  Use the sample account below; no real student data is involved.</p>
  <div class="grid">
    <section class="card">
      <h2>Sign in to {site_name.lower()}</h2>
      <form method="post" action="{html.escape(prefix)}/login">
        <label for="usn">Demo account</label>
        <input id="usn" name="usn" autocomplete="off" required>
        <label for="dob">Demo date of birth</label>
        <input id="dob" name="dob" type="date" required>
        {id_field}
        <button type="submit">Continue</button>
      </form>
    </section>
    <aside class="sample">
      <h2>Sample credentials</h2>
      <div>Account: <code>DEMO0001</code></div>
      <div>Date of birth: <code>2005-01-01</code>{example_id}</div>
      <p>For an alert demo, use this account and submit a wrong date of birth three times.</p>
    </aside>
  </div>
  <a class="back" href="/">All Campus Hub services</a>
</main>"""
        return HTMLResponse(_document(f"{site_name} Portal", content))

    @app.post("/login")
    async def login(request: Request):
        content_type = request.headers.get("content-type", "")
        body = await request.body()
        if "application/json" in content_type:
            try:
                values = json.loads(body or b"{}")
            except json.JSONDecodeError:
                return JSONResponse({"ok": False}, status_code=400)
            if not isinstance(values, dict):
                return JSONResponse({"ok": False}, status_code=400)
        else:
            parsed = parse_qs(body.decode("utf-8", errors="replace"))
            values = {key: items[0] for key, items in parsed.items() if items}
        usn = str(values.get("usn", "")).strip().upper()
        account = DEMO_ACCOUNTS.get(usn)
        valid = bool(account and values.get("dob") == account["dob"])
        if site == "results":
            valid = valid and values.get("id_no") == account["id_no"] if account else False

        status = 200 if valid else 401
        message = "Demo sign-in accepted" if valid else "Invalid demo credentials"
        if "application/json" in content_type:
            return JSONResponse(
                {"ok": valid, "message": message},
                status_code=status,
            )

        notice_class = "notice" if valid else "notice failure"
        heading = "Demo sign-in successful" if valid else "Sign-in not verified"
        guidance = (
            "You are signed in to this fictional campus service."
            if valid
            else "Check the sample credentials and try again. This demo never uses a real student account."
        )
        content = f"""
<header class="topbar"><a class="brand" href="/">Campus Hub</a><span class="tag">SYNTHETIC DEMO</span></header>
<main class="shell">
  <div class="{notice_class}">
    <div class="eyebrow">{site_name} portal</div>
    <h1>{heading}</h1>
    <p>{guidance}</p>
  </div>
  <a class="back" href="/">Return to Campus Hub</a>
</main>"""
        return HTMLResponse(_document(f"{site_name} sign-in", content), status_code=status)

    return app
