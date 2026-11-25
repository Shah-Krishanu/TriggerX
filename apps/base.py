from urllib.parse import parse_qs

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from faker import Faker

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


def create_app(site: str) -> FastAPI:
    app = FastAPI(title=f"Fake {site.title()} Campus Portal")

    @app.get("/health")
    def health() -> dict:
        return {"ok": True, "site": site}

    @app.get("/directory")
    def directory() -> list[dict]:
        return [{"usn": usn, "name": DEMO_NAMES[usn]} for usn in DEMO_ACCOUNTS]

    @app.get("/")
    def home() -> HTMLResponse:
        fields = '<input name="id_no" placeholder="Synthetic ID number">' if site == "results" else ""
        page = f"""<!doctype html>
<html><head><title>{site.title()} Campus Portal</title></head>
<body><h1>Demo {site.title()} Portal</h1>
<p>Fictional data only. Test account range: DEMO0001–DEMO0020.</p>
<form method="post" action="/login">
<input name="usn" placeholder="Synthetic USN" required>
<input name="dob" placeholder="YYYY-MM-DD" required>
{fields}<button type="submit">Sign in</button></form></body></html>"""
        return HTMLResponse(page)

    @app.post("/login")
    async def login(request: Request):
        content_type = request.headers.get("content-type", "")
        body = await request.body()
        if "application/json" in content_type:
            import json
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
        return JSONResponse(
            {"ok": True, "message": "Demo login accepted"}
            if valid else {"ok": False, "message": "Invalid demo credentials"},
            status_code=200 if valid else 401,
        )

    return app
