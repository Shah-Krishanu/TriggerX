import hmac
import os
from datetime import datetime, timezone

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from core import engine
from core.agent import explain
from notify.telegram import send_alert
app = FastAPI(title="Campus Sentinel API", version="0.1.0")


class Event(BaseModel):
    ts: str
    site: str = Field(min_length=1, max_length=80)
    ip: str = Field(min_length=1, max_length=64)
    user_hash: str = Field(default="", max_length=128)
    path: str = Field(min_length=1, max_length=2048)
    method: str = Field(min_length=1, max_length=16)
    status: int = Field(ge=100, le=599)
    ua: str = Field(default="", max_length=512)


class UnblockRequest(BaseModel):
    ip: str


@app.on_event("startup")
def startup() -> None:
    engine.initialize()


@app.get("/health")
def health() -> dict:
    return {"ok": True}


@app.post("/event")
async def receive_event(event: Event) -> dict:
    try:
        datetime.fromisoformat(event.ts.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="ts must be ISO 8601") from exc
    alert = await engine.record_event(event.model_dump(), explain)
    if alert and alert["score"] >= 70:
        await send_alert(alert)
    response = {"ok": True}
    if alert:
        response["alert"] = alert
    return response


@app.get("/check")
def check(ip: str) -> dict:
    return engine.decision_for_ip(ip)


@app.get("/alerts")
def alerts() -> list[dict]:
    return engine.list_alerts()


@app.get("/blocked")
def blocked() -> list[dict]:
    return engine.list_blocked()


@app.get("/pending")
def pending() -> list[dict]:
    return engine.list_pending()


@app.post("/approve/{pending_id}")
def approve(pending_id: int, x_admin_token: str = Header(default="")) -> dict:
    _require_admin(x_admin_token)
    if not engine.approve_pending(pending_id):
        raise HTTPException(status_code=404, detail="Pending action not found")
    return {"ok": True}


@app.post("/unblock")
def remove_block(
    request: UnblockRequest,
    x_admin_token: str = Header(default=""),
) -> dict:
    _require_admin(x_admin_token)
    engine.unblock(request.ip)
    return {"ok": True}


def _require_admin(token: str) -> None:
    expected = os.getenv("SENTINEL_ADMIN_TOKEN", "")
    if not expected or not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="Valid admin token required")
