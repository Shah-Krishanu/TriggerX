import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from core import engine
from core.api import app
from core.config import user_hash


class AdminActionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        engine.DB_PATH = str(Path(self.temp.name) / "sentinel.sqlite")
        self.previous_token = os.environ.get("SENTINEL_ADMIN_TOKEN")
        os.environ["SENTINEL_ADMIN_TOKEN"] = "test-admin-token"
        engine.initialize()
        with engine._connection() as db:
            db.execute(
                "INSERT INTO pending(action, ip, reason, created_at) VALUES (?, ?, ?, ?)",
                ("permanent_block", "192.0.2.30", "test", "2026-01-01T00:00:00+00:00"),
            )

    def tearDown(self) -> None:
        if self.previous_token is None:
            os.environ.pop("SENTINEL_ADMIN_TOKEN", None)
        else:
            os.environ["SENTINEL_ADMIN_TOKEN"] = self.previous_token
        self.temp.cleanup()

    def test_permanent_block_requires_admin_token(self) -> None:
        with TestClient(app) as client:
            self.assertEqual(client.post("/approve/1").status_code, 401)
            response = client.post(
                "/approve/1",
                headers={"X-Admin-Token": "test-admin-token"},
            )
            self.assertEqual(response.status_code, 200)
            self.assertIsNone(engine.list_blocked()[0]["until"])


class EventAlertApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.previous_db_path = engine.DB_PATH
        engine.DB_PATH = str(root / "sentinel.sqlite")
        self.previous_salt = os.environ.get("SALT")
        self.previous_honeypot = os.environ.get("HONEYPOT_FILE")
        os.environ["SALT"] = "api-test-only"
        honeypot_file = root / "honeypots.txt"
        honeypot_file.write_text("", encoding="utf-8")
        os.environ["HONEYPOT_FILE"] = str(honeypot_file)
        engine.initialize()

    def tearDown(self) -> None:
        engine.DB_PATH = self.previous_db_path
        if self.previous_salt is None:
            os.environ.pop("SALT", None)
        else:
            os.environ["SALT"] = self.previous_salt
        if self.previous_honeypot is None:
            os.environ.pop("HONEYPOT_FILE", None)
        else:
            os.environ["HONEYPOT_FILE"] = self.previous_honeypot
        self.temp.cleanup()

    def test_event_endpoint_returns_and_persists_explainable_alert(self) -> None:
        async def explain(site: str, score: int, reasons: list[str]) -> str:
            return f"Risk score {score}: " + "; ".join(reasons)

        base = datetime(2026, 11, 25, 18, 0, tzinfo=timezone.utc)
        event = {
            "site": "results",
            "ip": "192.0.2.40",
            "user_hash": user_hash("SYNTHETIC-ACCOUNT"),
            "path": "/login",
            "method": "POST",
            "status": 401,
            "ua": "fixture-client",
        }

        with patch("core.api.explain", new=explain), TestClient(app) as client:
            responses = []
            for attempt in range(3):
                payload = {
                    **event,
                    "ts": (base + timedelta(seconds=attempt * 10)).isoformat(),
                }
                response = client.post("/event", json=payload)
                self.assertEqual(response.status_code, 200)
                responses.append(response.json())

            self.assertEqual(responses[:2], [{"ok": True}, {"ok": True}])
            self.assertEqual(responses[2]["alert"]["score"], 35)
            self.assertEqual(
                responses[2]["alert"]["reasons"],
                [
                    "Three failed POST /login attempts for the same hashed account from this IP at this site within five minutes"
                ],
            )
            listed_alerts = client.get("/alerts").json()
            self.assertEqual(listed_alerts[0]["id"], responses[2]["alert"]["id"])
            self.assertEqual(client.get("/check", params={"ip": event["ip"]}).json()["action"], "allow")


if __name__ == "__main__":
    unittest.main()
