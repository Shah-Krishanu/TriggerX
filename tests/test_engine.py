import asyncio
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from core import engine
from core.config import user_hash


class RiskEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        engine.DB_PATH = str(root / "sentinel.sqlite")
        engine.initialize()
        self.honeypot_file = root / "honeypots.txt"
        self.honeypot_file.write_text("DEMOHONEYPOT01\n", encoding="utf-8")
        self.previous_honeypot = engine.os.environ.get("HONEYPOT_FILE")
        engine.os.environ["HONEYPOT_FILE"] = str(self.honeypot_file)
        self.previous_salt = engine.os.environ.get("SALT")
        engine.os.environ["SALT"] = "test-only"

    def tearDown(self) -> None:
        if self.previous_honeypot is None:
            engine.os.environ.pop("HONEYPOT_FILE", None)
        else:
            engine.os.environ["HONEYPOT_FILE"] = self.previous_honeypot
        if self.previous_salt is None:
            engine.os.environ.pop("SALT", None)
        else:
            engine.os.environ["SALT"] = self.previous_salt
        self.temp.cleanup()

    def test_honeypot_blocks_temporarily_and_requires_approval_to_make_permanent(self) -> None:
        async def explain(site: str, score: int, reasons: list[str]) -> str:
            self.assertEqual(engine.decision_for_ip(event["ip"])["action"], "block")
            return "Template explanation"

        event = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "site": "results",
            "ip": "192.0.2.10",
            "user_hash": user_hash("DEMOHONEYPOT01"),
            "path": "/login",
            "method": "POST",
            "status": 401,
            "ua": "test-client",
        }
        alert = asyncio.run(engine.record_event(event, explain))
        self.assertEqual(alert["score"], 80)
        self.assertEqual(engine.decision_for_ip(event["ip"])["action"], "block")

        pending = engine.list_pending()
        self.assertEqual(len(pending), 1)
        self.assertTrue(engine.approve_pending(pending[0]["id"]))
        self.assertIsNone(engine.list_blocked()[0]["until"])
        self.assertEqual(engine.decision_for_ip(event["ip"])["action"], "block")

    def test_three_failed_logins_create_explainable_alert_without_enforcement(self) -> None:
        async def explain(site: str, score: int, reasons: list[str]) -> str:
            return f"Risk score {score}: " + "; ".join(reasons)

        base = datetime(2026, 11, 25, 18, 0, tzinfo=timezone.utc)
        event = {
            "site": "results",
            "ip": "192.0.2.20",
            "user_hash": user_hash("SYNTHETIC-ACCOUNT"),
            "path": "/login",
            "method": "POST",
            "status": 401,
            "ua": "fixture-client",
        }

        alerts = []
        for attempt in range(3):
            current = {**event, "ts": (base.replace(second=attempt * 10)).isoformat()}
            alerts.append(asyncio.run(engine.record_event(current, explain)))

        self.assertIsNone(alerts[0])
        self.assertIsNone(alerts[1])
        self.assertEqual(
            alerts[2]["reasons"],
            [
                "Three failed POST /login attempts for the same hashed account from this IP at this site within five minutes"
            ],
        )
        self.assertEqual(alerts[2]["score"], 35)
        self.assertEqual(engine.decision_for_ip(event["ip"])["action"], "allow")
        self.assertEqual(engine.list_blocked(), [])
        self.assertEqual(engine.list_pending(), [])

    def test_non_login_failure_does_not_count_toward_login_alert(self) -> None:
        async def explain(site: str, score: int, reasons: list[str]) -> str:
            return "Template explanation"

        base = datetime(2026, 11, 25, 18, 0, tzinfo=timezone.utc)
        event = {
            "site": "results",
            "ip": "192.0.2.21",
            "user_hash": user_hash("SYNTHETIC-ACCOUNT"),
            "path": "/login",
            "method": "POST",
            "status": 401,
            "ua": "fixture-client",
        }

        for attempt in range(2):
            current = {**event, "ts": (base.replace(second=attempt * 10)).isoformat()}
            self.assertIsNone(asyncio.run(engine.record_event(current, explain)))

        other_site = {
            **event,
            "ts": base.replace(second=15).isoformat(),
            "site": "library",
        }
        self.assertIsNone(asyncio.run(engine.record_event(other_site, explain)))

        unrelated = {
            **event,
            "ts": base.replace(second=25).isoformat(),
            "path": "/profile",
        }
        self.assertIsNone(asyncio.run(engine.record_event(unrelated, explain)))

        third_login = {**event, "ts": base.replace(second=30).isoformat()}
        alert = asyncio.run(engine.record_event(third_login, explain))
        self.assertEqual(alert["score"], 35)
    def test_successful_redirected_login_uses_failures_from_first_step(self) -> None:
        async def explain(site: str, score: int, reasons: list[str]) -> str:
            return "Template explanation"

        base_time = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        for attempt in range(3):
            event = {
                "ts": (base_time + timedelta(seconds=attempt)).isoformat(),
                "site": "results",
                "ip": "192.0.2.20",
                "user_hash": user_hash("DEMO0001"),
                "path": "/login/start",
                "method": "POST",
                "status": 401,
                "ua": "test-client",
            }
            asyncio.run(engine.record_event(event, explain))

        success = {
            "ts": (base_time + timedelta(seconds=4)).isoformat(),
            "site": "results",
            "ip": "192.0.2.20",
            "user_hash": user_hash("DEMO0001"),
            "path": "/login",
            "method": "POST",
            "status": 303,
            "ua": "test-client",
        }
        alert = asyncio.run(engine.record_event(success, explain))

        self.assertIn(
            "Successful login followed at least three failures for the same account",
            alert["reasons"],
        )


if __name__ == "__main__":
    unittest.main()
