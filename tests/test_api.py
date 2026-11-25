import os
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from core import engine
from core.api import app


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


if __name__ == "__main__":
    unittest.main()
