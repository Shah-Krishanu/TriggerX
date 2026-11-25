import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from pathlib import Path

import httpx
from fastapi.testclient import TestClient

from apps import auth
from apps.base import DEMO_EMAILS, create_app
from apps.email_delivery import demo_outbox, get_otp_email_sender
from core.config import user_hash
import proxy.app as proxy_module


class CampusPortalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.previous_db_path = auth.DB_PATH
        auth.DB_PATH = str(Path(self.temp.name) / "campus-auth.sqlite")
        self.previous_salt = os.environ.get("SALT")
        self.previous_inbox = os.environ.get("CAMPUS_DEMO_EMAIL_INBOX")
        self.previous_provider = os.environ.get("CAMPUS_EMAIL_PROVIDER")
        os.environ["SALT"] = "campus-otp-test-secret"
        os.environ["CAMPUS_DEMO_EMAIL_INBOX"] = "true"
        os.environ["CAMPUS_EMAIL_PROVIDER"] = "demo"
        auth.initialize()

    def tearDown(self) -> None:
        auth.DB_PATH = self.previous_db_path
        for key, previous in (
            ("SALT", self.previous_salt),
            ("CAMPUS_DEMO_EMAIL_INBOX", self.previous_inbox),
            ("CAMPUS_EMAIL_PROVIDER", self.previous_provider),
        ):
            if previous is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = previous
        self.temp.cleanup()

    def test_portal_form_uses_proxy_prefix_and_shows_fake_credentials(self) -> None:
        client = TestClient(create_app("results"))

        response = client.get("/", headers={"x-forwarded-prefix": "/results"})

        self.assertEqual(response.status_code, 200)
        self.assertIn('action="login/start"', response.text)
        self.assertIn("DEMO0001", response.text)
        self.assertIn("DEMO-ID-0001", response.text)
        self.assertIn("FICTIONAL DATA ONLY", response.text)
        library_response = TestClient(create_app("library")).get(
            "/",
            headers={"x-forwarded-prefix": "/library"},
        )
        self.assertIn('action="login"', library_response.text)
        self.assertNotIn("Campus ID", library_response.text)

    def test_fake_login_uses_id_step_and_requires_email_otp(self) -> None:
        credentials = {
            "usn": "DEMO0001",
            "dob": "2005-01-01",
            "id_no": "DEMO-ID-0001",
        }

        with TestClient(create_app("results")) as client:
            rejected = client.post(
                "/login/start",
                data={
                    "usn": credentials["usn"],
                    "dob_day": "01",
                    "dob_month": "01",
                    "dob_year": "2000",
                },
            )
            first_step = client.post(
                "/login/start",
                data={
                    "usn": credentials["usn"],
                    "dob_day": "01",
                    "dob_month": "01",
                    "dob_year": "2005",
                },
                follow_redirects=False,
            )
            id_page = client.get(first_step.headers["location"])
            challenge = client.post(
                "/login",
                data={"usn": credentials["usn"], "id_no": credentials["id_no"]},
                follow_redirects=False,
            )
            self.assertEqual(rejected.status_code, 401)
            self.assertEqual(first_step.status_code, 303)
            self.assertIn("Enter the demo ID card number", id_page.text)
            self.assertEqual(challenge.status_code, 202)
            self.assertIn("Verify this new device", challenge.text)
            self.assertIn("demo-inbox/DEMO0001", challenge.text)
            self.assertIn("demo0001@students.campus.test", challenge.text)

            inbox = client.get("/demo-inbox/DEMO0001")
            code = demo_outbox.read(DEMO_EMAILS["DEMO0001"])
            self.assertEqual(inbox.status_code, 200)
            self.assertIn(code, inbox.text)
            self.assertEqual(len(code), 6)
            self.assertRegex(code, r"^[0-9]{6}$")
            with auth._connection() as db:
                stored_challenge = db.execute(
                    "SELECT token_hash, otp_hash FROM otp_challenges"
                ).fetchone()
            raw_challenge = client.cookies.get(auth.CHALLENGE_COOKIE)
            self.assertNotEqual(stored_challenge["token_hash"], raw_challenge)
            self.assertNotEqual(stored_challenge["otp_hash"], code)

            verified = client.post(
                "/verify-otp",
                data={"code": code},
                follow_redirects=False,
            )
            self.assertEqual(verified.status_code, 303)
            self.assertEqual(verified.headers["location"], "/dashboard")
            dashboard = client.get(verified.headers["location"])
            self.assertIn("DEMO STUDENT DASHBOARD", dashboard.text)
            self.assertIn("httponly", verified.headers["set-cookie"].lower())
            self.assertIsNone(demo_outbox.read(DEMO_EMAILS["DEMO0001"]))

            with auth._connection() as db:
                stored_device = db.execute(
                    "SELECT token_hash FROM trusted_devices"
                ).fetchone()["token_hash"]
                challenge_rows = db.execute("SELECT COUNT(*) AS count FROM otp_challenges").fetchone()
            raw_device_token = client.cookies.get(auth.TRUSTED_DEVICE_COOKIE)
            self.assertEqual(len(stored_device), 64)
            self.assertNotEqual(stored_device, raw_device_token)
            self.assertEqual(challenge_rows["count"], 0)
            self.assertEqual(auth.verify_challenge(raw_challenge, code)[0], "missing")
            self.assertFalse(auth.is_trusted_device("DEMO0002", raw_device_token))

            trusted_login = client.post("/login", json=credentials)
            self.assertEqual(trusted_login.status_code, 200)
            self.assertIn("Trusted-device sign-in accepted", trusted_login.text)

            forgotten = client.post("/forget-device")
            self.assertEqual(forgotten.status_code, 200)
            self.assertIn("Trusted device forgotten", forgotten.text)
            new_challenge = client.post("/login", json=credentials)
            self.assertEqual(new_challenge.status_code, 202)

    def test_json_login_also_requires_otp_before_trusting_device(self) -> None:
        credentials = {
            "usn": "DEMO0002",
            "dob": "2005-01-01",
            "id_no": "DEMO-ID-0002",
        }

        with TestClient(create_app("results")) as client:
            challenge = client.post("/login", json=credentials)
            self.assertEqual(challenge.status_code, 202)
            self.assertTrue(challenge.json()["requires_otp"])
            self.assertNotIn("code", challenge.json())

            code = demo_outbox.read(DEMO_EMAILS["DEMO0002"])
            verified = client.post("/verify-otp", json={"code": code})
            self.assertEqual(verified.status_code, 200)
            trusted = client.post("/login", json=credentials)
            self.assertEqual(trusted.status_code, 200)
            self.assertFalse(trusted.json().get("requires_otp", False))

    def test_wrong_and_expired_codes_are_rejected(self) -> None:
        with TestClient(create_app("results")) as client:
            challenge = client.post(
                "/login",
                json={
                    "usn": "DEMO0003",
                    "dob": "2005-01-01",
                    "id_no": "DEMO-ID-0003",
                },
            )
            self.assertEqual(challenge.status_code, 202)

            code = demo_outbox.read(DEMO_EMAILS["DEMO0003"])
            wrong_code = "000000" if code != "000000" else "000001"
            wrong = client.post("/verify-otp", data={"code": wrong_code})
            self.assertEqual(wrong.status_code, 401)
            self.assertIn("Incorrect code", wrong.text)

            raw_challenge = client.cookies.get(auth.CHALLENGE_COOKIE)
            expiry = auth._now() + auth.OTP_TTL_SECONDS + 1
            with patch.object(auth, "_now", return_value=expiry):
                expired = client.post("/verify-otp", data={"code": code})
            self.assertEqual(expired.status_code, 401)
            self.assertIn("expired", expired.text.lower())
            self.assertIsNone(client.cookies.get(auth.CHALLENGE_COOKIE))
            self.assertEqual(auth.verify_challenge(raw_challenge, code)[0], "missing")

    def test_trusted_device_server_expiry_is_enforced(self) -> None:
        raw_token = auth.trust_device("DEMO0006", now=1000)
        expiry = 1000 + auth.TRUSTED_DEVICE_SECONDS
        self.assertTrue(auth.is_trusted_device("DEMO0006", raw_token, now=expiry - 1))
        self.assertFalse(auth.is_trusted_device("DEMO0006", raw_token, now=expiry))

    def test_challenge_rate_limit_and_attempt_cap(self) -> None:
        first = auth.create_challenge("DEMO0004", now=1000)
        second = auth.create_challenge("DEMO0004", now=1001)
        third = auth.create_challenge("DEMO0004", now=1002)
        self.assertIsNotNone(first)
        self.assertIsNotNone(second)
        self.assertIsNotNone(third)
        self.assertIsNone(auth.create_challenge("DEMO0004", now=1003))

        token, code = auth.create_challenge("DEMO0005", now=1000)
        invalid_code = "000001" if code != "000001" else "000002"
        for _ in range(auth.OTP_MAX_ATTEMPTS - 1):
            status, _ = auth.verify_challenge(token, invalid_code, now=1001)
            self.assertEqual(status, "invalid")
        status, _ = auth.verify_challenge(token, invalid_code, now=1001)
        self.assertEqual(status, "locked")
        status, _ = auth.verify_challenge(token, code, now=1001)
        self.assertEqual(status, "missing")

    def test_otp_can_only_be_consumed_once_under_concurrent_submissions(self) -> None:
        token, code = auth.create_challenge("DEMO0012")
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(
                pool.map(
                    lambda _: auth.verify_challenge(token, code)[0],
                    range(2),
                )
            )
        self.assertCountEqual(results, ["verified", "missing"])

    def test_unimplemented_email_provider_fails_closed(self) -> None:
        with patch.dict(os.environ, {"CAMPUS_EMAIL_PROVIDER": "gmail"}):
            with self.assertRaisesRegex(RuntimeError, "not implemented"):
                get_otp_email_sender()

    def test_proxy_forwards_only_a_hashed_login_identifier(self) -> None:
        events = []
        requests = []

        async def allow_request(ip: str) -> str:
            return "allow"

        async def capture_event(event: dict) -> None:
            events.append(event)

        class FakeUpstreamClient:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc_value, traceback):
                return None

            async def request(self, method: str, url: str, **kwargs):
                requests.append((method, url, kwargs["headers"]))
                return httpx.Response(
                    401,
                    content=b"Sign-in not verified",
                    headers=[
                        ("content-type", "text/plain"),
                        ("set-cookie", "challenge=one; HttpOnly"),
                        ("set-cookie", "trusted=two; HttpOnly"),
                    ],
                )

        with (
            patch.object(proxy_module, "_check", new=allow_request),
            patch.object(proxy_module, "_send_event", new=capture_event),
            patch.object(proxy_module.httpx, "AsyncClient", FakeUpstreamClient),
            TestClient(proxy_module.app) as client,
        ):
            response = client.post(
                "/results/login/start",
                data={
                    "usn": "DEMO0001",
                    "dob": "2000-01-01",
                    "id_no": "DEMO-ID-0001",
                },
                headers={
                    "user-agent": "synthetic-browser",
                    "x-forwarded-proto": "https",
                },
            )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.headers.get_list("set-cookie"),
            ["challenge=one; HttpOnly", "trusted=two; HttpOnly"],
        )
        self.assertEqual(requests[0][2]["x-forwarded-prefix"], "/results")
        self.assertEqual(requests[0][2]["x-forwarded-proto"], "http")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["user_hash"], user_hash("DEMO0001"))
        self.assertEqual(events[0]["path"], "/login/start")
        self.assertEqual(events[0]["status"], 401)
        self.assertNotIn("DEMO0001", str(events[0]))
        self.assertNotIn("2000-01-01", str(events[0]))
        self.assertNotIn("DEMO-ID-0001", str(events[0]))

    def test_proxy_root_links_to_both_simulated_portals(self) -> None:
        with TestClient(proxy_module.app) as client:
            response = client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn('href="/results/"', response.text)
        self.assertIn('href="/library/"', response.text)
        self.assertIn("Campus Hub", response.text)

    def test_https_deployment_marks_challenge_cookie_secure(self) -> None:
        credentials = {
            "usn": "DEMO0007",
            "dob": "2005-01-01",
            "id_no": "DEMO-ID-0007",
        }

        with TestClient(create_app("results"), base_url="https://testserver") as client:
            response = client.post("/login", json=credentials)

        self.assertEqual(response.status_code, 202)
        self.assertIn("secure", response.headers["set-cookie"].lower())


if __name__ == "__main__":
    unittest.main()
