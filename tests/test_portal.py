import unittest
from unittest.mock import patch

import httpx
from fastapi.testclient import TestClient

from apps.base import create_app
from core.config import user_hash
import proxy.app as proxy_module


class CampusPortalTests(unittest.TestCase):
    def test_portal_form_uses_proxy_prefix_and_shows_fake_credentials(self) -> None:
        client = TestClient(create_app("results"))

        response = client.get("/", headers={"x-forwarded-prefix": "/results"})

        self.assertEqual(response.status_code, 200)
        self.assertIn('action="/results/login"', response.text)
        self.assertIn("DEMO0001", response.text)
        self.assertIn("DEMO-ID-0001", response.text)
        self.assertIn("SYNTHETIC DEMO", response.text)
        library_response = TestClient(create_app("library")).get(
            "/",
            headers={"x-forwarded-prefix": "/library"},
        )
        self.assertIn('action="/library/login"', library_response.text)
        self.assertNotIn("Campus ID", library_response.text)

    def test_fake_login_is_visible_in_browser_and_json_api(self) -> None:
        client = TestClient(create_app("results"))
        credentials = {
            "usn": "DEMO0001",
            "dob": "2005-01-01",
            "id_no": "DEMO-ID-0001",
        }

        accepted = client.post("/login", data=credentials)
        rejected = client.post("/login", data={**credentials, "dob": "2000-01-01"})
        json_response = client.post("/login", json=credentials)

        self.assertEqual(accepted.status_code, 200)
        self.assertIn("Demo sign-in successful", accepted.text)
        self.assertEqual(rejected.status_code, 401)
        self.assertIn("Sign-in not verified", rejected.text)
        self.assertEqual(json_response.json()["ok"], True)

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
                    headers={"content-type": "text/plain"},
                )

        with (
            patch.object(proxy_module, "_check", new=allow_request),
            patch.object(proxy_module, "_send_event", new=capture_event),
            patch.object(proxy_module.httpx, "AsyncClient", FakeUpstreamClient),
            TestClient(proxy_module.app) as client,
        ):
            response = client.post(
                "/results/login",
                data={
                    "usn": "DEMO0001",
                    "dob": "2000-01-01",
                    "id_no": "DEMO-ID-0001",
                },
                headers={"user-agent": "synthetic-browser"},
            )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(requests[0][2]["x-forwarded-prefix"], "/results")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["user_hash"], user_hash("DEMO0001"))
        self.assertEqual(events[0]["path"], "/login")
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


if __name__ == "__main__":
    unittest.main()
