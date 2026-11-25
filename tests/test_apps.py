import unittest

from fastapi.testclient import TestClient

from apps.base import create_app


class DemoPortalTests(unittest.TestCase):
    def test_results_portal_renders_first_authentication_step(self) -> None:
        with TestClient(create_app("results")) as client:
            response = client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn('action="login/start"', response.text)
        self.assertIn("FICTIONAL COLLEGE PORTAL", response.text)
        self.assertIn('id="demo-id-step" hidden', response.text)

    def test_results_authentication_redirects_through_id_card_to_dashboard(self) -> None:
        with TestClient(create_app("results")) as client:
            first_step = client.post(
                "/login/start",
                data={
                    "usn": "DEMO0001",
                    "dob_day": "01",
                    "dob_month": "01",
                    "dob_year": "2005",
                },
                follow_redirects=False,
            )
            id_page = client.get(first_step.headers["location"])
            dashboard_redirect = client.post(
                "/login",
                data={"usn": "DEMO0001", "id_no": "DEMO-ID-0001"},
                follow_redirects=False,
            )
            dashboard = client.get(dashboard_redirect.headers["location"])

        self.assertEqual(first_step.status_code, 303)
        self.assertEqual(first_step.headers["location"], "/id-card")
        self.assertIn("Enter the demo ID card number", id_page.text)
        self.assertEqual(dashboard_redirect.status_code, 303)
        self.assertEqual(dashboard_redirect.headers["location"], "/dashboard")
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn("DEMO STUDENT DASHBOARD", dashboard.text)
        self.assertIn("DEMO0001", dashboard.text)

    def test_first_step_rejects_non_demo_credentials(self) -> None:
        with TestClient(create_app("results")) as client:
            response = client.post(
                "/login/start",
                data={
                    "usn": "REALSTUDENT",
                    "dob_day": "01",
                    "dob_month": "01",
                    "dob_year": "2005",
                },
            )

        self.assertEqual(response.status_code, 401)
        self.assertIn("Those demo username and date values did not match.", response.text)

    def test_library_login_keeps_synthetic_usn_and_dob_flow(self) -> None:
        with TestClient(create_app("library")) as client:
            response = client.post(
                "/login",
                data={
                    "usn": "DEMO0001",
                    "dob_day": "01",
                    "dob_month": "01",
                    "dob_year": "2005",
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"ok": True, "message": "Demo login accepted"})


if __name__ == "__main__":
    unittest.main()
