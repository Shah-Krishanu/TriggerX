import json
import unittest

from adapters.log_reader import event_from_json_line, event_from_line


class LogReaderTests(unittest.TestCase):
    def test_parses_sanitized_json_event_and_normalizes_method(self) -> None:
        event = {
            "ts": "2026-11-25T18:07:00Z",
            "site": "results",
            "ip": "192.0.2.10",
            "path": "/login",
            "method": "post",
            "status": 401,
            "user_hash": "salted-hash",
        }

        parsed = event_from_json_line(json.dumps(event))

        self.assertEqual(parsed["method"], "POST")
        self.assertEqual(parsed["user_hash"], "salted-hash")
        self.assertEqual(parsed["ua"], "")

    def test_rejects_malformed_and_unsanitized_json_events(self) -> None:
        valid = {
            "ts": "2026-11-25T18:07:00Z",
            "site": "results",
            "ip": "192.0.2.10",
            "path": "/login",
            "method": "POST",
            "status": 401,
        }

        self.assertIsNone(event_from_json_line("{not json"))
        self.assertIsNone(event_from_json_line(json.dumps({**valid, "password": "secret"})))
        self.assertIsNone(event_from_json_line(json.dumps({**valid, "status": True})))
        self.assertIsNone(event_from_json_line(json.dumps({**valid, "ts": "not-a-timestamp"})))

    def test_skips_combined_log_with_invalid_timestamp(self) -> None:
        line = '192.0.2.10 - - [not-a-date] "POST /login HTTP/1.1" 401 10 "-" "test"'

        self.assertIsNone(event_from_line(line, "results"))


if __name__ == "__main__":
    unittest.main()
