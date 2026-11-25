import os
import time
from threading import Lock
from typing import Protocol


class OtpEmailSender(Protocol):
    def send_otp(self, recipient: str, code: str) -> None: ...


class DemoEmailOutbox:
    """Transient, in-memory fake inbox. This does not send email."""

    def __init__(self) -> None:
        self._messages: dict[str, tuple[str, int]] = {}
        self._lock = Lock()

    def send_otp(self, recipient: str, code: str) -> None:
        with self._lock:
            self._messages[recipient.lower()] = (code, int(time.time()) + 5 * 60)

    def read(self, recipient: str) -> str | None:
        with self._lock:
            entry = self._messages.get(recipient.lower())
            if entry is None:
                return None
            code, expires_at = entry
            if expires_at <= int(time.time()):
                self._messages.pop(recipient.lower(), None)
                return None
            return code

    def clear(self, recipient: str) -> None:
        with self._lock:
            self._messages.pop(recipient.lower(), None)


demo_outbox = DemoEmailOutbox()


def demo_inbox_enabled() -> bool:
    return os.getenv("CAMPUS_DEMO_EMAIL_INBOX", "false").lower() == "true"


def get_otp_email_sender() -> OtpEmailSender:
    """Provider seam; live email delivery is intentionally not configured."""
    provider = os.getenv("CAMPUS_EMAIL_PROVIDER", "demo").lower()
    if provider != "demo":
        raise RuntimeError(
            f"Email provider {provider!r} is not implemented; use the demo inbox."
        )
    return demo_outbox
