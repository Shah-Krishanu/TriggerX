import logging
import os

import httpx

logger = logging.getLogger(__name__)


async def send_alert(alert: dict) -> None:
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        return
    text = (
        f"Campus Sentinel: {alert['site']} risk {alert['score']} from "
        f"{alert['ip']}. {alert['explanation']}"
    )
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={"chat_id": chat_id, "text": text},
            )
            response.raise_for_status()
    except httpx.HTTPError as exc:
        logger.warning("Telegram alert failed: %s", exc)
