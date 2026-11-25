import logging
import os

import httpx

logger = logging.getLogger(__name__)


async def explain(site: str, score: int, reasons: list[str]) -> str:
    fallback = f"Risk score {score}: " + "; ".join(reasons)
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return fallback

    prompt = (
        "Explain this campus website security alert in one short, plain-language sentence. "
        "Do not recommend actions; the rule engine has already decided them. "
        f"Site: {site}. Risk score: {score}. Signals: {', '.join(reasons)}."
    )
    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"gemini-2.5-flash:generateContent?key={api_key}"
    )
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.post(
                url,
                json={"contents": [{"parts": [{"text": prompt}]}]},
            )
            response.raise_for_status()
            payload = response.json()
        text = payload["candidates"][0]["content"]["parts"][0]["text"].strip()
        return text or fallback
    except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError) as exc:
        logger.warning("Gemini explanation unavailable; using template: %s", exc)
        return fallback
