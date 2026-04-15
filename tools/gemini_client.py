"""
Gemini REST API client — calls the Gemini 2.0 Flash model directly
via HTTP so we don't depend on any specific version of the SDK.
"""

import json
import logging
import re
import time
from typing import Optional

import requests

logger = logging.getLogger(__name__)

GEMINI_API_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    "gemini-2.0-flash:generateContent"
)

_DEFAULT_GENERATION_CONFIG = {
    "temperature": 0.2,
    "topP": 0.8,
    "topK": 40,
    "maxOutputTokens": 8192,
}


class GeminiClient:
    """Thin wrapper around the Gemini REST API with exponential backoff."""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
        # Track last request time to enforce minimum spacing
        self._last_request_time = 0.0
        self._min_request_interval = 4.0  # seconds between requests (free tier: 15 RPM)

    def generate(
        self,
        prompt: str,
        max_retries: int = 5,
        base_retry_delay: float = 15.0,
    ) -> str:
        """
        Send a text prompt to Gemini and return the response text.
        Uses exponential backoff on 429 rate-limit responses.

        Raises:
            RuntimeError: if all retries are exhausted.
        """
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": _DEFAULT_GENERATION_CONFIG,
            "safetySettings": [
                {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
            ],
        }

        url = f"{GEMINI_API_URL}?key={self.api_key}"

        for attempt in range(1, max_retries + 1):
            # Enforce minimum spacing between requests
            elapsed = time.time() - self._last_request_time
            if elapsed < self._min_request_interval:
                time.sleep(self._min_request_interval - elapsed)

            try:
                self._last_request_time = time.time()
                response = self.session.post(url, json=payload, timeout=120)

                # Extract status before raise_for_status so we can inspect it
                status_code = response.status_code

                if status_code == 429:
                    # Exponential backoff: 15s, 30s, 60s, 120s, 240s
                    wait = base_retry_delay * (2 ** (attempt - 1))
                    logger.warning(
                        f"[Gemini] Rate limited (429). Waiting {wait:.0f}s "
                        f"before retry {attempt}/{max_retries}..."
                    )
                    time.sleep(wait)
                    continue

                if status_code in (500, 502, 503, 504):
                    wait = base_retry_delay
                    logger.warning(
                        f"[Gemini] Server error {status_code}. Waiting {wait}s "
                        f"before retry {attempt}/{max_retries}..."
                    )
                    time.sleep(wait)
                    continue

                response.raise_for_status()
                data = response.json()
                return self._extract_text(data)

            except requests.exceptions.HTTPError as e:
                # Catch any remaining HTTP errors not handled above
                logger.error(f"[Gemini] HTTP error on attempt {attempt}: {e}")
                if attempt >= max_retries:
                    raise RuntimeError(f"Gemini API HTTP error: {e}") from e
                time.sleep(base_retry_delay)

            except requests.exceptions.Timeout:
                logger.warning(f"[Gemini] Request timed out (attempt {attempt}/{max_retries})")
                if attempt < max_retries:
                    time.sleep(base_retry_delay)

            except Exception as e:
                logger.error(f"[Gemini] Unexpected error: {e}")
                raise RuntimeError(f"Gemini request failed: {e}") from e

        raise RuntimeError(f"Gemini API failed after {max_retries} retries")

    def generate_json(self, prompt: str, max_retries: int = 5) -> any:
        """
        Generate a response and parse it as JSON.
        Strips markdown code fences before parsing.
        """
        text = self.generate(prompt, max_retries=max_retries)
        return parse_json_response(text)

    @staticmethod
    def _extract_text(data: dict) -> str:
        """Extract text content from Gemini API response."""
        try:
            candidates = data.get("candidates", [])
            if not candidates:
                feedback = data.get("promptFeedback", {})
                block_reason = feedback.get("blockReason")
                if block_reason:
                    raise RuntimeError(f"Gemini blocked the request: {block_reason}")
                return ""
            candidate = candidates[0]
            content = candidate.get("content", {})
            parts = content.get("parts", [])
            return "".join(part.get("text", "") for part in parts)
        except (KeyError, IndexError) as e:
            raise RuntimeError(f"Unexpected Gemini response structure: {e}") from e


def parse_json_response(text: str) -> any:
    """Strip markdown fences and parse JSON."""
    text = text.strip()
    text = re.sub(r"^```[a-z]*\n?", "", text)
    text = re.sub(r"\n?```$", "", text.strip())
    return json.loads(text)
