"""
Gemini REST API client — calls the Gemini 1.5 Flash model directly
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
    "gemini-1.5-flash:generateContent"
)

_DEFAULT_GENERATION_CONFIG = {
    "temperature": 0.2,
    "topP": 0.8,
    "topK": 40,
    "maxOutputTokens": 8192,
}


class GeminiClient:
    """Thin wrapper around the Gemini REST API."""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})

    def generate(
        self,
        prompt: str,
        max_retries: int = 3,
        retry_delay: float = 5.0,
    ) -> str:
        """
        Send a text prompt to Gemini 1.5 Flash and return the response text.

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
            try:
                response = self.session.post(url, json=payload, timeout=120)
                response.raise_for_status()
                data = response.json()
                text = self._extract_text(data)
                return text

            except requests.exceptions.HTTPError as e:
                status = e.response.status_code if e.response else None
                if status == 429:
                    wait = retry_delay * attempt
                    logger.warning(f"Rate limited by Gemini. Waiting {wait}s before retry {attempt}/{max_retries}")
                    time.sleep(wait)
                elif status in (500, 502, 503, 504):
                    wait = retry_delay
                    logger.warning(f"Gemini server error {status}. Waiting {wait}s before retry {attempt}/{max_retries}")
                    time.sleep(wait)
                else:
                    logger.error(f"Gemini HTTP error {status}: {e}")
                    raise RuntimeError(f"Gemini API error {status}: {e}") from e

            except requests.exceptions.Timeout:
                logger.warning(f"Gemini request timed out (attempt {attempt}/{max_retries})")
                if attempt < max_retries:
                    time.sleep(retry_delay)

            except Exception as e:
                logger.error(f"Gemini request failed: {e}")
                raise RuntimeError(f"Gemini request failed: {e}") from e

        raise RuntimeError(f"Gemini API failed after {max_retries} retries")

    def generate_json(self, prompt: str, max_retries: int = 3) -> any:
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
                # Check for blocking
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
    # Remove ```json ... ``` or ``` ... ```
    text = re.sub(r"^```[a-z]*\n?", "", text)
    text = re.sub(r"\n?```$", "", text.strip())
    return json.loads(text)
