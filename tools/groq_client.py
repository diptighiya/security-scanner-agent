"""
Groq API client — calls Llama3-70b via the Groq SDK.
Used as a fallback/round-robin partner for the Gemini client.
"""

from __future__ import annotations

import json
import logging
import re
import time

from groq import Groq, RateLimitError, APIStatusError

logger = logging.getLogger(__name__)

GROQ_MODEL = "llama-3.3-70b-versatile"


class GroqClient:
    """Thin wrapper around the Groq SDK for text generation."""

    def __init__(self, api_key: str):
        self.client = Groq(api_key=api_key)
        logger.info("GroqClient initialized (model: %s)", GROQ_MODEL)

    def generate(
        self,
        prompt: str,
        max_retries: int = 3,
        base_retry_delay: float = 10.0,
    ) -> str:
        """
        Send a text prompt to Groq and return the response text.

        Raises:
            RateLimitError: propagated so the unified client can switch providers.
            RuntimeError: on non-recoverable errors.
        """
        for attempt in range(1, max_retries + 1):
            try:
                completion = self.client.chat.completions.create(
                    model=GROQ_MODEL,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.2,
                    max_tokens=8192,
                )
                return completion.choices[0].message.content or ""

            except RateLimitError:
                # Re-raise so LLMClient can switch to Gemini
                raise

            except APIStatusError as e:
                if e.status_code in (500, 502, 503, 504):
                    wait = base_retry_delay * attempt
                    logger.warning(
                        "[Groq] Server error %s. Waiting %ss (attempt %d/%d)",
                        e.status_code, wait, attempt, max_retries,
                    )
                    time.sleep(wait)
                else:
                    raise RuntimeError(f"Groq API error {e.status_code}: {e}") from e

            except Exception as e:
                raise RuntimeError(f"Groq request failed: {e}") from e

        raise RuntimeError(f"Groq API failed after {max_retries} retries")

    def generate_json(self, prompt: str, max_retries: int = 3) -> any:
        """Generate a response and parse it as JSON."""
        text = self.generate(prompt, max_retries=max_retries)
        return _parse_json_response(text)


def _parse_json_response(text: str) -> any:
    """Strip markdown fences and parse JSON."""
    text = text.strip()
    text = re.sub(r"^```[a-z]*\n?", "", text)
    text = re.sub(r"\n?```$", "", text.strip())
    return json.loads(text)
