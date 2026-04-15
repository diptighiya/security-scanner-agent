"""
Unified LLM client — round-robin between Gemini and Groq with
automatic fallback when one provider is rate-limited.

Usage:
    from tools.llm_client import LLMClient
    llm = LLMClient(gemini_api_key="...", groq_api_key="...")
    text = llm.generate("Your prompt here")
    data = llm.generate_json("Return JSON: ...")
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Optional

logger = logging.getLogger(__name__)

# How long to wait (seconds) when BOTH providers are rate-limited
BOTH_LIMITED_WAIT = 10.0
# How many times to retry when both are simultaneously limited
BOTH_LIMITED_MAX_CYCLES = 6


class LLMClient:
    """
    Unified LLM client that alternates between Gemini and Groq.

    Call order: Gemini → Groq → Gemini → Groq → ...
    On a 429 from either provider, switches to the other.
    If both are rate-limited simultaneously, waits and retries.
    """

    def __init__(self, gemini_api_key: str, groq_api_key: str):
        from tools.gemini_client import GeminiClient
        from tools.groq_client import GroqClient

        self._gemini = GeminiClient(gemini_api_key)
        self._groq = GroqClient(groq_api_key)

        # 0 = Gemini next, 1 = Groq next
        self._turn = 0
        self._providers = ["Gemini", "Groq"]

        logger.info("LLMClient initialized (round-robin: Gemini ↔ Groq)")

    def generate(self, prompt: str) -> str:
        """
        Send prompt to whichever provider is next in round-robin.
        Automatically falls back to the other on 429.
        If both are rate-limited, waits and retries up to BOTH_LIMITED_MAX_CYCLES times.
        """
        for cycle in range(BOTH_LIMITED_MAX_CYCLES):
            primary = self._turn
            fallback = 1 - primary

            # Try primary
            result = self._try_provider(primary, prompt)
            if result is not None:
                self._turn = fallback  # advance round-robin
                return result

            logger.warning(
                "[LLMClient] %s rate-limited. Switching to %s...",
                self._providers[primary], self._providers[fallback],
            )

            # Try fallback
            result = self._try_provider(fallback, prompt)
            if result is not None:
                self._turn = primary  # keep same turn (fallback used this round)
                return result

            # Both limited
            wait = BOTH_LIMITED_WAIT * (cycle + 1)
            logger.warning(
                "[LLMClient] Both providers rate-limited. Waiting %.0fs (cycle %d/%d)...",
                wait, cycle + 1, BOTH_LIMITED_MAX_CYCLES,
            )
            time.sleep(wait)

        raise RuntimeError(
            f"Both Gemini and Groq are rate-limited after {BOTH_LIMITED_MAX_CYCLES} cycles."
        )

    def generate_json(self, prompt: str) -> any:
        """Generate a response and parse it as JSON."""
        text = self.generate(prompt)
        return _parse_json_response(text)

    def _try_provider(self, provider_index: int, prompt: str) -> Optional[str]:
        """
        Attempt a single generation with the specified provider.
        Returns the text on success, or None if rate-limited.
        Raises RuntimeError on non-rate-limit failures.
        """
        provider_name = self._providers[provider_index]
        logger.info("[LLMClient] Using provider: %s", provider_name)

        try:
            if provider_index == 0:
                return self._gemini.generate(prompt, max_retries=1, base_retry_delay=5.0)
            else:
                return self._groq.generate(prompt, max_retries=1, base_retry_delay=5.0)

        except RuntimeError as e:
            msg = str(e).lower()
            if "429" in msg or "rate limit" in msg or "rate-limit" in msg or "failed after" in msg:
                return None  # Signal to try the other provider
            raise  # Non-rate-limit error — propagate

        except Exception as e:
            # Check if it's a rate limit wrapped in another exception type
            msg = str(e).lower()
            if "429" in msg or "rate limit" in msg:
                return None
            raise RuntimeError(f"{provider_name} error: {e}") from e


def _parse_json_response(text: str) -> any:
    """Strip markdown fences and parse JSON."""
    text = text.strip()
    text = re.sub(r"^```[a-z]*\n?", "", text)
    text = re.sub(r"\n?```$", "", text.strip())
    return json.loads(text)
