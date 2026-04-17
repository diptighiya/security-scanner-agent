"""
Gemini LangChain wrapper — exposes ChatGoogleGemini as a LangChain BaseChatModel
by wrapping the REST API, since langchain-google-genai is unavailable in this env.
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, List, Optional

import requests
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult

logger = logging.getLogger(__name__)

GEMINI_API_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    "gemini-2.0-flash:generateContent"
)

_GENERATION_CONFIG = {
    "temperature": 0.2,
    "topP": 0.8,
    "topK": 40,
    "maxOutputTokens": 8192,
}

_SAFETY_SETTINGS = [
    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
]


class ChatGoogleGemini(BaseChatModel):
    """
    LangChain-compatible ChatModel backed by the Gemini REST API.
    Implements BaseChatModel so it integrates with .with_fallbacks(),
    LCEL chains, and all other LangChain primitives.
    """

    api_key: str
    model: str = "gemini-2.0-flash"
    max_retries: int = 2
    base_retry_delay: float = 5.0
    min_request_interval: float = 4.0

    # Internal mutable state stored outside pydantic fields
    _session: Optional[requests.Session] = None
    _last_request_time: float = 0.0

    class Config:
        arbitrary_types_allowed = True

    @property
    def _llm_type(self) -> str:
        return "google-gemini"

    def _get_session(self) -> requests.Session:
        if self._session is None:
            self._session = requests.Session()
            self._session.headers.update({"Content-Type": "application/json"})
        return self._session

    def _generate(
        self,
        messages: List[BaseMessage],
        stop: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> ChatResult:
        prompt = "\n\n".join(str(m.content) for m in messages if hasattr(m, "content"))
        text = self._call_api(prompt)
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=text))])

    def _call_api(self, prompt: str) -> str:
        """Call Gemini REST API with retry and rate-limit backoff."""
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": _GENERATION_CONFIG,
            "safetySettings": _SAFETY_SETTINGS,
        }
        url = f"{GEMINI_API_URL}?key={self.api_key}"
        session = self._get_session()

        for attempt in range(1, self.max_retries + 1):
            elapsed = time.time() - self._last_request_time
            if elapsed < self.min_request_interval:
                time.sleep(self.min_request_interval - elapsed)

            self._last_request_time = time.time()
            response = session.post(url, json=payload, timeout=120)

            if response.status_code == 429:
                wait = self.base_retry_delay * (2 ** (attempt - 1))
                logger.warning("[Gemini] Rate limited. Waiting %.0fs (attempt %d/%d)", wait, attempt, self.max_retries)
                time.sleep(wait)
                if attempt == self.max_retries:
                    raise ValueError(f"Gemini rate limited (429) after {self.max_retries} retries")
                continue

            if response.status_code in (500, 502, 503, 504):
                time.sleep(self.base_retry_delay)
                continue

            response.raise_for_status()
            data = response.json()
            return self._extract_text(data)

        raise ValueError(f"Gemini API failed after {self.max_retries} retries")

    @staticmethod
    def _extract_text(data: dict) -> str:
        candidates = data.get("candidates", [])
        if not candidates:
            block = data.get("promptFeedback", {}).get("blockReason")
            if block:
                raise ValueError(f"Gemini blocked: {block}")
            return ""
        parts = candidates[0].get("content", {}).get("parts", [])
        return "".join(p.get("text", "") for p in parts)


# ---------------------------------------------------------------------------
# Convenience alias kept for any code that still does:
#   from tools.gemini_client import GeminiClient
# ---------------------------------------------------------------------------
class GeminiClient:
    """Legacy thin wrapper — delegates to ChatGoogleGemini internally."""

    def __init__(self, api_key: str):
        self._model = ChatGoogleGemini(api_key=api_key)

    def generate(self, prompt: str, **kwargs) -> str:
        from langchain_core.messages import HumanMessage
        result = self._model._generate([HumanMessage(content=prompt)])
        return result.generations[0].message.content

    def generate_json(self, prompt: str, **kwargs) -> Any:
        text = self.generate(prompt)
        return _parse_json(text)


def _parse_json(text: str) -> Any:
    text = text.strip()
    text = re.sub(r"^```[a-z]*\n?", "", text)
    text = re.sub(r"\n?```$", "", text.strip())
    return json.loads(text)
