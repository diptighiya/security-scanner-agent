"""
Groq LangChain wrapper — uses langchain-groq's ChatGroq natively.
Also provides a legacy GroqClient class for backward compatibility.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from langchain_groq import ChatGroq

logger = logging.getLogger(__name__)

GROQ_MODEL = "llama-3.3-70b-versatile"


def build_groq_chat_model(api_key: str) -> ChatGroq:
    """Return a LangChain ChatGroq instance ready for use in chains."""
    return ChatGroq(
        model=GROQ_MODEL,
        groq_api_key=api_key,
        temperature=0.2,
        max_tokens=8192,
    )


# ---------------------------------------------------------------------------
# Legacy thin wrapper kept for backward compatibility
# ---------------------------------------------------------------------------
class GroqClient:
    """Legacy wrapper — delegates to LangChain's ChatGroq internally."""

    def __init__(self, api_key: str):
        self._model = build_groq_chat_model(api_key)
        logger.info("GroqClient initialized via LangChain (model: %s)", GROQ_MODEL)

    def generate(self, prompt: str, **kwargs) -> str:
        from langchain_core.messages import HumanMessage
        result = self._model.invoke([HumanMessage(content=prompt)])
        return result.content

    def generate_json(self, prompt: str, **kwargs) -> Any:
        text = self.generate(prompt)
        return _parse_json(text)


def _parse_json(text: str) -> Any:
    text = text.strip()
    text = re.sub(r"^```[a-z]*\n?", "", text)
    text = re.sub(r"\n?```$", "", text.strip())
    return json.loads(text)
