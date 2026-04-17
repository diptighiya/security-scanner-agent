"""
Unified LangChain LLM client — round-robin between Gemini and Groq
using LangChain's .with_fallbacks() for automatic failover.

Architecture:
  - Primary:  ChatGoogleGemini  (custom BaseChatModel wrapping REST API)
  - Fallback: ChatGroq          (via langchain-groq)
  - Chain:    primary.with_fallbacks([fallback]) | OutputParser
  - Parsers:  StrOutputParser for text, _SafeJsonOutputParser for structured data
  - Template: ChatPromptTemplate with a single {prompt} variable

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
from typing import Any

from langchain_core.output_parsers import JsonOutputParser, StrOutputParser
from langchain_core.prompts import ChatPromptTemplate

from tools.gemini_client import ChatGoogleGemini
from tools.groq_client import build_groq_chat_model

logger = logging.getLogger(__name__)

BOTH_EXHAUSTED_WAIT = 15.0
BOTH_EXHAUSTED_MAX_CYCLES = 4


class LLMClient:
    """
    Unified client powered by LangChain LCEL chains.

    Uses ChatGoogleGemini as the primary model and ChatGroq as the
    automatic fallback via LangChain's .with_fallbacks(). Both are
    wired into a ChatPromptTemplate | LLM | OutputParser pipeline.
    """

    def __init__(self, gemini_api_key: str, groq_api_key: str):
        gemini = ChatGoogleGemini(api_key=gemini_api_key)
        groq = build_groq_chat_model(groq_api_key)

        # LangChain .with_fallbacks() — if Gemini raises any exception,
        # LangChain automatically retries with Groq
        llm_with_fallback = gemini.with_fallbacks(
            [groq],
            exceptions_to_handle=(Exception,),
        )

        # Shared prompt template — single {prompt} variable
        prompt_template = ChatPromptTemplate.from_messages([
            ("human", "{prompt}"),
        ])

        # LCEL pipelines:  template | llm_with_fallback | parser
        self._text_pipeline = prompt_template | llm_with_fallback | StrOutputParser()
        self._json_pipeline = prompt_template | llm_with_fallback | _SafeJsonOutputParser()

        logger.info("LLMClient initialized (LangChain LCEL: Gemini → Groq fallback)")

    def generate(self, prompt: str) -> str:
        """
        Invoke the text pipeline. Gemini is tried first; LangChain automatically
        falls back to Groq on any exception (including 429 rate limits).
        """
        for cycle in range(1, BOTH_EXHAUSTED_MAX_CYCLES + 1):
            try:
                logger.info("[LLMClient] Invoking text pipeline")
                return self._text_pipeline.invoke({"prompt": prompt})
            except Exception as e:
                if _is_rate_limit(e):
                    wait = BOTH_EXHAUSTED_WAIT * cycle
                    logger.warning(
                        "[LLMClient] Both providers rate-limited. Waiting %.0fs (cycle %d/%d)",
                        wait, cycle, BOTH_EXHAUSTED_MAX_CYCLES,
                    )
                    time.sleep(wait)
                else:
                    raise RuntimeError(f"LLM generation failed: {e}") from e

        raise RuntimeError("Both Gemini and Groq exhausted all retries.")

    def generate_json(self, prompt: str) -> Any:
        """
        Invoke the JSON pipeline. Uses _SafeJsonOutputParser which strips
        markdown fences before parsing, handling both Gemini and Groq output styles.
        """
        for cycle in range(1, BOTH_EXHAUSTED_MAX_CYCLES + 1):
            try:
                logger.info("[LLMClient] Invoking JSON pipeline")
                return self._json_pipeline.invoke({"prompt": prompt})
            except json.JSONDecodeError:
                raise  # Malformed JSON — not a rate limit, propagate
            except Exception as e:
                if _is_rate_limit(e):
                    wait = BOTH_EXHAUSTED_WAIT * cycle
                    logger.warning(
                        "[LLMClient] Both providers rate-limited. Waiting %.0fs (cycle %d/%d)",
                        wait, cycle, BOTH_EXHAUSTED_MAX_CYCLES,
                    )
                    time.sleep(wait)
                else:
                    raise RuntimeError(f"LLM JSON generation failed: {e}") from e

        raise RuntimeError("Both Gemini and Groq exhausted all retries.")


class _SafeJsonOutputParser(JsonOutputParser):
    """
    Extends LangChain's JsonOutputParser to strip markdown code fences
    (```json ... ```) before parsing — both Gemini and Groq often emit these.
    """

    def parse(self, text: str) -> Any:
        text = text.strip()
        text = re.sub(r"^```[a-z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text.strip())
        return json.loads(text)


def _is_rate_limit(exc: Exception) -> bool:
    """Return True if the exception looks like a rate-limit error."""
    msg = str(exc).lower()
    return any(kw in msg for kw in ("rate", "429", "limit", "quota", "exhausted"))
