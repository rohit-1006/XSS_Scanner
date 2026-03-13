"""
False Positive Filtering
Reduce noise by applying heuristic checks on potential findings.
"""

import re
import logging
from typing import List

from engine.injector import InjectionResult
from config import ScannerConfig

logger = logging.getLogger(__name__)


class FalsePositiveFilter:
    """Post-processing filter to eliminate likely false positives."""

    # Patterns that indicate the payload was sanitised / escaped
    SANITIZED_PATTERNS = [
        re.compile(r"&lt;script", re.IGNORECASE),
        re.compile(r"&lt;img", re.IGNORECASE),
        re.compile(r"&lt;svg", re.IGNORECASE),
        re.compile(r"&amp;lt;", re.IGNORECASE),
    ]

    # Security headers that reduce exploitability
    MITIGATION_HEADERS = [
        "Content-Security-Policy",
        "X-XSS-Protection",
        "X-Content-Type-Options",
    ]

    def __init__(self, config: ScannerConfig):
        self.config = config

    def filter(self, results: List[InjectionResult]) -> List[InjectionResult]:
        """Return only results that pass all FP checks."""
        if not self.config.false_positive_checks:
            return results

        filtered: List[InjectionResult] = []
        removed = 0

        for result in results:
            if self._is_false_positive(result):
                removed += 1
                logger.debug(
                    f"FP filtered: {result.payload[:40]} @ "
                    f"{result.injection_point.url}"
                )
                continue
            filtered.append(result)

        logger.info(
            f"False-positive filter: kept {len(filtered)}, removed {removed}"
        )
        return filtered

    def _is_false_positive(self, result: InjectionResult) -> bool:
        """Apply a chain of heuristic checks."""
        # ❶ Below confidence threshold
        if result.confidence < self.config.confidence_threshold:
            return True

        # ❷ Payload was HTML-entity-encoded in the response
        if self._is_sanitized(result.response_snippet):
            return True

        # ❸ Reflection is inside an HTML comment
        if self._inside_comment(result.response_snippet, result.payload):
            return True

        # ❹ Payload appears only inside a <textarea> or <pre>
        if self._inside_safe_tag(result.response_snippet, result.payload):
            return True

        # ❺ Response is a 4xx/5xx error page
        if result.response_code >= 400:
            return True

        # ❻ Payload is reflected but with critical chars stripped
        if self._chars_stripped(result.payload, result.response_snippet):
            return True

        return False

    def _is_sanitized(self, snippet: str) -> bool:
        for pattern in self.SANITIZED_PATTERNS:
            if pattern.search(snippet):
                return True
        return False

    @staticmethod
    def _inside_comment(snippet: str, payload: str) -> bool:
        idx = snippet.find(payload)
        if idx == -1:
            return False
        before = snippet[:idx]
        after = snippet[idx + len(payload):]
        return "<!--" in before and "-->" in after

    @staticmethod
    def _inside_safe_tag(snippet: str, payload: str) -> bool:
        lower = snippet.lower()
        idx = lower.find(payload.lower())
        if idx == -1:
            return False
        preceding = lower[:idx]
        safe_tags = ["<textarea", "<pre", "<code", "<xmp"]
        for tag in safe_tags:
            close_tag = tag.replace("<", "</") + ">"
            if tag in preceding and close_tag not in preceding:
                return True
        return False

    @staticmethod
    def _chars_stripped(original: str, snippet: str) -> bool:
        """If < and > were both removed from the snippet, it's not exploitable."""
        if "<" in original and ">" in original:
            # Check if both appear in the snippet around the payload
            if "<" not in snippet and ">" not in snippet:
                return True
        return False
