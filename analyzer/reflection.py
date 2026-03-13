"""
Response / Reflection Analysis
Deep inspection of how injected payloads appear in HTTP responses.
"""

import re
import logging
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass

from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


@dataclass
class ReflectionDetail:
    """Detailed information about a single reflection."""
    location: str            # "html_body" | "script" | "attribute" | etc.
    tag: Optional[str]       # surrounding HTML tag
    attribute: Optional[str] # attribute name if inside an attribute
    is_executable: bool      # whether the reflection could execute JS
    is_filtered: bool        # whether the payload was sanitised
    original: str            # what was sent
    reflected_as: str        # what appeared in the response


class ReflectionAnalyzer:
    """Detailed analysis of payload reflections in a response body."""

    # Characters that, if present unescaped, indicate broken out of context
    BREAKOUT_CHARS = {"<", ">", '"', "'", "(", ")", ";"}

    def analyze(
        self, response_body: str, payload: str
    ) -> List[ReflectionDetail]:
        """Find every occurrence of `payload` in `response_body` and classify."""
        details: List[ReflectionDetail] = []

        # Search both raw and HTML-decoded body
        import html
        bodies = {
            "raw": response_body,
            "decoded": html.unescape(response_body),
        }

        for label, body in bodies.items():
            start = 0
            while True:
                idx = body.find(payload, start)
                if idx == -1:
                    break

                detail = self._classify_reflection(body, payload, idx)
                details.append(detail)
                start = idx + len(payload)

        return details

    # ── Classification ──────────────────────────────────────

    def _classify_reflection(
        self, body: str, payload: str, idx: int
    ) -> ReflectionDetail:
        context_start = max(0, idx - 300)
        preceding = body[context_start:idx]
        reflected_as = body[idx:idx + len(payload)]

        # Determine context
        location, tag, attribute = self._find_context(preceding, body, idx)

        # Check if payload characters were sanitised
        is_filtered = self._check_filtering(payload, reflected_as)

        # Check if reflection is in an executable position
        is_executable = self._check_executable(location, reflected_as, tag, attribute)

        return ReflectionDetail(
            location=location,
            tag=tag,
            attribute=attribute,
            is_executable=is_executable,
            is_filtered=is_filtered,
            original=payload,
            reflected_as=reflected_as,
        )

    def _find_context(
        self, preceding: str, body: str, idx: int
    ) -> Tuple[str, Optional[str], Optional[str]]:
        lower_prec = preceding.lower()

        # Inside <script> block?
        script_open = lower_prec.rfind("<script")
        script_close = lower_prec.rfind("</script")
        if script_open > script_close:
            return "script", "script", None

        # Inside a <style> block?
        style_open = lower_prec.rfind("<style")
        style_close = lower_prec.rfind("</style")
        if style_open > style_close:
            return "style", "style", None

        # Inside an HTML comment?
        comment_open = lower_prec.rfind("<!--")
        comment_close = lower_prec.rfind("-->")
        if comment_open > comment_close:
            return "comment", None, None

        # Inside a tag attribute?
        tag_match = re.search(
            r'<(\\w+)\\s[^>]*?(\\w+)\\s*=\\s*["\\']?[^"\\']*$',
            preceding, re.IGNORECASE | re.DOTALL,
        )
        if tag_match:
            tag_name = tag_match.group(1)
            attr_name = tag_match.group(2)
            return "attribute", tag_name, attr_name

        # Inside a tag (but not in an attribute)?
        last_open = preceding.rfind("<")
        last_close = preceding.rfind(">")
        if last_open > last_close:
            tag_name_match = re.search(r"<(\\w+)", preceding[last_open:])
            tag_name = tag_name_match.group(1) if tag_name_match else None
            return "tag", tag_name, None

        return "html_body", None, None

    @staticmethod
    def _check_filtering(original: str, reflected: str) -> bool:
        """Check if any dangerous characters were stripped or encoded."""
        dangerous = {"<", ">", '"', "'", "(", ")"}
        for char in dangerous:
            if char in original and char not in reflected:
                return True
        return False

    @staticmethod
    def _check_executable(
        location: str, reflected: str, tag: Optional[str], attribute: Optional[str]
    ) -> bool:
        """Determine if the reflection location allows script execution."""
        if location == "script":
            return True

        if location == "attribute" and attribute:
            # Event handler attributes
            if attribute.lower().startswith("on"):
                return True
            # URL-type attributes with javascript: protocol
            if attribute.lower() in ("href", "src", "action", "data"):
                if "javascript:" in reflected.lower():
                    return True

        if location == "html_body":
            # Check if payload includes executable HTML
            if re.search(r"<\\s*(script|img|svg|iframe|body|input|details|embed)",
                         reflected, re.IGNORECASE):
                return True
            if re.search(r"\\bon\\w+\\s*=", reflected, re.IGNORECASE):
                return True

        return False
