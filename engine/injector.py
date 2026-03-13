"""
Payload Injection Engine
Sends crafted requests with XSS payloads to every injection point.
"""

import logging
import time
import copy
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from bs4 import BeautifulSoup

from config import ScannerConfig, XSSType
from detector.form_detector import InjectionPoint
from engine.payloads import get_payloads, load_custom_payloads, CANARY, DOM_PAYLOADS
from engine.encoders import encode_payload

logger = logging.getLogger(__name__)


@dataclass
class InjectionResult:
    """Outcome of a single payload injection."""
    injection_point: InjectionPoint
    payload: str
    encoded_payload: str
    encoding: str
    response_code: int
    reflected: bool
    reflection_context: str
    response_snippet: str
    xss_type: str
    confidence: float
    request_url: str
    request_method: str
    evidence: str = ""


class Injector:
    """Sends payloads and captures responses."""

    def __init__(self, config: ScannerConfig, session: Optional[requests.Session] = None):
        self.config = config
        self.session = session or self._build_session()
        self.payloads = self._load_payloads()
        self.results: List[InjectionResult] = []

    # ── Public API ──────────────────────────────────────────

    def run(self, injection_points: List[InjectionPoint]) -> List[InjectionResult]:
        """Inject every payload into every injection point."""
        logger.info(
            f"Injection engine starting: "
            f"{len(injection_points)} points × {len(self.payloads)} payloads"
        )

        with ThreadPoolExecutor(max_workers=self.config.threads) as pool:
            futures = {}
            for point in injection_points:
                for payload in self.payloads:
                    for encoded in encode_payload(
                        payload, self.config.encoding_techniques
                    ):
                        future = pool.submit(
                            self._inject_single, point, payload, encoded
                        )
                        futures[future] = (point, payload, encoded)

            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result and result.reflected:
                        self.results.append(result)
                        logger.info(
                            f"[HIT] {result.xss_type} XSS in "
                            f"{result.injection_point.param_name} @ "
                            f"{result.injection_point.url}"
                        )
                except Exception as exc:
                    logger.debug(f"Injection thread error: {exc}")

        logger.info(f"Injection complete – {len(self.results)} potential findings")
        return self.results

    # ── Single injection ────────────────────────────────────

    def _inject_single(
        self, point: InjectionPoint, raw_payload: str, encoded_payload: str
    ) -> Optional[InjectionResult]:
        """Send one payload to one injection point and analyze."""
        try:
            time.sleep(self.config.request_delay)

            if point.param_type == "url_param":
                return self._inject_url_param(point, raw_payload, encoded_payload)
            elif point.param_type == "form_input":
                return self._inject_form(point, raw_payload, encoded_payload)
            elif point.param_type == "fragment":
                # Fragments are client-side only; handled by DOM analyzer
                return None

        except requests.RequestException as exc:
            logger.debug(f"Request failed: {exc}")
            return None

    # ── URL parameter injection ─────────────────────────────

    def _inject_url_param(
        self, point: InjectionPoint, raw: str, encoded: str
    ) -> Optional[InjectionResult]:
        parsed = urlparse(point.url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        # Replace target parameter with payload
        params[point.param_name] = [encoded]

        new_query = urlencode(params, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))

        resp = self.session.get(
            test_url,
            timeout=self.config.crawl_timeout,
            allow_redirects=self.config.follow_redirects,
        )

        reflected, context, snippet = self._check_reflection(resp.text, raw, encoded)

        return InjectionResult(
            injection_point=point,
            payload=raw,
            encoded_payload=encoded,
            encoding=self._detect_encoding_name(raw, encoded),
            response_code=resp.status_code,
            reflected=reflected,
            reflection_context=context,
            response_snippet=snippet,
            xss_type=XSSType.REFLECTED,
            confidence=self._compute_confidence(reflected, context, resp),
            request_url=test_url,
            request_method="GET",
        )

    # ── Form injection ──────────────────────────────────────

    def _inject_form(
        self, point: InjectionPoint, raw: str, encoded: str
    ) -> Optional[InjectionResult]:
        form = point.form_data
        if form is None:
            return None

        # Build form data with payload in target field
        data = {}
        for inp in form.inputs:
            if inp["name"] == point.param_name:
                data[inp["name"]] = encoded
            else:
                data[inp["name"]] = inp.get("value", "test")

        if form.method == "POST":
            resp = self.session.post(
                form.action,
                data=data,
                timeout=self.config.crawl_timeout,
                allow_redirects=self.config.follow_redirects,
            )
        else:
            resp = self.session.get(
                form.action,
                params=data,
                timeout=self.config.crawl_timeout,
                allow_redirects=self.config.follow_redirects,
            )

        reflected, context, snippet = self._check_reflection(resp.text, raw, encoded)

        # Determine XSS type: if payload appears on different page → possibly stored
        xss_type = XSSType.REFLECTED
        if reflected and form.method == "POST":
            # Quick stored XSS check: re-fetch the page and see if payload persists
            verify_resp = self.session.get(form.action, timeout=self.config.crawl_timeout)
            if raw in verify_resp.text or encoded in verify_resp.text:
                xss_type = XSSType.STORED

        return InjectionResult(
            injection_point=point,
            payload=raw,
            encoded_payload=encoded,
            encoding=self._detect_encoding_name(raw, encoded),
            response_code=resp.status_code,
            reflected=reflected,
            reflection_context=context,
            response_snippet=snippet,
            xss_type=xss_type,
            confidence=self._compute_confidence(reflected, context, resp),
            request_url=form.action,
            request_method=form.method,
        )

    # ── Stored XSS verification ─────────────────────────────

    def verify_stored(
        self, pages_to_check: List[str], payloads_sent: List[str]
    ) -> List[InjectionResult]:
        """Re-visit pages and look for payloads that persisted."""
        stored_findings: List[InjectionResult] = []

        for url in pages_to_check:
            try:
                resp = self.session.get(url, timeout=self.config.crawl_timeout)
                for payload in payloads_sent:
                    if payload in resp.text:
                        # Find surrounding context
                        idx = resp.text.find(payload)
                        start = max(0, idx - 80)
                        end = min(len(resp.text), idx + len(payload) + 80)
                        snippet = resp.text[start:end]

                        stored_findings.append(InjectionResult(
                            injection_point=InjectionPoint(
                                url=url,
                                param_name="stored",
                                param_type="stored",
                                method="GET",
                            ),
                            payload=payload,
                            encoded_payload=payload,
                            encoding="none",
                            response_code=resp.status_code,
                            reflected=True,
                            reflection_context="html_body",
                            response_snippet=snippet,
                            xss_type=XSSType.STORED,
                            confidence=0.85,
                            request_url=url,
                            request_method="GET",
                            evidence="Payload persisted across requests",
                        ))
                        logger.info(f"[STORED XSS] Payload found on {url}")
            except requests.RequestException:
                continue

        return stored_findings

    # ── Reflection detection ────────────────────────────────

    def _check_reflection(
        self, body: str, raw_payload: str, encoded_payload: str
    ) -> Tuple[bool, str, str]:
        """
        Check whether the payload (raw or encoded) appears in the response.
        Returns (reflected, context, snippet).
        """
        # Check for raw payload
        for search_term in (raw_payload, encoded_payload):
            idx = body.find(search_term)
            if idx != -1:
                start = max(0, idx - 100)
                end = min(len(body), idx + len(search_term) + 100)
                snippet = body[start:end]
                context = self._determine_context(body, idx)
                return True, context, snippet

        # Check for partially decoded reflections
        import html as html_lib
        decoded_body = html_lib.unescape(body)
        idx = decoded_body.find(raw_payload)
        if idx != -1:
            start = max(0, idx - 100)
            end = min(len(decoded_body), idx + len(raw_payload) + 100)
            snippet = decoded_body[start:end]
            context = self._determine_context(decoded_body, idx)
            return True, context, snippet

        return False, "", ""

    def _determine_context(self, body: str, position: int) -> str:
        """Guess what HTML context the reflection landed in."""
        # Look backwards for context clues
        preceding = body[max(0, position - 200):position].lower()

        if "<script" in preceding and "</script>" not in preceding:
            return "javascript"
        if 'value="' in preceding[-50:] or "value='" in preceding[-50:]:
            return "attribute_value"
        if "href=" in preceding[-50:] or "src=" in preceding[-50:]:
            return "url_attribute"
        if "<style" in preceding and "</style>" not in preceding:
            return "css"

        return "html_body"

    # ── Confidence scoring ──────────────────────────────────

    def _compute_confidence(
        self, reflected: bool, context: str, response: requests.Response
    ) -> float:
        if not reflected:
            return 0.0

        score = 0.5

        # Context-based bonuses
        context_scores = {
            "html_body": 0.3,
            "javascript": 0.35,
            "attribute_value": 0.25,
            "url_attribute": 0.2,
            "css": 0.15,
        }
        score += context_scores.get(context, 0.1)

        # Check if security headers are missing (less likely to be filtered)
        headers = response.headers
        if "Content-Security-Policy" not in headers:
            score += 0.05
        if headers.get("X-XSS-Protection", "") != "1; mode=block":
            score += 0.05
        if "X-Content-Type-Options" not in headers:
            score += 0.05

        return min(score, 1.0)

    # ── Helpers ─────────────────────────────────────────────

    def _load_payloads(self) -> List[str]:
        payloads = get_payloads(self.config.payload_level)
        if self.config.custom_payload_file:
            custom = load_custom_payloads(self.config.custom_payload_file)
            payloads.extend(custom)
        return payloads

    def _build_session(self) -> requests.Session:
        s = requests.Session()
        s.headers.update({"User-Agent": self.config.user_agent})
        if self.config.headers:
            s.headers.update(self.config.headers)
        if self.config.cookies:
            s.cookies.update(self.config.cookies)
        return s

    @staticmethod
    def _detect_encoding_name(raw: str, encoded: str) -> str:
        if raw == encoded:
            return "none"
        if "%" in encoded:
            if "%25" in encoded:
                return "double_url"
            return "url"
        if "&" in encoded and ";" in encoded:
            return "html_entity"
        if "\\\\u" in encoded:
            return "unicode"
        if "\\\\x" in encoded:
            return "hex"
        if "atob" in encoded:
            return "base64"
        return "unknown"
