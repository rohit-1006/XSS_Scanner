"""
DOM-based XSS Analyzer
Uses Selenium to detect client-side XSS through dangerous sinks & sources.
"""

import re
import logging
import time
from typing import List, Dict, Optional
from dataclasses import dataclass

from config import ScannerConfig

logger = logging.getLogger(__name__)

# DOM sources that attackers control
DOM_SOURCES = [
    "document.URL", "document.documentURI", "document.baseURI",
    "location", "location.href", "location.search", "location.hash",
    "location.pathname", "document.cookie", "document.referrer",
    "window.name", "postMessage",
]

# DOM sinks that lead to execution
DOM_SINKS = [
    "eval(", "setTimeout(", "setInterval(", "Function(",
    "document.write(", "document.writeln(",
    "innerHTML", "outerHTML", "insertAdjacentHTML",
    "element.src", "element.href", "element.action",
    "jQuery.html(", "$.html(", ".html(",
]


@dataclass
class DOMVulnerability:
    """A suspected DOM-based XSS finding."""
    url: str
    source: str
    sink: str
    js_file: Optional[str]
    code_snippet: str
    confidence: float


class DOMAnalyzer:
    """Static + dynamic analysis for DOM-based XSS."""

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.driver = None

    # ── Static analysis of JS files ─────────────────────────

    def analyze_js_static(
        self, js_content: str, js_url: str, page_url: str
    ) -> List[DOMVulnerability]:
        """Scan JavaScript source code for source→sink data flows."""
        findings: List[DOMVulnerability] = []

        for source in DOM_SOURCES:
            source_pattern = re.escape(source).replace(r"\\.", r"\\s*\\.\\s*")
            source_matches = list(
                re.finditer(source_pattern, js_content, re.IGNORECASE)
            )
            if not source_matches:
                continue

            for sink in DOM_SINKS:
                sink_pattern = re.escape(sink).replace(r"\\.", r"\\s*\\.\\s*")
                sink_matches = list(
                    re.finditer(sink_pattern, js_content, re.IGNORECASE)
                )
                if not sink_matches:
                    continue

                # Simple proximity heuristic:
                # if a source and sink appear within 500 chars → suspect
                for sm in source_matches:
                    for sk in sink_matches:
                        distance = abs(sm.start() - sk.start())
                        if distance < 500:
                            start = max(0, min(sm.start(), sk.start()) - 40)
                            end = min(
                                len(js_content),
                                max(sm.end(), sk.end()) + 40,
                            )
                            snippet = js_content[start:end].strip()

                            confidence = self._score_static(distance, source, sink)
                            findings.append(DOMVulnerability(
                                url=page_url,
                                source=source,
                                sink=sink,
                                js_file=js_url,
                                code_snippet=snippet,
                                confidence=confidence,
                            ))
        return findings

    # ── Dynamic analysis with Selenium ──────────────────────

    def analyze_dynamic(self, url: str, payloads: List[str]) -> List[DOMVulnerability]:
        """Inject payloads via URL fragment / params and check for DOM execution."""
        if not self.config.use_selenium:
            return []

        findings: List[DOMVulnerability] = []

        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            from selenium.webdriver.chrome.service import Service
            from selenium.common.exceptions import (
                UnexpectedAlertPresentException,
                TimeoutException,
            )
            from webdriver_manager.chrome import ChromeDriverManager

            options = Options()
            if self.config.selenium_headless:
                options.add_argument("--headless=new")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--disable-web-security")

            service = Service(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=options)
            self.driver.set_page_load_timeout(self.config.crawl_timeout)

            for payload in payloads:
                test_url = f"{url}#{payload}"
                try:
                    self.driver.get(test_url)
                    time.sleep(1)

                    # Check for alert dialog (proof of execution)
                    try:
                        alert = self.driver.switch_to.alert
                        alert_text = alert.text
                        alert.accept()

                        findings.append(DOMVulnerability(
                            url=test_url,
                            source="location.hash",
                            sink="script execution",
                            js_file=None,
                            code_snippet=f"Alert triggered: {alert_text}",
                            confidence=0.95,
                        ))
                        logger.info(f"DOM XSS confirmed via alert: {test_url}")

                    except Exception:
                        pass  # No alert – check for DOM mutations next

                    # Check if payload landed in DOM
                    page_source = self.driver.page_source
                    if payload in page_source:
                        findings.append(DOMVulnerability(
                            url=test_url,
                            source="location.hash",
                            sink="DOM insertion",
                            js_file=None,
                            code_snippet=f"Payload reflected in DOM",
                            confidence=0.7,
                        ))

                except TimeoutException:
                    logger.warning(f"Timeout loading {test_url}")
                except Exception as exc:
                    logger.debug(f"Selenium error on {test_url}: {exc}")

        except ImportError:
            logger.warning("Selenium not installed – skipping DOM dynamic analysis")
        finally:
            if self.driver:
                self.driver.quit()

        return findings

    # ── Confidence scoring ──────────────────────────────────

    @staticmethod
    def _score_static(distance: int, source: str, sink: str) -> float:
        score = 0.5
        if distance < 100:
            score += 0.2
        elif distance < 250:
            score += 0.1

        # High-risk sinks
        if any(s in sink for s in ("eval", "innerHTML", "document.write")):
            score += 0.15

        # Directly controllable sources
        if any(s in source for s in ("location.hash", "location.search", "document.URL")):
            score += 0.1

        return min(score, 1.0)
