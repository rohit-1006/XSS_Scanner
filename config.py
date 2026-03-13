"""
XSS Scanner Configuration
All tunable parameters, defaults, and constants live here.
"""

from dataclasses import dataclass, field
from typing import List, Optional
import os


@dataclass
class ScannerConfig:
    """Master configuration for the XSS scanner."""

    # ── Target ──────────────────────────────────────────────
    target_url: str = ""
    max_depth: int = 3
    max_pages: int = 100
    scope: str = "same-domain"          # same-domain | same-origin | custom

    # ── Crawling ────────────────────────────────────────────
    crawl_timeout: int = 10             # seconds per request
    request_delay: float = 0.5          # delay between requests (rate limit)
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
    follow_redirects: bool = True
    max_retries: int = 2
    respect_robots_txt: bool = True

    # ── Authentication ──────────────────────────────────────
    cookies: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    auth_url: Optional[str] = None
    auth_data: Optional[dict] = None

    # ── Payloads ────────────────────────────────────────────
    custom_payload_file: Optional[str] = None
    encoding_techniques: List[str] = field(
        default_factory=lambda: [
            "none", "url", "double_url", "html_entity",
            "unicode", "hex", "base64", "mixed_case"
        ]
    )
    payload_level: int = 2              # 1 = basic, 2 = moderate, 3 = aggressive

    # ── Detection ───────────────────────────────────────────
    check_reflected: bool = True
    check_stored: bool = True
    check_dom: bool = True
    use_selenium: bool = False          # needed for DOM-based detection
    selenium_headless: bool = True

    # ── Filtering ───────────────────────────────────────────
    confidence_threshold: float = 0.6   # 0.0 – 1.0
    false_positive_checks: bool = True

    # ── Reporting ───────────────────────────────────────────
    report_dir: str = "reports"
    report_format: str = "html"         # html | json | both
    verbose: bool = True

    # ── Concurrency ─────────────────────────────────────────
    threads: int = 5

    def __post_init__(self):
        os.makedirs(self.report_dir, exist_ok=True)


# ── Severity levels ────────────────────────────────────────
class Severity:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# ── XSS type labels ───────────────────────────────────────
class XSSType:
    REFLECTED = "Reflected"
    STORED = "Stored"
    DOM_BASED = "DOM-based"
