"""
Web Spider / Crawler
Discovers URLs, forms, and injectable parameters across the target site.
"""

import re
import time
import logging
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from typing import Set, List, Dict, Optional, Tuple
from collections import deque
from dataclasses import dataclass, field

import requests
from bs4 import BeautifulSoup
import tldextract

from config import ScannerConfig

logger = logging.getLogger(__name__)


@dataclass
class FormData:
    """Represents a discoverable HTML form."""
    url: str                                 # page where the form lives
    action: str                              # resolved action URL
    method: str                              # GET | POST
    inputs: List[Dict[str, str]]             # [{name, type, value}, ...]
    enctype: str = "application/x-www-form-urlencoded"


@dataclass
class CrawlResult:
    """Everything the spider found."""
    urls_visited: Set[str] = field(default_factory=set)
    forms: List[FormData] = field(default_factory=list)
    url_params: Dict[str, Dict[str, List[str]]] = field(default_factory=dict)
    js_files: Set[str] = field(default_factory=set)
    errors: List[str] = field(default_factory=list)


class Spider:
    """Breadth-first web crawler scoped to the target domain."""

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.session = self._build_session()
        self.visited: Set[str] = set()
        self.result = CrawlResult()
        self._target_domain = self._extract_domain(config.target_url)

    # ── Public API ──────────────────────────────────────────

    def crawl(self) -> CrawlResult:
        """Run the crawl starting from the configured target URL."""
        logger.info(f"Starting crawl: {self.config.target_url}")
        queue: deque[Tuple[str, int]] = deque()
        queue.append((self.config.target_url, 0))

        while queue and len(self.visited) < self.config.max_pages:
            url, depth = queue.popleft()
            normalized = self._normalize(url)

            if normalized in self.visited:
                continue
            if depth > self.config.max_depth:
                continue
            if not self._in_scope(normalized):
                continue

            self.visited.add(normalized)
            self.result.urls_visited.add(normalized)

            try:
                response = self.session.get(
                    url,
                    timeout=self.config.crawl_timeout,
                    allow_redirects=self.config.follow_redirects,
                )
                content_type = response.headers.get("Content-Type", "")
                if "text/html" not in content_type:
                    continue

                soup = BeautifulSoup(response.text, "lxml")

                # Extract forms
                self._extract_forms(soup, url)

                # Extract URL parameters
                self._extract_url_params(url)

                # Extract JS file references
                self._extract_js(soup, url)

                # Discover new links
                for link in self._extract_links(soup, url):
                    link_norm = self._normalize(link)
                    if link_norm not in self.visited:
                        queue.append((link, depth + 1))

                logger.info(
                    f"[depth={depth}] Crawled {normalized} "
                    f"({len(self.visited)}/{self.config.max_pages})"
                )
                time.sleep(self.config.request_delay)

            except requests.RequestException as exc:
                msg = f"Request error on {url}: {exc}"
                logger.warning(msg)
                self.result.errors.append(msg)

        logger.info(
            f"Crawl finished – {len(self.visited)} pages, "
            f"{len(self.result.forms)} forms, "
            f"{len(self.result.url_params)} parameterized URLs"
        )
        return self.result

    # ── Link extraction ─────────────────────────────────────

    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        links: List[str] = []
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if href.startswith(("#", "mailto:", "javascript:", "tel:")):
                continue
            full = urljoin(base_url, href)
            # strip fragment
            full = full.split("#")[0]
            if full:
                links.append(full)
        return links

    # ── Form extraction ─────────────────────────────────────

    def _extract_forms(self, soup: BeautifulSoup, page_url: str) -> None:
        for form in soup.find_all("form"):
            action = form.get("action", "")
            action_url = urljoin(page_url, action) if action else page_url
            method = (form.get("method") or "GET").upper()
            enctype = form.get("enctype", "application/x-www-form-urlencoded")

            inputs: List[Dict[str, str]] = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                input_type = inp.get("type", "text")
                value = inp.get("value", "")
                inputs.append({
                    "name": name,
                    "type": input_type,
                    "value": value,
                })

            if inputs:
                fd = FormData(
                    url=page_url,
                    action=action_url,
                    method=method,
                    inputs=inputs,
                    enctype=enctype,
                )
                self.result.forms.append(fd)
                logger.debug(f"Found form: {method} {action_url} ({len(inputs)} inputs)")

    # ── URL parameter extraction ────────────────────────────

    def _extract_url_params(self, url: str) -> None:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if params:
            clean_url = parsed._replace(query="").geturl()
            self.result.url_params[url] = {k: v for k, v in params.items()}

    # ── JavaScript file extraction ──────────────────────────

    def _extract_js(self, soup: BeautifulSoup, base_url: str) -> None:
        for script in soup.find_all("script", src=True):
            js_url = urljoin(base_url, script["src"])
            self.result.js_files.add(js_url)

    # ── Scope enforcement ───────────────────────────────────

    def _in_scope(self, url: str) -> bool:
        if self.config.scope == "same-domain":
            return self._extract_domain(url) == self._target_domain
        if self.config.scope == "same-origin":
            target_parsed = urlparse(self.config.target_url)
            url_parsed = urlparse(url)
            return (
                url_parsed.scheme == target_parsed.scheme
                and url_parsed.netloc == target_parsed.netloc
            )
        return True

    # ── Helpers ─────────────────────────────────────────────

    def _build_session(self) -> requests.Session:
        s = requests.Session()
        s.headers.update({"User-Agent": self.config.user_agent})
        if self.config.headers:
            s.headers.update(self.config.headers)
        if self.config.cookies:
            s.cookies.update(self.config.cookies)
        if self.config.auth_url and self.config.auth_data:
            s.post(self.config.auth_url, data=self.config.auth_data)
        return s

    @staticmethod
    def _normalize(url: str) -> str:
        parsed = urlparse(url)
        return parsed._replace(fragment="").geturl().rstrip("/")

    @staticmethod
    def _extract_domain(url: str) -> str:
        ext = tldextract.extract(url)
        return f"{ext.domain}.{ext.suffix}"
