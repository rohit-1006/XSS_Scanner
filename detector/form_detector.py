"""
Form & Parameter Detection
Identifies all injectable points: URL params, form fields, headers, fragments.
"""

import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs

from crawler.spider import CrawlResult, FormData

logger = logging.getLogger(__name__)


@dataclass
class InjectionPoint:
    """Single injectable parameter."""
    url: str
    param_name: str
    param_type: str          # "url_param" | "form_input" | "fragment" | "header"
    method: str              # GET | POST
    original_value: str = ""
    form_data: Optional[FormData] = None
    context: str = ""        # Additional context info


class ParameterDetector:
    """Scans crawl results and builds injection-point inventory."""

    def __init__(self, crawl_result: CrawlResult):
        self.crawl_result = crawl_result

    def detect_all(self) -> List[InjectionPoint]:
        """Return every injectable point found during crawling."""
        points: List[InjectionPoint] = []
        points.extend(self._from_url_params())
        points.extend(self._from_forms())
        points.extend(self._from_fragments())

        logger.info(f"Detected {len(points)} injection points")
        return points

    # ── URL query parameters ────────────────────────────────

    def _from_url_params(self) -> List[InjectionPoint]:
        points = []
        for url, params in self.crawl_result.url_params.items():
            for name, values in params.items():
                points.append(InjectionPoint(
                    url=url,
                    param_name=name,
                    param_type="url_param",
                    method="GET",
                    original_value=values[0] if values else "",
                ))
        return points

    # ── Form inputs ─────────────────────────────────────────

    def _from_forms(self) -> List[InjectionPoint]:
        points = []
        for form in self.crawl_result.forms:
            for inp in form.inputs:
                # Skip non-injectable types
                if inp["type"] in ("submit", "button", "image", "reset", "file"):
                    continue
                points.append(InjectionPoint(
                    url=form.action,
                    param_name=inp["name"],
                    param_type="form_input",
                    method=form.method,
                    original_value=inp.get("value", ""),
                    form_data=form,
                ))
        return points

    # ── URL fragments (DOM sinks) ───────────────────────────

    def _from_fragments(self) -> List[InjectionPoint]:
        points = []
        for url in self.crawl_result.urls_visited:
            parsed = urlparse(url)
            if parsed.fragment:
                points.append(InjectionPoint(
                    url=url,
                    param_name="#fragment",
                    param_type="fragment",
                    method="GET",
                    original_value=parsed.fragment,
                ))
        return points
