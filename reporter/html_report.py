"""
HTML Vulnerability Report Generator
Produces a self-contained, styled HTML report of all findings.
"""

import os
import json
import logging
from datetime import datetime
from typing import List, Dict, Optional
from collections import Counter

from engine.injector import InjectionResult
from detector.dom_analyzer import DOMVulnerability
from config import ScannerConfig, Severity

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates comprehensive HTML vulnerability reports."""

    def __init__(self, config: ScannerConfig):
        self.config = config

    def generate(
        self,
        reflected_results: List[InjectionResult],
        dom_results: List[DOMVulnerability],
        scan_metadata: Dict,
    ) -> str:
        """Build and save the report.  Returns the output filepath."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"xss_report_{timestamp}.html"
        filepath = os.path.join(self.config.report_dir, filename)

        # Assign severity to each finding
        findings_with_severity = self._assign_severity(reflected_results)

        html = self._build_html(
            findings_with_severity, dom_results, scan_metadata, timestamp
        )

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

        logger.info(f"Report saved to {filepath}")

        # Optionally also dump JSON
        if self.config.report_format in ("json", "both"):
            json_path = filepath.replace(".html", ".json")
            self._save_json(
                findings_with_severity, dom_results, scan_metadata, json_path
            )

        return filepath

    # ── Severity assignment ─────────────────────────────────

    def _assign_severity(
        self, results: List[InjectionResult]
    ) -> List[Dict]:
        findings = []
        for r in results:
            severity = self._compute_severity(r)
            findings.append({
                "url": r.request_url,
                "parameter": r.injection_point.param_name,
                "method": r.request_method,
                "xss_type": r.xss_type,
                "payload": r.payload,
                "encoded_payload": r.encoded_payload,
                "encoding": r.encoding,
                "context": r.reflection_context,
                "confidence": round(r.confidence, 2),
                "severity": severity,
                "response_code": r.response_code,
                "snippet": self._escape_html(r.response_snippet[:500]),
                "evidence": r.evidence,
            })
        # Sort: CRITICAL first
        order = {
            Severity.CRITICAL: 0, Severity.HIGH: 1,
            Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4,
        }
        findings.sort(key=lambda f: order.get(f["severity"], 5))
        return findings

    @staticmethod
    def _compute_severity(result: InjectionResult) -> str:
        if result.xss_type == "Stored" and result.confidence >= 0.8:
            return Severity.CRITICAL
        if result.xss_type == "Stored":
            return Severity.HIGH
        if result.confidence >= 0.8:
            return Severity.HIGH
        if result.confidence >= 0.6:
            return Severity.MEDIUM
        if result.confidence >= 0.4:
            return Severity.LOW
        return Severity.INFO

    # ── HTML builder ────────────────────────────────────────

    def _build_html(
        self,
        findings: List[Dict],
        dom_findings: List[DOMVulnerability],
        meta: Dict,
        timestamp: str,
    ) -> str:
        severity_counts = Counter(f["severity"] for f in findings)
        type_counts = Counter(f["xss_type"] for f in findings)
        total = len(findings) + len(dom_findings)

        findings_rows = self._render_finding_rows(findings)
        dom_rows = self._render_dom_rows(dom_findings)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>XSS Vulnerability Report – {timestamp}</title>
<style>
{self._css()}
</style>
</head>
<body>

<!-- ─── Header ───────────────────────────────────────── -->
<header>
    <h1>🛡️ XSS Vulnerability Scan Report</h1>
    <p class="subtitle">Generated {datetime.now().strftime("%B %d, %Y at %H:%M:%S")}</p>
</header>

<!-- ─── Summary Cards ────────────────────────────────── -->
<section class="summary">
    <div class="card total">
        <h3>Total Findings</h3>
        <span class="count">{total}</span>
    </div>
    <div class="card critical">
        <h3>Critical</h3>
        <span class="count">{severity_counts.get(Severity.CRITICAL, 0)}</span>
    </div>
    <div class="card high">
        <h3>High</h3>
        <span class="count">{severity_counts.get(Severity.HIGH, 0)}</span>
    </div>
    <div class="card medium">
        <h3>Medium</h3>
        <span class="count">{severity_counts.get(Severity.MEDIUM, 0)}</span>
    </div>
    <div class="card low">
        <h3>Low</h3>
        <span class="count">{severity_counts.get(Severity.LOW, 0)}</span>
    </div>
</section>

<!-- ─── Scan Metadata ────────────────────────────────── -->
<section class="meta">
    <h2>Scan Details</h2>
    <table class="meta-table">
        <tr><td><strong>Target</strong></td>
            <td>{self._escape_html(meta.get("target", "N/A"))}</td></tr>
        <tr><td><strong>Pages Crawled</strong></td>
            <td>{meta.get("pages_crawled", 0)}</td></tr>
        <tr><td><strong>Forms Found</strong></td>
            <td>{meta.get("forms_found", 0)}</td></tr>
        <tr><td><strong>Injection Points</strong></td>
            <td>{meta.get("injection_points", 0)}</td></tr>
        <tr><td><strong>Payloads Tested</strong></td>
            <td>{meta.get("payloads_tested", 0)}</td></tr>
        <tr><td><strong>Scan Duration</strong></td>
            <td>{meta.get("duration", "N/A")}</td></tr>
        <tr><td><strong>XSS Types Found</strong></td>
            <td>{", ".join(f"{k}: {v}" for k, v in type_counts.items())}</td></tr>
    </table>
</section>

<!-- ─── Reflected / Stored Findings ──────────────────── -->
<section class="findings">
    <h2>Reflected &amp; Stored XSS Findings ({len(findings)})</h2>
    {findings_rows if findings else '<p class="none">No reflected/stored XSS found.</p>'}
</section>

<!-- ─── DOM-based Findings ───────────────────────────── -->
<section class="findings">
    <h2>DOM-based XSS Findings ({len(dom_findings)})</h2>
    {dom_rows if dom_findings else '<p class="none">No DOM-based XSS found.</p>'}
</section>

<!-- ─── Recommendations ──────────────────────────────── -->
<section class="recommendations">
    <h2>Remediation Recommendations</h2>
    <ul>
        <li><strong>Output Encoding:</strong> Encode all user-supplied data
            before rendering in HTML, JavaScript, CSS, or URL contexts.</li>
        <li><strong>Input Validation:</strong> Use allowlists to restrict
            acceptable input characters and patterns.</li>
        <li><strong>Content Security Policy:</strong> Deploy a strict CSP
            header to prevent inline script execution.</li>
        <li><strong>HTTPOnly Cookies:</strong> Mark session cookies as
            <code>HttpOnly</code> to limit the impact of XSS.</li>
        <li><strong>X-XSS-Protection:</strong> Enable browser-level
            XSS auditors via the <code>X-XSS-Protection</code> header.</li>
        <li><strong>Framework Auto-escaping:</strong> Use templating
            engines that auto-escape output by default.</li>
        <li><strong>DOM Safety:</strong> Avoid <code>innerHTML</code>,
            <code>document.write</code>, and <code>eval()</code>.
            Use <code>textContent</code> and safe DOM APIs.</li>
    </ul>
</section>

<footer>
    <p>Generated by <strong>XSS Vulnerability Scanner</strong> •
       For authorized security testing only</p>
</footer>

</body>
</html>"""

    # ── Row renderers ───────────────────────────────────────

    def _render_finding_rows(self, findings: List[Dict]) -> str:
        rows = []
        for i, f in enumerate(findings, 1):
            sev_class = f["severity"].lower()
            rows.append(f"""
<div class="finding {sev_class}">
    <div class="finding-header">
        <span class="badge {sev_class}">{f["severity"]}</span>
        <span class="finding-title">#{i} – {f["xss_type"]} XSS in
            <code>{self._escape_html(f["parameter"])}</code></span>
    </div>
    <table class="detail-table">
        <tr><td>URL</td><td><code>{self._escape_html(f["url"][:120])}</code></td></tr>
        <tr><td>Method</td><td>{f["method"]}</td></tr>
        <tr><td>Parameter</td><td><code>{self._escape_html(f["parameter"])}</code></td></tr>
        <tr><td>Payload</td>
            <td><code class="payload">{self._escape_html(f["payload"][:200])}</code></td></tr>
        <tr><td>Encoding</td><td>{f["encoding"]}</td></tr>
        <tr><td>Context</td><td>{f["context"]}</td></tr>
        <tr><td>Confidence</td>
            <td><span class="confidence">{f["confidence"]}</span></td></tr>
        <tr><td>Evidence</td>
            <td><pre class="snippet">{f["snippet"][:400]}</pre></td></tr>
    </table>
</div>""")
        return "\\n".join(rows)

    def _render_dom_rows(self, findings: List[DOMVulnerability]) -> str:
        rows = []
        for i, f in enumerate(findings, 1):
            sev = Severity.HIGH if f.confidence >= 0.7 else Severity.MEDIUM
            rows.append(f"""
<div class="finding {sev.lower()}">
    <div class="finding-header">
        <span class="badge {sev.lower()}">{sev}</span>
        <span class="finding-title">#{i} – DOM-based XSS</span>
    </div>
    <table class="detail-table">
        <tr><td>URL</td><td><code>{self._escape_html(f.url[:120])}</code></td></tr>
        <tr><td>Source</td><td><code>{self._escape_html(f.source)}</code></td></tr>
        <tr><td>Sink</td><td><code>{self._escape_html(f.sink)}</code></td></tr>
        <tr><td>JS File</td>
            <td><code>{self._escape_html(f.js_file or "inline")}</code></td></tr>
        <tr><td>Confidence</td>
            <td><span class="confidence">{f.confidence:.2f}</span></td></tr>
        <tr><td>Code</td>
            <td><pre class="snippet">{self._escape_html(f.code_snippet[:400])}</pre></td></tr>
    </table>
</div>""")
        return "\\n".join(rows)

    # ── CSS ─────────────────────────────────────────────────

    @staticmethod
    def _css() -> str:
        return """
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    background: #0f172a; color: #e2e8f0; line-height: 1.6;
    padding: 2rem; max-width: 1200px; margin: 0 auto;
}
header { text-align: center; margin-bottom: 2rem; }
header h1 { font-size: 2rem; color: #38bdf8; }
.subtitle { color: #94a3b8; margin-top: .3rem; }

/* Summary cards */
.summary {
    display: flex; gap: 1rem; flex-wrap: wrap;
    justify-content: center; margin-bottom: 2rem;
}
.card {
    background: #1e293b; border-radius: 12px; padding: 1.2rem 2rem;
    text-align: center; min-width: 140px; border-left: 4px solid #475569;
}
.card h3 { font-size: .85rem; color: #94a3b8; text-transform: uppercase; }
.card .count { font-size: 2.4rem; font-weight: 700; }
.card.total  .count { color: #38bdf8; }
.card.critical { border-color: #ef4444; }
.card.critical .count { color: #ef4444; }
.card.high   { border-color: #f97316; }
.card.high   .count { color: #f97316; }
.card.medium { border-color: #eab308; }
.card.medium .count { color: #eab308; }
.card.low    { border-color: #22c55e; }
.card.low    .count { color: #22c55e; }

/* Sections */
section { margin-bottom: 2.5rem; }
section h2 {
    font-size: 1.3rem; color: #38bdf8;
    border-bottom: 1px solid #334155; padding-bottom: .5rem;
    margin-bottom: 1rem;
}

/* Meta table */
.meta-table { width: 100%; border-collapse: collapse; }
.meta-table td {
    padding: .5rem 1rem; border-bottom: 1px solid #1e293b;
}
.meta-table td:first-child { width: 200px; color: #94a3b8; }

/* Findings */
.finding {
    background: #1e293b; border-radius: 10px;
    margin-bottom: 1.2rem; overflow: hidden;
    border-left: 4px solid #475569;
}
.finding.critical { border-color: #ef4444; }
.finding.high     { border-color: #f97316; }
.finding.medium   { border-color: #eab308; }
.finding.low      { border-color: #22c55e; }
.finding-header {
    padding: .8rem 1.2rem; background: #162032;
    display: flex; align-items: center; gap: .8rem;
}
.badge {
    padding: .15rem .7rem; border-radius: 6px;
    font-size: .75rem; font-weight: 700; text-transform: uppercase;
}
.badge.critical { background: #7f1d1d; color: #fca5a5; }
.badge.high     { background: #7c2d12; color: #fdba74; }
.badge.medium   { background: #713f12; color: #fde047; }
.badge.low      { background: #14532d; color: #86efac; }
.badge.info     { background: #1e3a5f; color: #7dd3fc; }
.finding-title { font-weight: 600; }

.detail-table { width: 100%; border-collapse: collapse; }
.detail-table td {
    padding: .45rem 1.2rem; border-bottom: 1px solid #0f172a;
    vertical-align: top;
}
.detail-table td:first-child {
    width: 130px; color: #94a3b8; font-size: .85rem;
}
code {
    background: #0f172a; padding: .1rem .4rem;
    border-radius: 4px; font-size: .85rem; color: #fbbf24;
    word-break: break-all;
}
.payload { color: #f87171; }
.snippet {
    background: #0f172a; padding: .6rem; border-radius: 6px;
    font-size: .78rem; white-space: pre-wrap;
    word-break: break-all; max-height: 150px; overflow-y: auto;
    color: #cbd5e1;
}
.confidence { font-weight: 700; color: #38bdf8; }
.none { color: #64748b; font-style: italic; }

/* Recommendations */
.recommendations ul {
    list-style: none; padding-left: 0;
}
.recommendations li {
    padding: .6rem 1rem; margin-bottom: .4rem;
    background: #1e293b; border-radius: 8px;
    border-left: 3px solid #38bdf8;
}

footer {
    text-align: center; color: #475569;
    padding-top: 2rem; border-top: 1px solid #1e293b;
    font-size: .85rem;
}
"""

    # ── Helpers ─────────────────────────────────────────────

    @staticmethod
    def _escape_html(text: str) -> str:
        return (
            text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#x27;")
        )

    def _save_json(
        self, findings, dom_findings, meta, filepath
    ):
        data = {
            "metadata": meta,
            "findings": findings,
            "dom_findings": [
                {
                    "url": d.url,
                    "source": d.source,
                    "sink": d.sink,
                    "js_file": d.js_file,
                    "confidence": d.confidence,
                    "code_snippet": d.code_snippet,
                }
                for d in dom_findings
            ],
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        logger.info(f"JSON report saved to {filepath}")
