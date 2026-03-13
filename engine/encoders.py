"""
Encoding Bypass Techniques
Transform payloads to evade common XSS filters and WAFs.
"""

import base64
import html
import urllib.parse
from typing import List, Callable, Dict


def encode_none(payload: str) -> str:
    """No encoding – raw payload."""
    return payload


def encode_url(payload: str) -> str:
    """Standard URL encoding."""
    return urllib.parse.quote(payload, safe="")


def encode_double_url(payload: str) -> str:
    """Double URL encoding."""
    return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")


def encode_html_entity(payload: str) -> str:
    """HTML entity encoding for key characters."""
    mapping = {
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#x27;",
        "/": "&#x2F;",
    }
    result = payload
    for char, entity in mapping.items():
        result = result.replace(char, entity)
    return result


def encode_html_numeric(payload: str) -> str:
    """Convert each character to HTML numeric entity."""
    return "".join(f"&#{ord(c)};" for c in payload)


def encode_unicode(payload: str) -> str:
    """JavaScript Unicode escape sequences."""
    return "".join(f"\\\\u{ord(c):04x}" for c in payload)


def encode_hex(payload: str) -> str:
    """Hex encoding: \\\\xNN."""
    return "".join(f"\\\\x{ord(c):02x}" for c in payload)


def encode_base64(payload: str) -> str:
    """Base64 encoding wrapped in eval(atob(...))."""
    b64 = base64.b64encode(payload.encode()).decode()
    return f'eval(atob("{b64}"))'


def encode_mixed_case(payload: str) -> str:
    """Randomly alternate case for tag names to bypass naive filters."""
    import random

    result = []
    in_tag = False
    for char in payload:
        if char == "<":
            in_tag = True
        elif char in (" ", ">", "/"):
            in_tag = False

        if in_tag and char.isalpha():
            result.append(char.upper() if random.random() > 0.5 else char.lower())
        else:
            result.append(char)
    return "".join(result)


def encode_null_bytes(payload: str) -> str:
    """Insert null bytes to bypass certain parsers."""
    return payload.replace("<", "<%00").replace(">", "%00>")


def encode_tab_newline(payload: str) -> str:
    """Insert tabs / newlines inside tags."""
    return payload.replace("<", "<\\t").replace("=", "=\\n")


# ── Encoder registry ───────────────────────────────────────

ENCODERS: Dict[str, Callable[[str], str]] = {
    "none": encode_none,
    "url": encode_url,
    "double_url": encode_double_url,
    "html_entity": encode_html_entity,
    "html_numeric": encode_html_numeric,
    "unicode": encode_unicode,
    "hex": encode_hex,
    "base64": encode_base64,
    "mixed_case": encode_mixed_case,
    "null_bytes": encode_null_bytes,
    "tab_newline": encode_tab_newline,
}


def encode_payload(payload: str, techniques: List[str]) -> List[str]:
    """
    Apply each requested encoding technique to a payload
    and return all encoded variants.
    """
    variants: List[str] = []
    seen = set()
    for tech in techniques:
        encoder = ENCODERS.get(tech)
        if encoder is None:
            continue
        encoded = encoder(payload)
        if encoded not in seen:
            seen.add(encoded)
            variants.append(encoded)
    return variants
