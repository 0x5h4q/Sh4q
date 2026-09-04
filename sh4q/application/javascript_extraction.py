"""Bounded, passive extraction of references from HTML and JavaScript text."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse


@dataclass(frozen=True)
class JavaScriptExtractionLimits:
    max_input_bytes: int = 64 * 1024
    max_scripts: int = 20
    max_script_bytes: int = 256 * 1024
    max_results: int = 100


_SCRIPT_RE = re.compile(r"<script\b[^>]*?\bsrc\s*=\s*(['\"])(.*?)\1", re.IGNORECASE | re.DOTALL)
_URL_RE = re.compile(r"(?:https?://[^\s\"'`<>]+|/api(?:/|\b)[^\s\"'`<>]*)", re.IGNORECASE)
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("generic_api_key_assignment", re.compile(r"\b(?:api[_-]?key|access[_-]?token|client[_-]?secret)\b\s*[:=]\s*['\"]([^'\"]{8,})['\"]", re.IGNORECASE)),
)


def _bounded_text(value: str, limit: int) -> str:
    return value.encode("utf-8", errors="replace")[:limit].decode("utf-8", errors="ignore")


def _absolute_reference(reference: str, base_url: str) -> str | None:
    value = reference.strip()
    if not value or value.startswith(("data:", "javascript:", "#")):
        return None
    absolute = urljoin(base_url, value)
    parsed = urlparse(absolute)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    return absolute


def extract_javascript_observations(
    html: str,
    base_url: str,
    limits: JavaScriptExtractionLimits | None = None,
) -> list[dict[str, str | int]]:
    """Extract script URLs, endpoint references, and secret-like signals.

    This function parses bounded text only. It never executes JavaScript or
    performs network requests.
    """

    limits = limits or JavaScriptExtractionLimits()
    bounded_html = _bounded_text(html, limits.max_input_bytes)
    observations: list[dict[str, str | int]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str, **extra: str | int) -> None:
        if len(observations) >= limits.max_results or (kind, value) in seen:
            return
        seen.add((kind, value))
        observations.append({"kind": kind, "value": value, **extra})

    for _, raw_src in _SCRIPT_RE.findall(bounded_html)[: limits.max_scripts]:
        script_url = _absolute_reference(raw_src, base_url)
        if script_url:
            add("script_url", script_url)

    for match in _URL_RE.finditer(bounded_html):
        reference = _absolute_reference(match.group(0), base_url)
        if reference:
            add("endpoint_reference", reference)

    for pattern_name, pattern in _SECRET_PATTERNS:
        for _ in pattern.finditer(bounded_html):
            add("secret_like_pattern", pattern_name, pattern=pattern_name, context=f"matched {pattern_name}")
            if len(observations) >= limits.max_results:
                break

    return observations
