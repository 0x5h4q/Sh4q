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
_INLINE_SCRIPT_RE = re.compile(r"<script\b(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script\s*>", re.IGNORECASE | re.DOTALL)
_URL_RE = re.compile(r"(?:https?://[^\s\"'`<>]+|/api(?:/|\b)[^\s\"'`<>]*)", re.IGNORECASE)
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("generic_api_key_assignment", re.compile(r"\b(?:api[_-]?key|access[_-]?token|client[_-]?secret)\b\s*[:=]\s*['\"]([^'\"]{8,})['\"]", re.IGNORECASE)),
)


def _bounded_text(value: str, limit: int) -> str:
    return value.encode("utf-8", errors="replace")[:limit].decode("utf-8", errors="ignore")


def _absolute_reference(reference: str, base_url: str) -> str | None:
    value = reference.strip().rstrip(".,;:!?)]}")
    if not value or value.startswith(("data:", "javascript:", "#")):
        return None
    # A reference is lifted out of surrounding syntax, and the syntax must not
    # come with it -- which is why trailing punctuation is trimmed above. A
    # backslash is the same thing one level down: the URL pattern does not stop
    # at one, so an escaped JS literal like "https://host/a.css\\" yields a
    # value ending in a backslash. A real scan produced 26 of those. They were
    # refused at Gate 2 only because the host happened to be out of scope; an
    # in-scope one persists as an asset no browser would resolve, and asset
    # values are what diff compares and what an export hands to someone else.
    #
    # Truncated rather than dropped: a backslash cannot appear unescaped
    # anywhere in a URL, so its presence marks where the match ran past the end
    # of the literal. What precedes it is the reference, and discarding the
    # whole match would lose a real discovery. Percent-encoded %5C is untouched
    # and still legitimate.
    value = value.split("\\", 1)[0].rstrip(".,;:!?)]}")
    if not value:
        return None
    absolute = urljoin(base_url, value)
    parsed = urlparse(absolute)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    return absolute


def extract_javascript_observations(html: str, base_url: str, limits: JavaScriptExtractionLimits | None = None) -> list[dict[str, str | int]]:
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
    inline_script = "\n".join(_INLINE_SCRIPT_RE.findall(bounded_html))
    for match in _URL_RE.finditer(inline_script):
        reference = _absolute_reference(match.group(0), base_url)
        if reference:
            add("endpoint_reference", reference)
    for pattern_name, pattern in _SECRET_PATTERNS:
        for _ in pattern.finditer(bounded_html):
            add("secret_like_pattern", pattern_name, pattern=pattern_name, context=f"matched {pattern_name}")
            if len(observations) >= limits.max_results:
                break
    return observations


def extract_javascript_bundle_observations(
    script: str,
    source_url: str,
    limits: JavaScriptExtractionLimits | None = None,
) -> list[dict[str, str | int]]:
    """Extract passive endpoint and secret indicators from one JS bundle."""
    limits = limits or JavaScriptExtractionLimits()
    bounded_script = _bounded_text(script, limits.max_script_bytes)
    observations: list[dict[str, str | int]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str, **extra: str | int) -> None:
        if len(observations) >= limits.max_results or (kind, value) in seen:
            return
        seen.add((kind, value))
        observations.append({"kind": kind, "value": value, **extra})

    for match in _URL_RE.finditer(bounded_script):
        reference = _absolute_reference(match.group(0), source_url)
        if reference:
            add("endpoint_reference", reference)
    for pattern_name, pattern in _SECRET_PATTERNS:
        if pattern.search(bounded_script):
            add("secret_like_pattern", pattern_name, pattern=pattern_name, context=f"matched {pattern_name}")
    return observations
