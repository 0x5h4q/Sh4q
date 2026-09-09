from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class NormalizedPath:
    value: str
    rejected: bool = False
    reason: str | None = None


def normalize_candidate(raw: str, *, max_length: int = 512) -> NormalizedPath:
    """Normalize one operator-supplied relative path without contacting it."""
    if not isinstance(raw, str):
        return NormalizedPath("", True, "candidate is not text")
    if any(ord(char) < 32 or ord(char) == 127 for char in raw):
        return NormalizedPath("", True, "candidate contains control characters")
    candidate = raw.strip()
    if not candidate:
        return NormalizedPath("", True, "candidate is empty")
    if len(candidate.encode("utf-8")) > max_length:
        return NormalizedPath("", True, "candidate exceeds maximum path length")
    if "#" in candidate:
        return NormalizedPath("", True, "fragments are not allowed")
    if "?" in candidate:
        return NormalizedPath("", True, "query strings are not allowed")
    parsed = urlsplit(candidate)
    if parsed.scheme or parsed.netloc or parsed.username or parsed.password:
        return NormalizedPath("", True, "absolute URLs and credentials are not allowed")
    path = parsed.path
    if not path.startswith("/"):
        path = "/" + path
    segments: list[str] = []
    for segment in path.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if not segments:
                return NormalizedPath("", True, "path escapes the origin")
            segments.pop()
            continue
        segments.append(segment)
    return NormalizedPath("/" + "/".join(segments))
