from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit
from pathlib import Path


@dataclass(frozen=True)
class NormalizedPath:
    value: str
    rejected: bool = False
    reason: str | None = None


class DirectoryCandidateError(ValueError):
    """A candidate file cannot be safely admitted for probing."""


@dataclass(frozen=True)
class CandidateLoadResult:
    accepted: tuple[str, ...]
    rejected: tuple[tuple[int, str, str], ...]
    duplicates: int


def load_candidates(path: str | Path, *, max_paths: int = 200, max_length: int = 512) -> CandidateLoadResult:
    """Load and normalize a bounded operator-supplied candidate file."""
    if max_paths < 1 or max_length < 1:
        raise DirectoryCandidateError("directory discovery limits must be positive")
    candidate_path = Path(path).expanduser()
    if not candidate_path.is_file():
        raise DirectoryCandidateError(f"directory candidate file not found: {candidate_path}")
    try:
        lines = candidate_path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise DirectoryCandidateError(
            f"directory candidate file is not valid UTF-8: {candidate_path}"
        ) from error
    accepted: list[str] = []
    rejected: list[tuple[int, str, str]] = []
    seen: set[str] = set()
    duplicates = 0
    for line_number, raw in enumerate(lines, 1):
        if not raw.strip():
            continue
        normalized = normalize_candidate(raw, max_length=max_length)
        if normalized.rejected:
            rejected.append((line_number, raw, normalized.reason or "invalid candidate"))
            continue
        if normalized.value in seen:
            duplicates += 1
            continue
        if len(accepted) >= max_paths:
            raise DirectoryCandidateError(
                f"directory candidate file exceeds maximum of {max_paths} paths"
            )
        seen.add(normalized.value)
        accepted.append(normalized.value)
    return CandidateLoadResult(tuple(accepted), tuple(rejected), duplicates)


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
