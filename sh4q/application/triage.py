"""Presentation-side relevance judgments over already-persisted observations.

Nothing here authorizes, persists, or reclassifies inventory. Gate 2 already
decided that, and these classifiers never see scope state. They answer the
reviewer's next question -- "which of these 196 rows do I read first?" --
from the shape of the value alone.

Rules are structural on purpose: path segments, extensions, and hostname
shape. There are no domain allow/denylists, so a new third party can never
silently change a bucket, and a renamed library cannot either.
"""

from __future__ import annotations

from urllib.parse import urlparse


#: Buckets for `classify_javascript_reference`, most specific first. The order
#: below is the precedence: a value matching several rules takes the first.
JS_BUCKETS = (
    "boilerplate",
    "third-party",
    "auth-flow",
    "api-route",
    "static-asset",
    "page-route",
)

#: Buckets for `classify_historical_url`, most specific first.
HISTORY_BUCKETS = (
    "admin-console",
    "api-surface",
    "auth-flow",
    "static-asset",
    "parameterized",
    "page",
)

_STATIC_EXTENSIONS = frozenset({
    ".js", ".css", ".map",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
    ".mp4", ".webm", ".mp3", ".wav",
    ".pdf", ".zip",
})

#: Basenames that mark vendored documentation rather than application surface.
#: Matched case-insensitively against the final path segment, with or without
#: a .txt suffix.
_BOILERPLATE_BASENAMES = frozenset({
    "license", "licence", "authors", "contributors", "patents",
    "notice", "readme", "changelog", "copying",
})

_AUTH_SEGMENTS = frozenset({
    "oauth", "oauth2", "openid", "authorize", "authorization",
    "token", "introspect", "login", "signin", "sign-in", "logout",
    "sso", "saml", "callback",
})

_ADMIN_SEGMENTS = frozenset({
    "admin", "administrator", "wp-admin", "upload", "uploads",
    "config", "backup", "backups", "console", "manage", "manager",
    "phpmyadmin", "dashboard",
})


def _host(value: str) -> str | None:
    try:
        host = urlparse(value).hostname
    except ValueError:
        return None
    if not host:
        return None
    return host.casefold().rstrip(".")


def _segments(path: str) -> list[str]:
    return [segment.casefold() for segment in path.split("/") if segment]


def _source_host(source_endpoint: str) -> str | None:
    if not source_endpoint:
        return None
    return _host(source_endpoint)


def classify_javascript_reference(
    value: str, source_endpoint: str = ""
) -> tuple[str, tuple[str, ...]]:
    """Bucket one extracted JavaScript reference for triage display.

    Returns (bucket, reasons). Buckets: boilerplate, third-party,
    auth-flow, api-route, static-asset, page-route. An unparseable value
    reports ("unparseable", ...) rather than raising: triage must never
    break a listing.
    """
    host = _host(value)
    if host is None:
        return "unparseable", ("not an http(s) URL with a hostname",)
    try:
        path = urlparse(value).path
    except ValueError:
        return "unparseable", ("unparseable path",)

    basename = path.rsplit("/", 1)[-1].casefold()
    stem = basename[:-4] if basename.endswith(".txt") else basename
    if stem in _BOILERPLATE_BASENAMES:
        return "boilerplate", (f"vendored document path ({basename})",)
    if "." not in host and host != "localhost":
        return "boilerplate", ("single-label hostname is library test-fixture shape",)

    source = _source_host(source_endpoint)
    if source is not None and host != source:
        return "third-party", ("different host than the page that linked it",)

    segments = _segments(path)
    if any(segment in _AUTH_SEGMENTS for segment in segments):
        return "auth-flow", ("authentication protocol path",)
    if "api" in segments:
        return "api-route", ("application API path",)
    if any(path.casefold().endswith(extension) for extension in _STATIC_EXTENSIONS):
        return "static-asset", ("static file extension",)
    if "/combo?" in value.casefold():
        # Concatenated asset loaders carry the file list in the query string,
        # so the path itself (`/combo`) has no static extension to match.
        return "static-asset", ("concatenated asset-loader URL",)
    return "page-route", ("same-host page or route",)


def classify_historical_url(value: str) -> tuple[str, tuple[str, ...]]:
    """Bucket one Wayback URL for triage display.

    Returns (bucket, reasons). Buckets: admin-console, api-surface,
    auth-flow, static-asset, parameterized, page. Same no-raise contract
    as `classify_javascript_reference`.
    """
    host = _host(value)
    if host is None:
        return "unparseable", ("not an http(s) URL with a hostname",)
    try:
        parsed = urlparse(value)
    except ValueError:
        return "unparseable", ("unparseable URL",)

    segments = _segments(parsed.path)
    if any(segment in _ADMIN_SEGMENTS for segment in segments):
        return "admin-console", ("administrative or upload path",)
    if "api" in segments:
        return "api-surface", ("application API path",)
    if any(segment in _AUTH_SEGMENTS for segment in segments):
        return "auth-flow", ("authentication protocol path",)
    if any(parsed.path.casefold().endswith(extension) for extension in _STATIC_EXTENSIONS):
        return "static-asset", ("static file extension",)
    if parsed.query:
        return "parameterized", ("carries a query string",)
    return "page", ("plain page path",)
