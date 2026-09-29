"""Cookie flags and review headers are recorded from responses already fetched.

An authorised engagement produced exactly one genuine finding: a session
cookie with no Secure, HttpOnly, or SameSite attribute. Sh4q had fetched
that response, parsed its Set-Cookie header, kept the cookie name and
discarded every attribute. The finding had to be reproduced by hand.

Capturing this costs no additional request.
"""

import asyncio
import contextlib
import io

import httpx

from sh4q.config import Sh4qConfig
from sh4q.events import Event
from sh4q.fingerprints.native import (
    SECURITY_HEADERS,
    extract_cookies,
    extract_http_metadata,
    parse_set_cookie,
)
from sh4q.handlers import make_discovery_handler
from sh4q.scope import ScopeEngine


# --- parsing ---------------------------------------------------------------
bare = parse_set_cookie("PHPSESSID=73660bd0f628; path=/")
assert bare == {"name": "PHPSESSID", "secure": False, "http_only": False, "same_site": ""}, bare

guarded = parse_set_cookie("sess=abc; expires=Tue; path=/; httponly; samesite=lax")
assert guarded["http_only"] is True and guarded["same_site"] == "lax" and guarded["secure"] is False

strict = parse_set_cookie("XSRF-TOKEN=v; Secure; SameSite=Strict")
assert strict["secure"] is True and strict["same_site"] == "strict", strict

# Attribute order and casing must not matter.
assert parse_set_cookie("a=1; HTTPONLY; SECURE")["secure"] is True
assert parse_set_cookie("a=1; HTTPONLY; SECURE")["http_only"] is True

# Malformed input is skipped rather than raising.
assert parse_set_cookie("no-equals-sign") is None
assert parse_set_cookie("=novalue; secure") is None
assert parse_set_cookie("") is None

# The cookie VALUE is never retained: evidence is written to disk and shared,
# and a session token must not travel with it.
for candidate in (bare, guarded, strict):
    assert "value" not in candidate, candidate
assert "73660bd0f628" not in repr(bare), "the session token leaked into the record"


def response_with(headers: list[tuple[str, str]]) -> httpx.Response:
    return httpx.Response(
        200,
        headers=headers,
        content=b"<html><title>t</title></html>",
        request=httpx.Request("GET", "https://example.com/"),
    )


# --- extraction from a real response object --------------------------------
response = response_with([
    ("content-type", "text/html"),
    ("set-cookie", "PHPSESSID=x; path=/"),
    ("set-cookie", "other=y; Secure; HttpOnly; SameSite=Strict"),
    ("strict-transport-security", "max-age=15552000"),
    ("x-frame-options", "SAMEORIGIN"),
])
cookies = extract_cookies(response)
assert [c["name"] for c in cookies] == ["PHPSESSID", "other"], cookies
assert cookies[0]["secure"] is False and cookies[1]["secure"] is True

metadata = extract_http_metadata(response)
assert metadata["cookie_names"] == ["PHPSESSID", "other"], "the existing field is preserved"
assert metadata["cookies"] == cookies
headers = metadata["security_headers"]
assert set(headers) == set(SECURITY_HEADERS), headers
assert headers["strict-transport-security"] == "max-age=15552000"
assert headers["x-frame-options"] == "SAMEORIGIN"
assert headers["content-security-policy"] == "", "an absent header is recorded as empty, not omitted"

# A response with no cookies must not invent any.
assert extract_cookies(response_with([("content-type", "text/html")])) == []


# --- the attributes reach the stored asset ---------------------------------
class MemoryStorage:
    def __init__(self):
        self.nodes, self.relationships = {}, {}

    async def save_node(self, node):
        self.nodes[node.id] = node

    async def save_relationship(self, relationship):
        self.relationships[relationship.id] = relationship


class MemoryEvidenceStore:
    def __init__(self):
        self.records = []

    async def append(self, evidence):
        self.records.append(evidence)


async def main() -> None:
    scope = ScopeEngine(Sh4qConfig(scope={"targets": ["example.com"]}))
    storage, evidence = MemoryStorage(), MemoryEvidenceStore()
    handler = make_discovery_handler(scope, storage, evidence, stats={})
    with contextlib.redirect_stdout(io.StringIO()):
        await handler(Event(type="discovery", payload={
            "kind": "http_probe",
            "source_plugin": "http",
            "scan_target": "example.com",
            "data": {
                "final_url": "https://example.com/",
                "status": 200,
                "cookie_names": ["PHPSESSID"],
                "cookies": [{"name": "PHPSESSID", "secure": False, "http_only": False, "same_site": ""}],
                "security_headers": {"strict-transport-security": "", "x-frame-options": "SAMEORIGIN"},
            },
        }))
    url_node = next(n for n in storage.nodes.values() if n.type == "url")
    assert url_node.attributes["cookies"][0]["name"] == "PHPSESSID"
    assert url_node.attributes["cookies"][0]["http_only"] is False
    assert url_node.attributes["security_headers"]["x-frame-options"] == "SAMEORIGIN"

    print("response attributes test passed")


asyncio.run(main())
