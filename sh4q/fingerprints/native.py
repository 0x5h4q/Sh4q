from __future__ import annotations

import re
from html.parser import HTMLParser

from sh4q.plugins.discovery import Discovery


SIGNATURE_SET_VERSION = "2026.08.1"
MAX_HTML_SAMPLE_BYTES = 65_536
CATEGORY_PRIORITY = {
    "web-server": 10,
    "runtime-or-framework": 20,
    "runtime": 30,
    "framework": 40,
    "web-framework": 50,
    "cms": 60,
    "cdn-waf": 70,
}


class _TitleParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self._in_title = False
        self.parts: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.parts.append(data)


def extract_http_metadata(response) -> dict:
    content = bytes(getattr(response, "content", b"") or b"")
    sample = content[:MAX_HTML_SAMPLE_BYTES]
    content_type = response.headers.get("content-type", "")
    text = sample.decode(getattr(response, "encoding", None) or "utf-8", errors="replace")
    title = ""
    if "html" in content_type.lower() or "<html" in text[:1000].lower():
        parser = _TitleParser()
        parser.feed(text)
        title = " ".join(" ".join(parser.parts).split())[:300]
    cookie_names = sorted({
        value.split("=", 1)[0].strip()
        for value in response.headers.get_list("set-cookie")
        if "=" in value and value.split("=", 1)[0].strip()
    }) if hasattr(response.headers, "get_list") else []
    return {
        "title": title,
        "content_type": content_type,
        "cookie_names": cookie_names,
        "html_sample": text,
        "sample_bytes": len(sample),
        "sample_truncated": len(content) > len(sample),
    }


def fingerprint_response(endpoint: str, status: int, response, metadata: dict) -> list[Discovery]:
    headers = {key.lower(): value for key, value in response.headers.items()}
    html = metadata["html_sample"].lower()
    cookies = {name.lower() for name in metadata["cookie_names"]}
    findings: dict[str, dict] = {}

    def observe(technology: str, category: str, signal: str, version: str = "") -> None:
        finding = findings.setdefault(technology.lower(), {
            "observed_name": technology,
            "category": category,
            "version": version,
            "signals": [],
        })
        finding["signals"].append(signal)
        if CATEGORY_PRIORITY.get(category, 0) > CATEGORY_PRIORITY.get(finding["category"], 0):
            finding["category"] = category
        if version and not finding["version"]:
            finding["version"] = version

    server = headers.get("server", "").strip()
    if server:
        product = server.split("/", 1)[0].split(" ", 1)[0]
        version_match = re.search(r"/(\d[\w.\-]*)", server)
        observe(product, "web-server", f"header:server={server}", version_match.group(1) if version_match else "")
    powered_by = headers.get("x-powered-by", "").strip()
    if powered_by:
        product = powered_by.split("/", 1)[0].split(" ", 1)[0]
        version_match = re.search(r"/(\d[\w.\-]*)", powered_by)
        observe(product, "runtime-or-framework", f"header:x-powered-by={powered_by}", version_match.group(1) if version_match else "")
    if "cf-ray" in headers:
        observe("Cloudflare", "cdn-waf", "header:cf-ray")
    if "cf-cache-status" in headers:
        observe("Cloudflare", "cdn-waf", "header:cf-cache-status")
    if "phpsessid" in cookies:
        observe("PHP", "runtime", "cookie:PHPSESSID")
    if "asp.net_sessionid" in cookies:
        observe("ASP.NET", "framework", "cookie:ASP.NET_SessionId")
    if "/wp-content/" in html:
        observe("WordPress", "cms", "html:/wp-content/")
    if "/wp-includes/" in html:
        observe("WordPress", "cms", "html:/wp-includes/")
    if "__next_data__" in html or "/_next/" in html:
        observe("Next.js", "web-framework", "html:nextjs-marker")
    if "drupalsettings" in html or "content=\"drupal" in html:
        observe("Drupal", "cms", "html:drupal-marker")

    discoveries = []
    for finding in findings.values():
        signals = sorted(set(finding["signals"]))
        confidence = "high" if len(signals) >= 2 else "explicit" if signals[0].startswith("header:") else "medium"
        discoveries.append(Discovery("http_fingerprint", {
            "endpoint": endpoint,
            "status": status,
            "title": metadata["title"],
            "technologies": [finding["observed_name"]],
            "category": finding["category"],
            "version": finding["version"],
            "detection_method": "native-signature",
            "confidence": confidence,
            "source": "native-http",
            "signals": signals,
            "signature_version": SIGNATURE_SET_VERSION,
            "raw_observation": "; ".join(signals),
        }))
    return discoveries
