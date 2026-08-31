from __future__ import annotations

import re
from html.parser import HTMLParser

from sh4q.plugins.discovery import Discovery
from .signatures import SIGNATURE_SET_VERSION, match_signatures


MAX_HTML_SAMPLE_BYTES = 65_536
CATEGORY_PRIORITY = {
    "web-server": 10,
    "runtime-or-framework": 20,
    "runtime": 30,
    "framework": 40,
    "web-framework": 50,
    "javascript-library": 45,
    "javascript-framework": 50,
    "ui-framework": 50,
    "cms": 60,
    "ecommerce": 65,
    "cdn-waf": 70,
}


class _MetadataParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self._in_title = False
        self.parts: list[str] = []
        self.meta: dict[str, list[str]] = {}
        self.scripts: list[str] = []
        self.stylesheets: list[str] = []

    def handle_starttag(self, tag, attrs):
        normalized_tag = tag.lower()
        attributes = {str(key).lower(): str(value or "") for key, value in attrs}
        if normalized_tag == "title":
            self._in_title = True
        elif normalized_tag == "meta":
            name = (attributes.get("name") or attributes.get("property") or attributes.get("http-equiv") or "").lower()
            content = attributes.get("content", "")
            if name and content:
                self.meta.setdefault(name, []).append(content)
        elif normalized_tag == "script" and attributes.get("src"):
            self.scripts.append(attributes["src"])
        elif normalized_tag == "link" and "stylesheet" in attributes.get("rel", "").lower() and attributes.get("href"):
            self.stylesheets.append(attributes["href"])

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
    meta: dict[str, list[str]] = {}
    scripts: list[str] = []
    stylesheets: list[str] = []
    if "html" in content_type.lower() or "<html" in text[:1000].lower():
        parser = _MetadataParser()
        parser.feed(text)
        title = " ".join(" ".join(parser.parts).split())[:300]
        meta = {key: sorted(set(values)) for key, values in parser.meta.items()}
        scripts = sorted(set(parser.scripts))
        stylesheets = sorted(set(parser.stylesheets))
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
        "meta": meta,
        "scripts": scripts,
        "stylesheets": stylesheets,
        "sample_bytes": len(sample),
        "sample_truncated": len(content) > len(sample),
    }


def fingerprint_response(endpoint: str, status: int, response, metadata: dict) -> list[Discovery]:
    headers = {key.lower(): value for key, value in response.headers.items()}
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
    for matched in match_signatures(metadata, headers):
        for signal in matched["signals"]:
            observe(matched["technology"], matched["category"], signal, matched["version"])

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
            "detection_method": "offline-signature",
            "confidence": confidence,
            "source": "offline-http-signatures",
            "signals": signals,
            "signature_version": SIGNATURE_SET_VERSION,
            "raw_observation": "; ".join(signals),
        }))
    return discoveries
