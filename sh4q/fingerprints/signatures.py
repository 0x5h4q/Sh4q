from __future__ import annotations

import re
from dataclasses import dataclass


SIGNATURE_SET_VERSION = "2026.08.2"


@dataclass(frozen=True)
class Pattern:
    field: str
    expression: str
    signal: str
    version_group: int | None = None


@dataclass(frozen=True)
class Signature:
    technology: str
    category: str
    patterns: tuple[Pattern, ...]
    minimum_matches: int = 1


SIGNATURES = (
    Signature("Cloudflare", "cdn-waf", (
        Pattern("header:cf-ray", r".+", "header:cf-ray"),
        Pattern("header:cf-cache-status", r".+", "header:cf-cache-status"),
    )),
    Signature("PHP", "runtime", (
        Pattern("cookie", r"^phpsessid$", "cookie:PHPSESSID"),
        Pattern("header:x-powered-by", r"php/?([\d.]+)?", "header:x-powered-by=PHP", 1),
    )),
    Signature("ASP.NET", "framework", (
        Pattern("cookie", r"^asp\.net_sessionid$", "cookie:ASP.NET_SessionId"),
        Pattern("header:x-powered-by", r"asp\.net(?:/?([\d.]+))?", "header:x-powered-by=ASP.NET", 1),
        Pattern("header:x-aspnet-version", r"([\d.]+)", "header:x-aspnet-version", 1),
    )),
    Signature("WordPress", "cms", (
        Pattern("html", r"/wp-content/", "html:/wp-content/"),
        Pattern("html", r"/wp-includes/", "html:/wp-includes/"),
        Pattern("meta:generator", r"wordpress\s*([\d.]+)?", "meta:generator=WordPress", 1),
    )),
    Signature("WooCommerce", "ecommerce", (
        Pattern("html", r"woocommerce", "html:woocommerce"),
        Pattern("script", r"woocommerce", "script:woocommerce"),
    )),
    Signature("Drupal", "cms", (
        Pattern("html", r"drupalsettings|/sites/default/files/", "html:drupal-marker"),
        Pattern("meta:generator", r"drupal\s*([\d.]+)?", "meta:generator=Drupal", 1),
    )),
    Signature("Joomla", "cms", (
        Pattern("meta:generator", r"joomla!?\s*([\d.]+)?", "meta:generator=Joomla", 1),
        Pattern("html", r"/media/system/js/", "html:joomla-media"),
    )),
    Signature("Next.js", "web-framework", (
        Pattern("html", r"__next_data__|/_next/", "html:nextjs-marker"),
        Pattern("header:x-powered-by", r"next\.js", "header:x-powered-by=Next.js"),
    )),
    Signature("React", "javascript-framework", (
        Pattern("html", r"data-reactroot|data-reactid", "html:react-marker"),
        Pattern("script", r"react(?:\.production)?(?:\.min)?\.js", "script:react"),
    )),
    Signature("Vue.js", "javascript-framework", (
        Pattern("html", r"data-v-[0-9a-f]{6,}", "html:vue-marker"),
        Pattern("script", r"vue(?:\.runtime)?(?:\.global)?(?:\.prod)?\.js", "script:vue"),
    )),
    Signature("Angular", "javascript-framework", (
        Pattern("html", r"ng-version=[\"']([\d.]+)", "html:ng-version", 1),
        Pattern("html", r"<app-root(?:\s|>)", "html:app-root"),
    )),
    Signature("jQuery", "javascript-library", (
        Pattern("script", r"jquery[-.]([\d.]+)(?:\.min)?\.js", "script:jquery", 1),
        Pattern("script", r"jquery(?:\.min)?\.js", "script:jquery"),
    )),
    Signature("Bootstrap", "ui-framework", (
        Pattern("script", r"bootstrap(?:\.bundle)?[-.]([\d.]+)(?:\.min)?\.js", "script:bootstrap", 1),
        Pattern("stylesheet", r"bootstrap[-.]([\d.]+)(?:\.min)?\.css", "stylesheet:bootstrap", 1),
        Pattern("stylesheet", r"bootstrap(?:\.min)?\.css", "stylesheet:bootstrap"),
    )),
    Signature("Shopify", "ecommerce", (
        Pattern("html", r"cdn\.shopify\.com|shopify\.theme", "html:shopify-marker"),
        Pattern("header:x-shopid", r".+", "header:x-shopid"),
    )),
    Signature("Laravel", "web-framework", (
        Pattern("cookie", r"^laravel_session$", "cookie:laravel_session"),
    )),
    Signature("Django", "web-framework", (
        Pattern("cookie", r"^csrftoken$", "cookie:csrftoken"),
        Pattern("cookie", r"^sessionid$", "cookie:sessionid"),
    ), minimum_matches=2),
)


def match_signatures(metadata: dict, headers: dict[str, str]) -> list[dict]:
    findings = []
    for signature in SIGNATURES:
        signals = []
        version = ""
        matched_patterns = 0
        for pattern in signature.patterns:
            pattern_matched = False
            for value in _field_values(pattern.field, metadata, headers):
                match = re.search(pattern.expression, value, flags=re.IGNORECASE)
                if not match:
                    continue
                pattern_matched = True
                signals.append(pattern.signal)
                if pattern.version_group and not version:
                    captured = match.group(pattern.version_group)
                    if captured:
                        version = captured
            matched_patterns += int(pattern_matched)
        if matched_patterns >= signature.minimum_matches:
            findings.append({
                "technology": signature.technology,
                "category": signature.category,
                "version": version,
                "signals": sorted(set(signals)),
            })
    return findings


def _field_values(field: str, metadata: dict, headers: dict[str, str]) -> list[str]:
    if field.startswith("header:"):
        value = headers.get(field.split(":", 1)[1], "")
        return [value] if value else []
    if field.startswith("meta:"):
        return metadata.get("meta", {}).get(field.split(":", 1)[1], [])
    if field == "cookie":
        return [str(value) for value in metadata.get("cookie_names", [])]
    if field == "script":
        return metadata.get("scripts", [])
    if field == "stylesheet":
        return metadata.get("stylesheets", [])
    if field == "html":
        return [metadata.get("html_sample", "")]
    return []
