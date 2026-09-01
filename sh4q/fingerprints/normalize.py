from __future__ import annotations

import re


TECHNOLOGY_CATEGORIES = {
    "apache http server": "web-server",
    "cloudflare": "cdn-waf",
    "cloudflare browser insights": "analytics",
    "cloudflare bot management": "security",
    "elementor": "page-builder",
    "google analytics": "analytics",
    "google cloud": "cloud-platform",
    "google cloud cdn": "cdn",
    "hsts": "security-header",
    "http/2": "protocol",
    "http/3": "protocol",
    "joomla": "cms",
    "jquery": "javascript-library",
    "jquery migrate": "javascript-library",
    "mysql": "database",
    "php": "runtime",
    "wordpress": "cms",
}


def normalize_external_technology(observation: str) -> tuple[str, str, str]:
    """Return normalized name, explicit version, and conservative category."""
    observed = observation.strip()
    name = observed
    version = ""
    if ":" in observed:
        candidate_name, candidate_version = observed.rsplit(":", 1)
        if candidate_name and re.fullmatch(r"v?\d[\w.+-]*", candidate_version):
            name = candidate_name
            version = candidate_version.removeprefix("v")
    normalized = name.strip().lower()
    return normalized, version, TECHNOLOGY_CATEGORIES.get(normalized, "")
