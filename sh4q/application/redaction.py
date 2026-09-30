from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SECRET_KEYS = {"token", "access_token", "api_key", "apikey", "key", "secret", "password", "passwd", "auth", "authorization"}

def redact_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"}:
        return value
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if not any(key.lower() in SECRET_KEYS for key, _ in pairs):
        # Keep the query byte-for-byte. Round-tripping it through urlencode
        # rewrote queries that had nothing to redact: a bare cache-buster like
        # "?0808dd08ad62f57" parses as one valueless key and came back out as
        # "?0808dd08ad62f57=", so --redact silently altered 8 of the 238 URLs
        # in a real scan. A redacted report must differ from the observation
        # only where something was redacted.
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))
    redacted = [
        (key, "[REDACTED]" if key.lower() in SECRET_KEYS else item)
        for key, item in pairs
    ]
    # The brackets are left literal: percent-encoded as %5BREDACTED%5D the
    # marker is far harder to recognise in a report handed to someone else.
    return urlunsplit((
        parsed.scheme, parsed.netloc, parsed.path, urlencode(redacted, safe="[]"), ""
    ))


@dataclass
class Redactor:
    """Applies URL redaction and records how much it changed.

    A safety feature that cannot be distinguished from a no-op is a trap.
    `--redact` printed the same "Exported 381 asset(s)" line whether it
    rewrote four hundred values or none, so a verification run against a
    database whose URLs happen to carry no query string looked exactly like a
    working one -- and so would a regression that silently stopped redacting.

    Counting also covers the gap this class closes: redaction reached only the
    `value` field of url assets, so the technology CSV's endpoint column, the
    HTTP-inventory endpoint column, and the exported JavaScript observations
    -- the one place an extracted URL most often carries a key -- went out
    unredacted under `--redact`.
    """

    enabled: bool = False
    considered: int = 0
    redacted: int = 0

    def url(self, value: str) -> str:
        """Redact one URL-bearing field, counting whether anything changed."""
        if not self.enabled or not isinstance(value, str) or not value:
            return value
        self.considered += 1
        cleaned = redact_url(value)
        if cleaned != value:
            self.redacted += 1
        return cleaned

    def summary(self) -> str:
        """One line stating what redaction did, for the operator who asked."""
        if not self.enabled:
            return ""
        if not self.considered:
            return "Redaction was on; no URL-bearing field was exported."
        return (
            f"Redaction rewrote {self.redacted} of {self.considered} "
            f"URL-bearing field(s)."
        )
