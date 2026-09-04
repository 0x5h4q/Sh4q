from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SECRET_KEYS = {"token", "access_token", "api_key", "apikey", "key", "secret", "password", "passwd", "auth", "authorization"}

def redact_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"}:
        return value
    pairs = [(key, "[REDACTED]" if key.lower() in SECRET_KEYS else item) for key, item in parse_qsl(parsed.query, keep_blank_values=True)]
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(pairs), ""))
