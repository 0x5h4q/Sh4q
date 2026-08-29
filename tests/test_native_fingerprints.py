import httpx

from sh4q.fingerprints import extract_http_metadata, fingerprint_response


response = httpx.Response(
    200,
    request=httpx.Request("GET", "https://example.com/"),
    headers=[
        ("server", "nginx/1.25.4"),
        ("x-powered-by", "PHP/8.2"),
        ("cf-ray", "abc-LHR"),
        ("cf-cache-status", "DYNAMIC"),
        ("set-cookie", "PHPSESSID=abc; Secure; HttpOnly"),
        ("content-type", "text/html; charset=utf-8"),
    ],
    content=b"<html><head><title> Demo Site </title></head><body><script src='/wp-content/app.js'></script><div id='__NEXT_DATA__'></div></body></html>",
)
metadata = extract_http_metadata(response)
assert metadata["title"] == "Demo Site"
assert metadata["cookie_names"] == ["PHPSESSID"]
assert not metadata["sample_truncated"]

discoveries = fingerprint_response(str(response.url), response.status_code, response, metadata)
findings = {item.data["technologies"][0]: item.data for item in discoveries}
assert findings["nginx"]["version"] == "1.25.4"
assert findings["PHP"]["confidence"] == "high"
assert findings["Cloudflare"]["confidence"] == "high"
assert findings["WordPress"]["category"] == "cms"
assert findings["Next.js"]["category"] == "web-framework"
assert all(item.data["signature_version"] == "2026.08.1" for item in discoveries)
print("native fingerprint signature test passed")
