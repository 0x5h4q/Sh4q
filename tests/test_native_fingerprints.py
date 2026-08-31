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
    content=b"<html><head><title> Demo Site </title><meta name='generator' content='WordPress 6.8'><link rel='stylesheet' href='/css/bootstrap-5.3.3.min.css'></head><body><script src='/wp-content/jquery-3.7.1.min.js'></script><div id='__NEXT_DATA__'></div></body></html>",
)
metadata = extract_http_metadata(response)
assert metadata["title"] == "Demo Site"
assert metadata["cookie_names"] == ["PHPSESSID"]
assert not metadata["sample_truncated"]
assert metadata["meta"]["generator"] == ["WordPress 6.8"]
assert metadata["scripts"] == ["/wp-content/jquery-3.7.1.min.js"]
assert metadata["stylesheets"] == ["/css/bootstrap-5.3.3.min.css"]

discoveries = fingerprint_response(str(response.url), response.status_code, response, metadata)
findings = {item.data["technologies"][0]: item.data for item in discoveries}
assert findings["nginx"]["version"] == "1.25.4"
assert findings["PHP"]["confidence"] == "high"
assert findings["Cloudflare"]["confidence"] == "high"
assert findings["Cloudflare"]["category"] == "cdn-waf"
assert findings["WordPress"]["category"] == "cms"
assert findings["WordPress"]["version"] == "6.8"
assert findings["Next.js"]["category"] == "web-framework"
assert findings["jQuery"]["version"] == "3.7.1"
assert findings["Bootstrap"]["version"] == "5.3.3"
assert all(item.data["signature_version"] == "2026.08.2" for item in discoveries)
assert all(item.data["detection_method"] == "offline-signature" for item in discoveries)
print("native fingerprint signature test passed")
