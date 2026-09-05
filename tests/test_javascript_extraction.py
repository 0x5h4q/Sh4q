from sh4q.javascript_extraction import (
    JavaScriptExtractionLimits,
    extract_javascript_observations,
    extract_javascript_bundle_observations,
)


html = """
<html>
  <script src="/static/app.js"></script>
  <script>
    fetch('/api/users');
    const key = 'AKIA1234567890ABCDEF';
    const external = 'https://cdn.example.net/lib.js';
  </script>
  <link rel="stylesheet" href="https://cdn.example.net/site.css">
</html>
"""

punctuation_html = "<script>fetch('https://api.example.com/v1/users;')</script>"
punctuation = extract_javascript_observations(punctuation_html, "https://example.com/")
assert punctuation[0]["value"] == "https://api.example.com/v1/users"

observations = extract_javascript_observations(
    html,
    "https://example.com/dashboard",
)

assert {item["kind"] for item in observations} == {
    "script_url",
    "endpoint_reference",
    "secret_like_pattern",
}
assert {item["value"] for item in observations if item["kind"] == "script_url"} == {
    "https://example.com/static/app.js",
}
assert "https://example.com/api/users" in {
    item["value"] for item in observations if item["kind"] == "endpoint_reference"
}
assert "https://cdn.example.net/site.css" not in {
    item["value"] for item in observations if item["kind"] == "endpoint_reference"
}
assert all("AKIA1234567890ABCDEF" not in str(item) for item in observations)

limited = extract_javascript_observations(
    html,
    "https://example.com/",
    JavaScriptExtractionLimits(max_results=1),
)
assert len(limited) == 1
print("javascript extraction test passed")

bundle = extract_javascript_bundle_observations(
    "fetch('/api/profile'); const key = 'AKIA1234567890ABCDEF';",
    "https://example.com/static/app.js",
)
assert {item["kind"] for item in bundle} == {
    "endpoint_reference",
    "secret_like_pattern",
}
