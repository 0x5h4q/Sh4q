"""An extracted reference is not a JavaScript string literal.

A real scan produced 26 references ending in a backslash:

    https://ton.twimg.com/.../c76f4afb6133f143.css\\

That is the escape from the surrounding JS literal, caught by the URL
pattern because a backslash is not in its stop set. A backslash cannot
appear unescaped in a URL, so each of those is malformed. What precedes
it is the real reference, so the value is truncated there rather than
discarded.

They were refused at Gate 2 on this scan -- but only because the host was
out of scope. An in-scope reference with the same shape persists as an
asset whose value no browser would resolve, and asset values are what
`diff` compares and what an export hands to someone else.

Trailing punctuation was already trimmed for the same reason: a reference
is being lifted out of surrounding syntax, and the syntax must not come
with it.
"""

from sh4q.javascript_extraction import (
    JavaScriptExtractionLimits,
    extract_javascript_observations,
)

LIMITS = JavaScriptExtractionLimits()


def values(html, base="https://example.com/"):
    return [item["value"] for item in extract_javascript_observations(html, base, LIMITS)]


# --- the shape that produced it: an escaped string in a bundle ------------
found = values('<script>var a = "https://example.com/app.js\\\\";</script>')
assert found, "the reference must still be extracted"
for value in found:
    assert "\\" not in value, f"a JS escape came with the reference: {value!r}"
assert "https://example.com/app.js" in found, found

# --- several at once, as a real bundle produces --------------------------
bundle = (
    '<script>'
    'a="https://example.com/a.css\\\\";'
    'b="https://example.com/b.woff2\\\\";'
    'c="https://example.com/c.js";'
    '</script>'
)
found = values(bundle)
assert not any("\\" in v for v in found), found
assert {"https://example.com/a.css", "https://example.com/b.woff2",
        "https://example.com/c.js"} <= set(found), found

# --- an interior backslash truncates rather than poisoning the value -----
# The backslash marks where the match overran the literal, so what precedes
# it is the reference. Keeping the prefix preserves a real discovery; keeping
# the backslash would record a destination that cannot be resolved.
interior = values('<script>u="https://example.com/a\\\\b/c.js";</script>')
assert interior == ["https://example.com/a"], interior

# --- what must not change ------------------------------------------------
# Percent-encoding is legitimate and must survive untouched.
encoded = values('<script>u="https://example.com/a%5Cb.js";</script>')
assert "https://example.com/a%5Cb.js" in encoded, encoded

# Ordinary references are unaffected.
plain = values('<script src="https://example.com/app.js"></script>')
assert plain == ["https://example.com/app.js"], plain

# The existing trailing-punctuation trim still applies.
trimmed = values('<script>see https://example.com/doc.js, and more</script>')
assert "https://example.com/doc.js" in trimmed, trimmed

print("javascript escape artifact test passed")
