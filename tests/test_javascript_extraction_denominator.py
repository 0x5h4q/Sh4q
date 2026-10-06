"""A JavaScript stage that found nothing says what it looked at.

On a real scan the stage ran in 0.00s, printed STAGE COMPLETE, and produced
nothing. It had in fact examined three pages totalling 21KB, none of which
contained a single <script> tag -- a correct result, and indistinguishable
from the stage having had no HTML to look at. Those are different states:
one means the pages are clean, the other means the scan never saw them.

`results --type javascript` made it worse by asserting the reason: "The
extraction stage runs under --js, --profile web, or --profile full" is
false advice when the stage did run.

Same rule as everywhere else: a zero states its denominator.
"""

import asyncio
import contextlib
import io

from sh4q.javascript_extraction import JavaScriptExtractionLimits
from sh4q.plugins.javascript_extraction_plugin import JavaScriptExtractionPlugin

PLAIN = "<html><head><title>no script here</title></head><body>hi</body></html>"
WITH_SCRIPT = '<html><body><script src="https://example.com/app.js"></script></body></html>'


def plugin_for(observations):
    async def provider(target):
        return observations

    return JavaScriptExtractionPlugin(provider, limits=JavaScriptExtractionLimits())


async def rendered(observations):
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        results = await plugin_for(observations).execute("example.com")
    return results, output.getvalue()


async def main() -> None:
    # --- examined pages, found nothing: both numbers must be stated --------
    results, text = await rendered([
        {"endpoint": "http://a.example.com/", "content": PLAIN},
        {"endpoint": "http://b.example.com/", "content": PLAIN},
        {"endpoint": "http://c.example.com/", "content": PLAIN},
    ])
    assert results == [], [r.kind for r in results]
    assert "3" in text, f"the number of endpoints examined must appear: {text!r}"
    assert "endpoint" in text.lower(), text

    # --- nothing to examine is a different statement ----------------------
    _, empty = await rendered([])
    assert "3" not in empty
    assert empty.strip(), "a stage with no input must still say so"
    assert empty != text, "no HTML and clean HTML must not read identically"

    # --- a page with references still reports what it examined ------------
    found, with_text = await rendered([
        {"endpoint": "http://a.example.com/", "content": WITH_SCRIPT},
    ])
    assert found, "a script reference must still be extracted"
    assert "1" in with_text, with_text

    # --- an endpoint with no usable content is not counted as examined ----
    _, skipped = await rendered([
        {"endpoint": "http://a.example.com/", "content": PLAIN},
        {"endpoint": None, "content": PLAIN},
        {"endpoint": "http://c.example.com/", "content": None},
    ])
    assert "1 " in skipped or "1 endpoint" in skipped, (
        f"only the usable endpoint counts as examined: {skipped!r}"
    )

    print("javascript extraction denominator test passed")


asyncio.run(main())


# --- the results view must not assert a reason it cannot know --------------
import inspect  # noqa: E402

from sh4q.cli import main as cli  # noqa: E402

_cli = inspect.getsource(cli)
assert "The extraction\\n  stage runs under" not in _cli, (
    "the view cannot know the stage did not run; it may have run and found nothing"
)
assert "found no references" in _cli or "found nothing" in _cli, (
    "the empty case must offer both explanations"
)

print("javascript empty-view wording test passed")
