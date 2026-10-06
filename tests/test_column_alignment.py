"""A styled cell occupies the width it was padded to.

`len()` counts escape bytes, so styling before padding pads a coloured cell
short and every column after it drifts. The bug only appears with colour
on, which is exactly when nobody is diffing the output, and never in a
captured test run -- `colour_enabled()` is false without a TTY.

`column()` pads the plain text and styles the result, and this file pins
that by measuring the visible width with the escapes stripped.
"""

import re

from sh4q.cli import branding
from sh4q.cli.branding import accent, column, muted, note, refusal

ESCAPES = re.compile(r"\033\[[0-9;]*m")


def visible(text: str) -> str:
    return ESCAPES.sub("", text)


# --- with colour forced on, the width is still the width ------------------
original = branding.colour_enabled
branding.colour_enabled = lambda stream=None: True
try:
    for style in (accent, muted, note, refusal, None):
        cell = column("api.certspotter.com", 30, style)
        assert len(visible(cell)) == 30, (
            f"{style}: padded to {len(visible(cell))}, not 30"
        )
        if style is not None:
            assert len(cell) > 30, "a styled cell carries escapes beyond its width"
            assert cell.endswith("\033[0m"), "a styled cell must reset"

    # A whole row keeps its column boundaries.
    row = (
        column("service", 20, muted)
        + column("native", 12)
        + column("observed", 12, accent)
    )
    assert len(visible(row)) == 44, len(visible(row))
    assert visible(row) == "service".ljust(20) + "native".ljust(12) + "observed".ljust(12)

    # Text longer than the width is not truncated by column(); callers trim
    # first, so a surprise here would be silent column drift.
    long_cell = column("x" * 40, 10)
    assert len(visible(long_cell)) == 40, "column must not silently truncate"

    # A refusal is a policy decision, not an error: magenta, matching the
    # deny marker, never the red used for failures.
    assert "\033[35m" in refusal("refused"), refusal("refused")
    assert "\033[31m" not in refusal("refused"), "a refusal is not an error"
finally:
    branding.colour_enabled = original

# --- with colour off, nothing is emitted at all ---------------------------
branding.colour_enabled = lambda stream=None: False
try:
    for style in (accent, muted, note, refusal):
        cell = column("value", 12, style)
        assert cell == "value".ljust(12), repr(cell)
        assert "\033" not in cell, repr(cell)
finally:
    branding.colour_enabled = original

print("column alignment test passed")
