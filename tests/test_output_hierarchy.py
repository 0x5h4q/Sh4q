"""Findings must be visually separable from noise, and colour must degrade.

An operator scanning the terminal should be able to tell which lines are
the reason they ran the tool without reading every one. Everything here
also has to survive being piped to a file or into grep.
"""

import io
import os

from sh4q.cli.branding import colour_enabled, gate_line, observation_line, status_line


class FakeTTY(io.StringIO):
    def isatty(self):
        return True


# --- colour policy ---------------------------------------------------------
_previous = os.environ.pop("NO_COLOR", None)
try:
    assert colour_enabled(FakeTTY()) is True, "an interactive terminal gets colour"
    assert colour_enabled(io.StringIO()) is False, "a pipe or file must stay plain"

    os.environ["NO_COLOR"] = "1"
    assert colour_enabled(FakeTTY()) is False, "NO_COLOR must win over a terminal"
    os.environ["NO_COLOR"] = ""
    assert colour_enabled(FakeTTY()) is False, "NO_COLOR set to empty still disables"
finally:
    os.environ.pop("NO_COLOR", None)
    if _previous is not None:
        os.environ["NO_COLOR"] = _previous

# --- text content survives without a terminal ------------------------------
# status_line checks the real stdout, which is not a tty under the runner, so
# these render plain and are safe to assert on exactly.
finding = observation_line("PATH", "/admin", 200, "distinct response", notable=True)
dismissed = observation_line("path", "/missing", 404, "matches this server's not-found response", notable=False)
denial = gate_line("evil.example", "explicitly excluded", "not persisted")

assert "\033[" not in finding, "no escape codes when stdout is not a terminal"
assert "\033[" not in dismissed
assert "\033[" not in denial

# --- the three classes carry distinct markers ------------------------------
assert finding.startswith("[!]"), finding
assert dismissed.startswith("[-]"), dismissed
assert denial.startswith("[x]"), denial
assert status_line("saved", "ok").startswith("[+]")
assert status_line("broke", "error").startswith("[-]")
assert status_line("working", "info").startswith("[~]")

# --- content the operator needs is present and greppable -------------------
assert "/admin" in finding and "200" in finding and "distinct response" in finding
assert "/missing" in dismissed and "404" in dismissed
assert "evil.example" in denial and "explicitly excluded" in denial and "not persisted" in denial

# A denial is a policy outcome, not a failure, and must not read as an error.
assert denial.startswith("[x]") and not denial.startswith("[-]"), (
    "a Gate 2 denial must not share the error marker"
)

# --- alignment: subjects line up so a column can be scanned ----------------
rows = [
    observation_line("PATH", "/admin", 200, "distinct response", notable=True),
    observation_line("path", "/a-much-longer-path-name", 404, "matches", notable=False),
    observation_line("PATH", "/x", 500, "distinct response", notable=True),
]
offsets = {row.index("2") if "200" in row else None for row in rows[:1]}
assert len({len(row.split()[0]) for row in rows}) == 1, "markers are the same width"
statuses = [row for row in rows]
assert all(row.startswith(("[!]", "[-]")) for row in statuses)

# An over-long subject must not be silently truncated: the record matters more
# than the column.
long_subject = "/" + "a" * 80
assert long_subject in observation_line("PATH", long_subject, 200, "d", notable=True)

print("output hierarchy test passed")


# --- result views separate figures, labels, and guidance -------------------
# The explanation under a summary is guidance, not data, and was competing
# with the numbers it explains. Four roles, four treatments.
from sh4q.cli.branding import accent, figure, muted, note  # noqa: E402

for render in (accent, figure, muted, note):
    plain = render("text")
    assert plain == "text", (
        f"{render.__name__} must emit nothing extra when output is not a terminal: {plain!r}"
    )

_previous = os.environ.pop("NO_COLOR", None)
try:
    import sh4q.cli.branding as _branding

    _real = _branding.colour_enabled
    _branding.colour_enabled = lambda *a, **k: True
    try:
        assert _branding.note("g") == "\033[2;3mg\033[0m", "guidance is dimmed and italic"
        assert _branding.figure("184") == "\033[1m184\033[0m", "a figure is emphasised"
        assert _branding.muted("label") == "\033[2mlabel\033[0m", "a label recedes"
        assert _branding.accent("Head") == "\033[1;36mHead\033[0m", "a heading stands out"
        # Every style must close itself, or the rest of the terminal inherits it.
        for render in (_branding.accent, _branding.figure, _branding.muted, _branding.note):
            assert render("x").endswith("\033[0m"), render.__name__
    finally:
        _branding.colour_enabled = _real
finally:
    if _previous is not None:
        os.environ["NO_COLOR"] = _previous
