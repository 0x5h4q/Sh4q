"""Terminal presentation for the interactive scan command.

The output hierarchy exists so an operator scanning the terminal can tell,
without reading, which lines are the reason they ran the tool:

    finding   a response worth a human look -- the payload
    ok        an authorised asset was stored
    deny      policy refused a destination; expected, not an error
    muted     a negative result, kept for the record but not interesting
    error     something failed
    info      progress

Colour is applied only when stdout is a terminal and NO_COLOR is unset, so
piped and redirected output stays plain.
"""

import os
import shutil
import sys


SCAN_BANNER = "S H 4 Q\npolicy-controlled recon"

_MARKERS = {
    "finding": "[!]",
    "ok": "[+]",
    "deny": "[x]",
    "muted": "[-]",
    "error": "[-]",
    "info": "[~]",
}

_RESET = "\033[0m"
_STYLES = {
    "finding": "\033[1;33m",   # bold yellow: the line to look at
    "ok": "\033[32m",
    "deny": "\033[35m",        # magenta: a policy decision, not a failure
    "muted": "\033[2m",        # dim: recorded, not interesting
    "error": "\033[31m",
    "info": "\033[36m",
}


def colour_enabled(stream=None) -> bool:
    """Colour only for an interactive terminal, and never when NO_COLOR is set."""
    if os.environ.get("NO_COLOR") is not None:
        return False
    stream = stream or sys.stdout
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


def render_scan_banner(colored: bool = False, width: int | None = None) -> str:
    terminal_width = width or shutil.get_terminal_size((80, 24)).columns
    lines = [line.center(max(1, terminal_width)) for line in SCAN_BANNER.splitlines()]
    if not colored:
        return "\n".join(lines)
    cyan, green, reset = "\033[36m", "\033[32m", _RESET
    return "\n".join(
        f"{cyan if i % 2 == 0 else green}{line}{reset}"
        for i, line in enumerate(lines)
    )


def status_line(text: str, status: str = "info") -> str:
    marker = _MARKERS.get(status, _MARKERS["info"])
    if not colour_enabled():
        return f"{marker} {text}"
    style = _STYLES.get(status, _STYLES["info"])
    if status in {"finding", "muted"}:
        # Carry the emphasis across the whole line: these are the two the eye
        # needs to separate at a glance.
        return f"{style}{marker} {text}{_RESET}"
    return f"{style}{marker}{_RESET} {text}"


def observation_line(label: str, subject: str, status, detail: str, *, notable: bool) -> str:
    """One aligned row for a vhost or directory observation."""
    code = str(status if status not in (None, "") else "-")
    row = f"{label:<6} {subject:<34} {code:>4}  {detail}"
    return status_line(row.rstrip(), "finding" if notable else "muted")


def gate_line(subject: str, reason: str, note: str = "") -> str:
    """A Gate 2 refusal. Expected policy behaviour, styled apart from failures."""
    suffix = f" ({note})" if note else ""
    return status_line(f"GATE 2 DENY {subject} -> {reason}{suffix}", "deny")
