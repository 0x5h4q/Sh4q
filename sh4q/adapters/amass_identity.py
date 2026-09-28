"""Version compatibility check for the Amass CLI.

Amass changed its output contract at v4: `amass enum` no longer prints
discovered names to stdout. It renders a progress bar to stderr and stores
findings in a local database, which `amass subs -names` reads back. The
passive adapter parses stdout, so against v4 or newer it observes nothing
and reports a successful stage with no discoveries.

Detecting that is better than silently returning an empty result, which is
indistinguishable from a domain that genuinely has no passive records.
"""

from __future__ import annotations

import re
from pathlib import Path

from .runner import AdapterExecutionError, ControlledProcessRunner


SUPPORTED_MAJOR_VERSIONS = (3,)

_VERSION = re.compile(r"v?(\d+)\.(\d+)\.(\d+)")


def parse_amass_version(output: str) -> tuple[int, int, int] | None:
    match = _VERSION.search(output or "")
    if not match:
        return None
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


async def validate_amass(
    executable: str,
    runner: ControlledProcessRunner,
    *,
    cwd: Path,
) -> str:
    """Reject an Amass whose output contract this adapter cannot read."""
    result = await runner.run((executable, "-version"), cwd=cwd, timeout=5.0)
    output = "\n".join(part for part in (result.stdout, result.stderr) if part).strip()
    version = parse_amass_version(output)
    if version is None:
        raise AdapterExecutionError(
            f"--amass could not determine the Amass version from {executable}; "
            "this adapter supports Amass 3.x"
        )
    if version[0] not in SUPPORTED_MAJOR_VERSIONS:
        readable = ".".join(str(part) for part in version)
        raise AdapterExecutionError(
            f"--amass supports Amass 3.x, found v{readable}. Amass 4 and later no "
            "longer print discovered names to stdout: enum stores them in a local "
            "database that 'amass subs -names' reads back, so this adapter would "
            "observe nothing and report an empty stage. Use --sub (Subfinder) for "
            "passive subdomain discovery instead."
        )
    return f"amass v{'.'.join(str(part) for part in version)}"
