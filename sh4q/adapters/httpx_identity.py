from __future__ import annotations

from pathlib import Path

from .runner import AdapterExecutionError, ControlledProcessRunner


async def validate_projectdiscovery_httpx(
    executable: str,
    runner: ControlledProcessRunner,
    *,
    cwd: Path,
) -> str:
    """Reject unrelated executables that happen to be named ``httpx``."""
    result = await runner.run((executable, "-version"), cwd=cwd, timeout=5.0)
    output = "\n".join(part for part in (result.stdout, result.stderr) if part).strip()
    normalized = output.lower()
    if result.returncode != 0 or "projectdiscovery" not in normalized or "current version" not in normalized:
        raise AdapterExecutionError(
            "--httpx requires the ProjectDiscovery httpx CLI; "
            f"found incompatible executable at {executable}"
        )
    for line in output.splitlines():
        if "current version" in line.lower():
            return line.strip()
    return "ProjectDiscovery httpx"
