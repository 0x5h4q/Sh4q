from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


@dataclass(frozen=True)
class Dependency:
    name: str
    executable: str
    install_hint: str
    # Some tool names are not unique. `httpx` in particular is both the
    # ProjectDiscovery scanner and the console script of the Python httpx
    # library, and the Python one shadows the scanner whenever a virtual
    # environment is active. Reporting the first match on PATH would tell an
    # operator a tool is present when the thing found cannot do the job.
    identity: Callable[[str], bool] | None = None


@dataclass(frozen=True)
class DependencyReport:
    """What was found for one dependency, and what was passed over."""

    dependency: Dependency
    path: str | None
    rejected: tuple[str, ...] = ()


def executables_on_path(executable: str) -> list[str]:
    """Every executable of this name on PATH, in search order, deduplicated."""
    found: list[str] = []
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(directory or ".") / executable
        if candidate.is_file() and os.access(candidate, os.X_OK):
            resolved = str(candidate.resolve())
            if resolved not in found:
                found.append(resolved)
    return found


def is_projectdiscovery_httpx(path: str) -> bool:
    """Distinguish the ProjectDiscovery scanner from the Python httpx CLI."""
    try:
        result = subprocess.run(
            [path, "-version"],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    output = f"{result.stdout}\n{result.stderr}".lower()
    return "projectdiscovery" in output or "current version" in output


OPTIONAL_DEPENDENCIES = (
    Dependency("subfinder", "subfinder", "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    Dependency(
        "httpx",
        "httpx",
        "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        identity=is_projectdiscovery_httpx,
    ),
    Dependency("waybackurls", "waybackurls", "go install github.com/tomnomnom/waybackurls@latest"),
    Dependency("katana", "katana", "go install -v github.com/projectdiscovery/katana/cmd/katana@latest"),
)


def dependency_reports() -> list[DependencyReport]:
    """Resolve each dependency the way a scan would, not just by name."""
    reports: list[DependencyReport] = []
    for item in OPTIONAL_DEPENDENCIES:
        if item.identity is None:
            reports.append(DependencyReport(item, shutil.which(item.executable)))
            continue
        rejected: list[str] = []
        chosen: str | None = None
        for candidate in executables_on_path(item.executable):
            if item.identity(candidate):
                chosen = candidate
                break
            rejected.append(candidate)
        reports.append(DependencyReport(item, chosen, tuple(rejected)))
    return reports


def dependency_status() -> dict[str, str | None]:
    return {report.dependency.name: report.path for report in dependency_reports()}


def required_dependencies(*, subfinder=False, httpx=False, url_history=False, katana=False) -> list[Dependency]:
    requested = {"subfinder": subfinder, "httpx": httpx, "waybackurls": url_history, "katana": katana}
    return [item for item in OPTIONAL_DEPENDENCIES if requested[item.name]]


def missing_dependencies(**requested) -> list[Dependency]:
    status = dependency_status()
    return [item for item in required_dependencies(**requested) if status[item.name] is None]


def format_missing(dependencies: list[Dependency]) -> str:
    lines = ["Scan cannot start because requested optional tools are missing.", "", "Missing:"]
    lines.extend(f"  {item.name}  required by the corresponding scan option/profile" for item in dependencies)
    lines.extend(["", "Install:"])
    lines.extend(f"  {item.install_hint}" for item in dependencies)
    lines.extend(["", "Run `sh4q doctor` to check all optional dependencies."])
    return "\n".join(lines)
