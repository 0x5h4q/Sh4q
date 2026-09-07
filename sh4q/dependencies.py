from __future__ import annotations

import shutil
from dataclasses import dataclass


@dataclass(frozen=True)
class Dependency:
    name: str
    executable: str
    install_hint: str


OPTIONAL_DEPENDENCIES = (
    Dependency("subfinder", "subfinder", "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    Dependency("amass", "amass", "go install -v github.com/owasp-amass/amass/v4/...@master"),
    Dependency("httpx", "httpx", "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    Dependency("waybackurls", "waybackurls", "go install github.com/tomnomnom/waybackurls@latest"),
    Dependency("katana", "katana", "go install -v github.com/projectdiscovery/katana/cmd/katana@latest"),
)


def dependency_status() -> dict[str, str | None]:
    return {item.name: shutil.which(item.executable) for item in OPTIONAL_DEPENDENCIES}


def required_dependencies(*, subfinder=False, amass=False, httpx=False, url_history=False, katana=False) -> list[Dependency]:
    requested = {"subfinder": subfinder, "amass": amass, "httpx": httpx, "waybackurls": url_history, "katana": katana}
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
