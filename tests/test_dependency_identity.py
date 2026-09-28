"""`doctor` must report a tool that works, not the first name that matches.

`httpx` is both the ProjectDiscovery scanner and the console script of the
Python httpx library. With a virtual environment active the Python one
comes first on PATH, so `shutil.which("httpx")` returned it and doctor
reported PASS pointing at a program that cannot scan anything. Scans were
unaffected -- scan_runner validates every candidate -- but doctor exists
precisely to answer "will my tools work".
"""

import os
import stat
import tempfile
from pathlib import Path

from sh4q.dependencies import (
    OPTIONAL_DEPENDENCIES,
    dependency_reports,
    dependency_status,
    executables_on_path,
    is_projectdiscovery_httpx,
)


def make_executable(directory: Path, name: str, body: str) -> Path:
    path = directory / name
    path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


root = Path(tempfile.mkdtemp(prefix="sh4q_identity_"))
impostor_dir = root / "venv-bin"
real_dir = root / "usr-local-bin"
impostor_dir.mkdir()
real_dir.mkdir()

# The Python httpx CLI: right name, wrong tool, and it fails when invoked.
impostor = make_executable(
    impostor_dir,
    "httpx",
    'echo "The httpx command line client could not run because the required '
    'dependencies were not installed." >&2; exit 1',
)
# ProjectDiscovery httpx announces itself on -version.
real = make_executable(real_dir, "httpx", 'echo "[INF] Current Version: v1.9.0" >&2')

# --- the identity check separates them -----------------------------------
assert is_projectdiscovery_httpx(str(real)) is True
assert is_projectdiscovery_httpx(str(impostor)) is False
assert is_projectdiscovery_httpx(str(root / "does-not-exist")) is False, (
    "a missing executable must be rejected, not raise"
)

previous_path = os.environ.get("PATH", "")
try:
    # The impostor is first, exactly as an active virtual environment arranges.
    os.environ["PATH"] = f"{impostor_dir}{os.pathsep}{real_dir}"

    found = executables_on_path("httpx")
    assert found == [str(impostor), str(real)], found

    report = next(r for r in dependency_reports() if r.dependency.name == "httpx")
    assert report.path == str(real), (
        f"doctor must report the tool that works, got {report.path}"
    )
    assert str(impostor) in report.rejected, (
        "the shadowing executable must be named, so the operator can see why"
    )
    assert dependency_status()["httpx"] == str(real)

    # Only the impostor present: that is a miss, not a false pass.
    os.environ["PATH"] = str(impostor_dir)
    report = next(r for r in dependency_reports() if r.dependency.name == "httpx")
    assert report.path is None, f"an unusable httpx must not report as present: {report.path}"
    assert report.rejected == (str(impostor),)

    # Tools without an identity check keep the plain lookup.
    subfinder = make_executable(impostor_dir, "subfinder", "echo ok")
    report = next(r for r in dependency_reports() if r.dependency.name == "subfinder")
    assert report.path == str(subfinder), report.path
    assert report.rejected == ()
finally:
    os.environ["PATH"] = previous_path

# Only httpx needs disambiguating today; if that changes, this will say so.
with_identity = {d.name for d in OPTIONAL_DEPENDENCIES if d.identity is not None}
assert with_identity == {"httpx"}, with_identity

import shutil  # noqa: E402

shutil.rmtree(root, ignore_errors=True)
print("dependency identity test passed")
