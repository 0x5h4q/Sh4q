"""Amass 4+ is rejected before a scan starts rather than reported as empty.

`amass enum` stopped printing discovered names to stdout at v4: it renders
a progress bar to stderr and stores findings in a local database that
`amass subs -names` reads back. The passive adapter parses stdout, so
against a modern Amass it observes nothing and reports a successful stage
with zero discoveries -- indistinguishable from a domain with no passive
records.
"""

import asyncio
from pathlib import Path

from sh4q.adapters import AdapterExecutionError, parse_amass_version, validate_amass


assert parse_amass_version("v5.1.1") == (5, 1, 1)
assert parse_amass_version("v3.23.3") == (3, 23, 3)
assert parse_amass_version("amass version 3.19.2 released") == (3, 19, 2)
assert parse_amass_version("no version here") is None
assert parse_amass_version("") is None


class FakeResult:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout, self.stderr, self.returncode = stdout, stderr, returncode


class FakeRunner:
    def __init__(self, stdout="", stderr=""):
        self._result = FakeResult(stdout, stderr)
        self.calls = []

    async def run(self, argv, **kwargs):
        self.calls.append(argv)
        return self._result


async def main() -> None:
    # A supported release is accepted and identified.
    runner = FakeRunner(stdout="v3.23.3")
    identity = await validate_amass("/usr/bin/amass", runner, cwd=Path("."))
    assert identity == "amass v3.23.3", identity
    assert runner.calls == [("/usr/bin/amass", "-version")]

    # v4 and v5 are refused, and the message says what to use instead.
    for release in ("v4.2.0", "v5.1.1"):
        try:
            await validate_amass("/usr/bin/amass", FakeRunner(stderr=release), cwd=Path("."))
        except AdapterExecutionError as error:
            message = str(error)
            assert "supports Amass 3.x" in message, message
            assert release.lstrip("v") in message, message
            assert "--sub" in message, "the message must point at a working alternative"
        else:
            raise AssertionError(f"{release} should have been refused")

    # An unreadable version is refused rather than assumed compatible.
    try:
        await validate_amass("/usr/bin/amass", FakeRunner(stdout="???"), cwd=Path("."))
    except AdapterExecutionError as error:
        assert "could not determine the Amass version" in str(error)
    else:
        raise AssertionError("an unparseable version should have been refused")

    print("amass version guard test passed")


asyncio.run(main())
