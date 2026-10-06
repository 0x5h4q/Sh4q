"""An empty certificate-transparency source list means do not run the stage.

The validator refused an empty list and told the operator to "disable the
stage instead" -- which nothing could do. CT was appended unconditionally
and no flag skipped it.

That gap shows up on a single-host target. Scanning
`cuportal.example.com` runs CT looking for `*.cuportal.example.com`:
`_clean_hostname` keeps only names ending in `.{target}`, so siblings and
the parent are correctly discarded and what remains is sub-subdomains,
which rarely exist. On a real estate that stage cost four minutes and
disclosed the target to three services for nothing.

The lever belongs in configuration rather than a tenth stage flag. The
nine existing ones encode a policy -- active-low stages stay explicitly
opt-in -- and a setting that already has a home should not become a flag.
"""

import asyncio

from sh4q.application.scan_runner import _default_config
from sh4q.config import Sh4qConfig
from sh4q.plugins.ct_plugin import CTPlugin

# --- an empty list is accepted, and means "do not run" --------------------
off = Sh4qConfig(
    scope={"targets": ["example.com"]},
    certificate_transparency={"sources": []},
)
assert off.certificate_transparency.sources == []

# --- the default is unchanged --------------------------------------------
assert _default_config("example.com").certificate_transparency.sources == [
    "certspotter", "crt.sh",
]
assert Sh4qConfig(scope={"targets": ["example.com"]}).certificate_transparency.sources == [
    "certspotter", "crt.sh",
]

# --- an unknown source is still refused, and still names what is valid ----
try:
    Sh4qConfig(scope={"targets": ["example.com"]},
               certificate_transparency={"sources": ["nope"]})
    raise AssertionError("an unknown source must be refused")
except Exception as error:
    assert "nope" in str(error), error
    assert "crt.name" in str(error), "the error must list what is available"

# --- the plugin builds no connectors from an empty list -------------------
assert CTPlugin(config=off)._connectors == []


# --- and a stage with no connectors reports that, rather than succeeding --
async def main() -> None:
    import contextlib
    import io

    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        results = await CTPlugin(config=off).execute("example.com")
    assert results == [], results
    text = output.getvalue()
    assert "CT providers:" not in text, (
        f"an empty provider table claims the stage ran: {text!r}"
    )

    print("certificate transparency opt-out test passed")


asyncio.run(main())


# --- scan_runner does not append the stage at all -------------------------
import inspect  # noqa: E402

from sh4q.application import scan_runner  # noqa: E402

source = inspect.getsource(scan_runner)
assert "if config.certificate_transparency.sources:" in source, (
    "the stage must be skipped, not run with nothing to ask"
)

print("certificate transparency wiring test passed")
