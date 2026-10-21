"""The exported rules are valid Sigma according to Sigma's own parser.

Structural assertions in `test_detection_export.py` guard the two defects
this exporter shipped with, but they are assertions I wrote about a format
I do not own. This runs the reference implementation over the output.

It found both defects. `id: sh4q-subdomain-enumeration` read fine to a
human and is not a valid Sigma identifier -- `id` must be a UUID. And
`condition: selection | count(query_name) by src_ip > 380` is the
deprecated aggregation form; pySigma refuses it outright, so every rule
the first version exported would load in no Sigma pipeline at all.

Optional because it needs pySigma, which is not a project dependency:
`pip install sigma-cli`. Registered in OPTIONAL_INTEGRATION_TESTS and run
with `--include-integration`.

The `attacktag` validator is excluded deliberately: it resolves the MITRE
taxonomy over the network, and this suite must not reach out to anyone.
That leaves the ATT&CK tags themselves unverified here -- see the note at
the end.
"""

import sqlite3
import sys
import tempfile
from pathlib import Path

try:
    from sigma.collection import SigmaCollection
    from sigma.validation import SigmaValidator
    from sigma.validators.core import validators as core_validators
except ModuleNotFoundError:
    # Loudly, not silently. A skipped check that reads like a pass is the
    # trap this project keeps rediscovering.
    print(
        "SKIPPED: pySigma is not installed, so the exported rules were NOT\n"
        "         validated against Sigma's own parser. Install it with\n"
        "         `pip install sigma-cli` and run this again."
    )
    raise SystemExit(0)

from sh4q.application.detection import Detection, DetectionReport, SIGNALS

TARGET = "example.com"

# Every signal a defender can see, at a rate high enough to clear the floor,
# so each rule shape this exporter can emit is actually parsed.
report = DetectionReport(
    scan_id="scan-1",
    target=TARGET,
    detections=tuple(
        Detection(
            signal=spec.signal, observed=900, window_seconds=90.0, rate=10.0,
            log_source=spec.log_source, attack=spec.attack,
            description=spec.description, _selection=spec.selection,
            _count_field=spec.count_field, _group_by=spec.group_by,
        )
        for spec in SIGNALS
    ),
)

rules = report.to_sigma_rules()
# One rule per distinct detection, not per signal: signals whose generated
# Sigma is identical are merged, so every visible signal must appear in some
# rule's filename without each one getting a file of its own.
visible = [spec for spec in SIGNALS if spec.log_source]
covered = {name for spec in visible for name in rules if spec.signal in name}
assert len(covered) == len(rules), (sorted(rules), sorted(covered))
for spec in visible:
    assert any(spec.signal in name for name in rules), (
        f"{spec.signal} is visible but appears in no exported rule: {sorted(rules)}"
    )
assert len(rules) <= len(visible), (sorted(rules), len(visible))

parsed = []
for name, text in sorted(rules.items()):
    try:
        collection = SigmaCollection.from_yaml(text)
    except Exception as error:                        # noqa: BLE001
        raise AssertionError(f"{name} is not valid Sigma: {error}\n\n{text}") from error
    kinds = [type(rule).__name__ for rule in collection.rules]
    assert kinds == ["SigmaRule", "SigmaCorrelationRule"], (
        f"{name} must be a base rule plus a correlation over it, got {kinds}"
    )
    parsed.extend(collection.rules)

# The non-network validators: unknown fields, duplicate ids, title length,
# dangling correlation references, and the rest.
offline = {
    cls for name, cls in core_validators.items() if name != "attacktag"
}
validator = SigmaValidator(offline)
issues = list(validator.validate_rules(parsed)) + list(validator.finalize())
assert not issues, "\n".join(
    f"[{issue.severity.name}] {type(issue).__name__}: {issue}" for issue in issues
)

print(f"detection sigma validation test passed "
      f"({len(rules)} rule file(s), {len(parsed)} documents, "
      f"{len(offline)} validators, 0 issues)")
print("  NOTE: ATT&CK tag values are not checked here -- the validator that "
      "would\n        check them resolves the MITRE taxonomy over the network.")
