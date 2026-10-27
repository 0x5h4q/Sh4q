"""The exported rules convert to a real SIEM query, not merely parse.

Validation proves a rule is valid Sigma. It does not prove a backend can turn
it into a query a defender could run. This converts every exported rule with
the Splunk backend and checks that the correlation survives: a distinct count
over a fixed window, grouped by source, with the measured threshold.

Optional because backends are separate packages (`pip install
pysigma-backend-splunk`) and are not project dependencies. Registered in
OPTIONAL_INTEGRATION_TESTS and run with `--include-integration`.
"""

try:
    from sigma.backends.splunk import SplunkBackend
    from sigma.collection import SigmaCollection
except ModuleNotFoundError:
    # Loudly, not silently: a skipped check that reads like a pass is the trap
    # this project keeps rediscovering.
    print(
        "SKIPPED: a pySigma backend is not installed, so the exported rules\n"
        "         were NOT converted to a SIEM query. Install one with\n"
        "         `pip install pysigma-backend-splunk` and run this again."
    )
    raise SystemExit(0)

from sh4q.application.detection import Detection, DetectionReport, SIGNALS

TARGET = "example.com"

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

backend = SplunkBackend()
converted: list[tuple[str, str]] = []
for name, text in sorted(report.to_sigma_rules().items()):
    collection = SigmaCollection.from_yaml(text)
    queries = backend.convert(collection)
    assert queries, f"{name} converted to nothing"
    for query in queries:
        assert isinstance(query, str) and query.strip(), (name, query)
        converted.append((name, query))

joined = "\n".join(query for _, query in converted)
files = len({name for name, _ in converted})

# The correlation has to survive conversion intact, or the query no longer
# means what the exporter claimed: a distinct count of the breadth field, over
# the fixed window, grouped by the source, compared against the threshold.
assert "stats dc(" in joined, joined
assert "value_count" in joined, joined
assert "bin _time span=60s" in joined, joined
assert ">= " in joined, joined
# The backend quotes field names containing hyphens but not plain identifiers.
assert '"cs-host"' in joined, joined
assert "query_name" in joined, joined

print(
    f"detection sigma backend test passed "
    f"({len(converted)} converted quer"
    f"{'y' if len(converted) == 1 else 'ies'} from {files} rule file(s))"
)
