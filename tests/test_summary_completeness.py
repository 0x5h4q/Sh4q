"""A summary counts everything, or it is worse than no summary.

list_assets caps at 1000 rows because it feeds a terminal listing, and
results --limit defaults to 100. Both are right for a listing. Both were
being used by views that aggregate, so a scan of 1209 hostnames reported
1000 and a scan of 228 endpoints reported 87 -- each looking complete,
neither carrying any indication it had stopped early.

This is the same failure as the truncated HTTP stage: a confident total
over a partial set.
"""

import asyncio
import os
import tempfile

from sh4q.application.results import list_response_attributes, summarize_names
from sh4q.storage import Node, SQLiteStorage
from sh4q.storage.evidence import Evidence, SQLiteEvidenceStore

# Deliberately above both caps: 100 (the --limit default) and 1000 (the
# hard cap inside list_assets).
DOMAINS = 1209
URLS = 228


async def main() -> None:
    handle, db_path = tempfile.mkstemp(prefix="sh4q_summary_", suffix=".db")
    os.close(handle)
    os.remove(db_path)
    try:
        storage = SQLiteStorage(db_path)
        await storage.init()
        evidence = SQLiteEvidenceStore(db_path)
        await evidence.init()

        for i in range(DOMAINS):
            await storage.save_node(Node(type="domain", value=f"h{i:05d}.example.com"))
        for i in range(URLS):
            await storage.save_node(Node(
                type="url",
                value=f"https://h{i:05d}.example.com/",
                attributes={
                    "cookies": [{"name": "s", "secure": False, "http_only": False, "same_site": ""}],
                    "security_headers": {"x-frame-options": "", "strict-transport-security": ""},
                },
            ))
        # a resolution outcome for a third of the names
        for i in range(0, DOMAINS, 3):
            await evidence.append(Evidence(
                id=f"r{i}", target="example.com", plugin="discovered-dns",
                kind="discovered_dns_resolution",
                content={"domain": f"h{i:05d}.example.com", "ip": "1.2.3.4"},
            ))

        composition = summarize_names(db_path)
        assert composition.total == DOMAINS, (
            f"the summary must count every name, reported {composition.total} of {DOMAINS}"
        )
        assert composition.resolved == len(range(0, DOMAINS, 3)), composition.resolved
        assert composition.resolved + composition.unresolved + composition.unchecked == DOMAINS, (
            "every name must land in exactly one bucket"
        )

        attributes = list_response_attributes(db_path)
        assert len(attributes) == URLS, (
            f"every endpoint must be counted, reported {len(attributes)} of {URLS}"
        )

        # An explicit limit still works for callers that want a page.
        assert len(list_response_attributes(db_path, limit=10)) == 10

        print("summary completeness test passed")
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


asyncio.run(main())


# --- an export is never shortened -----------------------------------------
# list_technology_observations clamped to 1000 even when asked for more, and
# the exporter asked for exactly 1000. A terminal listing caps because it is
# read on screen; an export is handed to someone else, and a silently
# shortened one is worse than none.
import inspect  # noqa: E402

from sh4q.application import exporter  # noqa: E402
from sh4q.application.results import list_technology_observations  # noqa: E402

_source = inspect.getsource(exporter)
assert "limit=1000" not in _source, "the export must not carry a row cap"
assert "list_technology_observations(database, scan_id=run.id, limit=None)" in _source

_listing = inspect.getsource(list_technology_observations)
assert "min(limit, 1000)" not in _listing, (
    "an explicit limit must be honoured rather than silently clamped"
)


# --- the same label must not mean two different things --------------------
# "DNS addresses" counted the scan target's addresses in the summary and
# every host's in the overview: 6 against 11 for one scan, with the five
# hidden by the smaller figure being the origins outside the CDN.
from sh4q.cli import main as cli  # noqa: E402

_cli = inspect.getsource(cli)
assert '("Target addresses"' in _cli, "the summary figure must say it is the target's"
assert "Addresses, all hosts" in _cli, "the overview figure must say it covers every host"
assert _cli.count('"DNS addresses"') == 0, "the ambiguous label must not remain"
