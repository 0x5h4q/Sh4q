"""A view describes the set it is actually showing.

Three statements from one real scan, each false in a different way.

`--js-kind secret_like_pattern` matched nothing and reported "No
JavaScript observations are recorded for this scan" -- while 55 were
recorded, none of that kind. A filter returning nothing says nothing
about whether the stage ran.

`--names` reported "past the per-scan resolution bound, which defaults to
500" on a scan configured for 1500. The default is not the bound that
applied, and the number that did apply is derivable from the data.

`--type javascript` listed `cdn.jsdelivr.net` and `apis.google.com`
beside the target's own scripts. Gate 2 had refused both: zero URL nodes
for either exist in the graph. The view reads evidence, which is correct
-- a refused observation belongs in the audit trail -- but it sits under
`results` next to `--type url`, which reads the authorized subset. Saying
which is which is the difference between an audit trail and a claim of
inventory.
"""

import asyncio
import os
import tempfile

from sh4q.application.results import list_javascript_observations
from sh4q.storage import Node, SQLiteStorage
from sh4q.storage.evidence import Evidence, SQLiteEvidenceStore

SCAN = "scan-1"
OWN = "https://example.com/app.js"
THIRD_PARTY = "https://cdn.jsdelivr.net/npm/select2/dist/js/select2.min.js"


async def main() -> None:
    handle, db_path = tempfile.mkstemp(prefix="sh4q_view_truth_", suffix=".db")
    os.close(handle)
    os.remove(db_path)
    try:
        storage = SQLiteStorage(db_path)
        await storage.init()
        evidence = SQLiteEvidenceStore(db_path)
        await evidence.init()

        # Both were observed; only the in-scope one became an asset.
        for index, value in enumerate((OWN, THIRD_PARTY)):
            await evidence.append(Evidence(
                id=f"e{index}", target="example.com", plugin="javascript-extraction",
                kind="javascript_script_url",
                content={"value": value, "source_endpoint": "https://example.com/"},
                scan_run_id=SCAN,
            ))
        await storage.save_node(Node(type="url", value=OWN))

        rows = list_javascript_observations(db_path, scan_id=SCAN)
        assert len(rows) == 2, rows

        by_value = {row.value: row for row in rows}
        assert by_value[OWN].in_inventory is True, (
            "an authorized reference is in the asset graph and must say so"
        )
        assert by_value[THIRD_PARTY].in_inventory is False, (
            "Gate 2 refused this host; the view must not present it as inventory"
        )

        # The handler canonicalises before persisting, so the comparison must
        # too. Raw-vs-stored reported "https://host" as refused while
        # "https://host/" sat in the graph -- a false accusation, worse than
        # the ambiguity it replaced.
        await evidence.append(Evidence(
            id="e2", target="example.com", plugin="javascript-extraction",
            kind="javascript_endpoint_reference",
            content={"value": "https://example.com", "source_endpoint": "https://example.com/"},
            scan_run_id=SCAN,
        ))
        await storage.save_node(Node(type="url", value="https://example.com/"))
        canonical = {row.value: row for row in list_javascript_observations(db_path, scan_id=SCAN)}
        assert canonical["https://example.com"].in_inventory is True, (
            "a reference differing only by canonicalisation is in the graph"
        )

        # A kind filter that matches nothing must not deny the others exist.
        empty = list_javascript_observations(db_path, scan_id=SCAN, kind="secret_like_pattern")
        assert empty == [], empty
        total = list_javascript_observations(db_path, scan_id=SCAN)
        assert len(total) == 3, "the unfiltered set is what the message must describe"

        print("javascript view truthfulness test passed")
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


asyncio.run(main())


# --- the empty message must distinguish "none" from "none of this kind" ----
import inspect  # noqa: E402

from sh4q.cli import main as cli  # noqa: E402

_cli = inspect.getsource(cli)
assert "no_javascript_message" in _cli, (
    "the empty case needs one helper, not a message that guesses"
)
from sh4q.cli.main import no_javascript_message  # noqa: E402

filtered = no_javascript_message(total=55, kind="secret_like_pattern")
assert "55" in filtered, filtered
assert "did not run" not in filtered, (
    f"55 observations exist, so the stage plainly ran: {filtered}"
)

none_at_all = no_javascript_message(total=0, kind=None)
assert "did not run" in none_at_all, none_at_all
assert "55" not in none_at_all

# A filter over an empty set is still an empty set, not a filter problem.
both_empty = no_javascript_message(total=0, kind="script_url")
assert "did not run" in both_empty, both_empty


# --- the bound reported is the one that applied ----------------------------
from sh4q.cli.main import resolution_bound_note  # noqa: E402

note_text = resolution_bound_note(unchecked=279, resolved=194, unresolved=1306)
assert "1500" in note_text, f"the bound that applied was 194+1306=1500: {note_text}"
assert "500" not in note_text.replace("1500", ""), (
    f"the default must not be quoted as though it applied: {note_text}"
)
assert "279" in note_text

print("results view messaging test passed")
