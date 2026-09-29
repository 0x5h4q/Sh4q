"""Hostnames are summarised by resolution outcome and leftmost label.

A real scan returned 908 certificate-transparency names. 524 of them
shared a service prefix that hosting panels request certificates for
automatically, and not one of those resolved. Establishing that by hand
took a database query, a bulk DNS pass, and a control test. Sh4q had
every input already.

The prefix alone proves nothing -- organisations do run mail.example.com
-- so the summary crosses it with whether the name resolved and says so
in the output.
"""

import asyncio
import os
import tempfile

from sh4q.application.results import AUTO_ISSUED_LABELS, summarize_names
from sh4q.storage import Node, SQLiteStorage
from sh4q.storage.evidence import Evidence, SQLiteEvidenceStore


async def main() -> None:
    handle, db_path = tempfile.mkstemp(prefix="sh4q_names_", suffix=".db")
    os.close(handle)
    os.remove(db_path)
    try:
        storage = SQLiteStorage(db_path)
        await storage.init()
        evidence = SQLiteEvidenceStore(db_path)
        await evidence.init()

        real = ["app.example.com", "portal.example.com", "mail.example.com"]
        auto = ["cpanel.a.example.com", "webmail.a.example.com", "webdisk.a.example.com"]
        never_checked = ["later.example.com"]
        for name in real + auto + never_checked:
            await storage.save_node(Node(type="domain", value=name))

        async def record(index, kind, domain):
            await evidence.append(Evidence(
                id=f"e{index}", target="example.com", plugin="discovered-dns",
                kind=kind, content={"domain": domain, "ip": "1.2.3.4"},
            ))

        # app and portal resolve; mail resolves too, which is the point of
        # crossing the label with the outcome rather than trusting the label.
        for i, name in enumerate(["app.example.com", "portal.example.com", "mail.example.com"]):
            await record(i, "discovered_dns_resolution", name)
        # every cpanel-style name fails, as they did in the real scan
        for i, name in enumerate(auto, start=10):
            await record(i, "discovered_dns_error", name)

        c = summarize_names(db_path)
        assert c.total == 7, c.total
        assert c.resolved == 3, c.resolved
        assert c.unresolved == 3, c.unresolved
        assert c.unchecked == 1, f"a name nothing tried must not count as failed: {c.unchecked}"

        # mail.example.com carries a service prefix AND resolved, so the
        # summary must report it as auto-issued yet confirmed.
        assert c.auto_issued == 4, c.auto_issued
        assert c.auto_issued_resolved == 1, (
            "a service-prefix name that resolves must be counted as resolved, "
            f"not dismissed: {c.auto_issued_resolved}"
        )
        assert c.auto_issued_share == 57, c.auto_issued_share

        labels = dict(c.label_counts)
        assert labels["cpanel"] == 1 and labels["webmail"] == 1, labels
        assert len(c.label_counts) <= 8, "the label list stays readable"

        # A resolution recorded after a failure wins: a name is not both.
        await record(99, "discovered_dns_resolution", "webdisk.a.example.com")
        c2 = summarize_names(db_path)
        assert c2.resolved == 4 and c2.unresolved == 2, (c2.resolved, c2.unresolved)
        assert c2.auto_issued_resolved == 2, c2.auto_issued_resolved

        # An empty database summarises to nothing rather than raising.
        handle2, empty = tempfile.mkstemp(prefix="sh4q_names_empty_", suffix=".db")
        os.close(handle2)
        os.remove(empty)
        empty_store = SQLiteStorage(empty)
        await empty_store.init()
        await SQLiteEvidenceStore(empty).init()
        blank = summarize_names(empty)
        assert blank.total == 0 and blank.auto_issued_share == 0
        os.remove(empty)

        assert {"cpanel", "webmail", "webdisk", "mail"} <= AUTO_ISSUED_LABELS

        print("name composition test passed")
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


asyncio.run(main())
