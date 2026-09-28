"""Storage guarantees that make at-least-once event delivery safe.

The event bus can deliver the same event twice after a crash, so every
persistence path has to be idempotent. This asserts the three properties
that depend on: a repeated node merges rather than duplicating, first_seen
survives the merge, and a repeated relationship stays single.

This file previously only printed its observations -- including the line
"(should still be 1)" -- and asserted nothing, so it passed regardless of
what storage did. It was also outside the offline runner.
"""

import asyncio
import os
import tempfile

from sh4q.storage import Node, Relationship, SQLiteStorage


async def main() -> None:
    handle, db_path = tempfile.mkstemp(prefix="sh4q_storage_manual_", suffix=".db")
    os.close(handle)
    os.remove(db_path)
    try:
        storage = SQLiteStorage(db_path)
        await storage.init()

        # A node round-trips with its attributes and a deterministic id.
        domain = Node(type="domain", value="example.com", attributes={"source": "dns_plugin"})
        await storage.save_node(domain)
        assert domain.id == "domain:example.com", domain.id
        fetched = await storage.get_node("domain:example.com")
        assert fetched is not None, "a saved node must be retrievable"
        assert fetched.type == "domain" and fetched.value == "example.com"
        assert fetched.attributes.get("source") == "dns_plugin", fetched.attributes

        # Re-discovering the same node merges new attributes instead of
        # replacing the record or creating a second one.
        await storage.save_node(
            Node(type="domain", value="example.com", attributes={"tls_grade": "A"})
        )
        merged = await storage.get_node("domain:example.com")
        assert merged.attributes.get("tls_grade") == "A", merged.attributes
        assert merged.attributes.get("source") == "dns_plugin", (
            f"the merge dropped an existing attribute: {merged.attributes}"
        )
        assert merged.first_seen == domain.first_seen, (
            "first_seen must survive a merge, or asset history becomes meaningless"
        )

        # A relationship is stored once and retrievable from its source node.
        ip = Node(type="ip", value="93.184.216.34")
        await storage.save_node(ip)
        relationship = Relationship(from_id=domain.id, to_id=ip.id, type="RESOLVES_TO")
        await storage.save_relationship(relationship)
        stored = await storage.get_relationships(domain.id)
        assert len(stored) == 1, stored
        assert (stored[0].from_id, stored[0].type, stored[0].to_id) == (
            domain.id,
            "RESOLVES_TO",
            ip.id,
        ), stored[0]

        # Replaying the same event must not duplicate the edge. This is the
        # property that makes crash recovery safe.
        await storage.save_relationship(relationship)
        await storage.save_relationship(relationship)
        after_replay = await storage.get_relationships(domain.id)
        assert len(after_replay) == 1, (
            f"a repeated relationship must stay single, found {len(after_replay)}"
        )

        print("storage manual test passed")
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


asyncio.run(main())
