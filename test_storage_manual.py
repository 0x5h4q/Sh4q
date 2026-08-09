
import asyncio
import os
from sh4q.storage import Node, Relationship, SQLiteStorage


async def main():
    db_path = "/tmp/sh4q_test.db"
    if os.path.exists(db_path):
        os.remove(db_path)

    storage = SQLiteStorage(db_path)
    await storage.init()

    print("-- save + get a node --")
    domain = Node(type="domain", value="example.com", attributes={"source": "dns_plugin"})
    await storage.save_node(domain)
    fetched = await storage.get_node("domain:example.com")
    print(f"  saved id: {domain.id}")
    print(f"  fetched: {fetched.type} {fetched.value} attrs={fetched.attributes}")

    print()
    print("-- dedup / merge: discover the same node again with new info --")
    domain_again = Node(type="domain", value="example.com", attributes={"tls_grade": "A"})
    await storage.save_node(domain_again)
    merged = await storage.get_node("domain:example.com")
    print(f"  merged attrs: {merged.attributes}")
    print(f"  first_seen preserved: {merged.first_seen == domain.first_seen}")

    print()
    print("-- relationship: domain RESOLVES_TO ip --")
    ip = Node(type="ip", value="93.184.216.34")
    await storage.save_node(ip)
    rel = Relationship(from_id=domain.id, to_id=ip.id, type="RESOLVES_TO")
    await storage.save_relationship(rel)
    rels = await storage.get_relationships(domain.id)
    print(f"  relationships for {domain.id}: {[(r.from_id, r.type, r.to_id) for r in rels]}")

    print()
    print("-- relationship idempotency: save the exact same relationship twice --")
    await storage.save_relationship(rel)
    rels_after = await storage.get_relationships(domain.id)
    print(f"  count after re-saving same relationship: {len(rels_after)} (should still be 1)")


asyncio.run(main())