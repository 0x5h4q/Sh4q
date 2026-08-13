"""
sh4q/handlers.py

The initial discovery handler — deliberately a plain function, not a
Normalizer class (per the Week 3 scoping decision). Subscribes to the
Event bus, converts Discovery payloads into Node/Relationship, and
persists them through Storage.

This is also where Gate 2 lives: a newly discovered target (e.g. the IP
a domain resolves to) gets its own scope check before Sh4q treats it as
an actual asset — separate from Gate 1, which already authorized the
original target before the plugin ever ran.
"""

from httpx import URL as HttpURL

from sh4q.events import Event
from sh4q.scope import ScopeEngine
from sh4q.storage import Node, Relationship, StorageRepository
from sh4q.storage.evidence import Evidence, EvidenceStore


def make_discovery_handler(scope: ScopeEngine, storage: StorageRepository, evidence_store: EvidenceStore):
    """Returns an event handler bound to a specific ScopeEngine, Storage,
    and EvidenceStore instance, matching the EventBus's single-argument
    Handler shape."""

    async def handle_discovery(event: Event) -> None:
        kind = event.payload["kind"]
        data = event.payload["data"]
        source_plugin = event.payload.get("source_plugin", "unknown")

        # Evidence is appended UNCONDITIONALLY — it records what was
        # observed, independent of whether Gate 2 later decides it's
        # authorized to become part of the believed asset graph. This is
        # the "why do we believe this" trail, and it should exist even
        # for things that get denied.
        await evidence_store.append(
            Evidence(
                id=event.id,
                target=data.get("domain") or data.get("final_url") or data.get("url") or "",
                plugin=source_plugin,
                kind=kind,
                content=data,
            )
        )

        if kind == "dns_resolution":
            domain = data["domain"]
            ip = data["ip"]

            # The domain itself was already Gate-1-authorized before the
            # plugin ran, so it's saved unconditionally.
            domain_node = Node(type="domain", value=domain)
            await storage.save_node(domain_node)

            # Gate 2: the IP is a NEWLY discovered target. A domain being
            # in scope does not automatically mean its resolved IP is —
            # e.g. shared hosting or a CDN IP a program explicitly excludes.
            decision = scope.authorize(ip)
            if not decision.allowed:
                print(f"  GATE 2 DENY: {ip} -> {decision.reason} (not persisted as an asset)")
                return

            ip_node = Node(type="ip", value=ip)
            await storage.save_node(ip_node)
            await storage.save_relationship(
                Relationship(from_id=domain_node.id, to_id=ip_node.id, type="RESOLVES_TO")
            )
            print(f"  SAVED: {domain} --RESOLVES_TO--> {ip}")

        elif kind == "http_probe":
            final_url = data["final_url"]
            host = HttpURL(final_url).host

            # Gate 2 again, same principle, different trigger: a redirect
            # can land on a completely different host than the one that
            # was originally authorized. Check the ACTUAL host reached,
            # not the one that was requested.
            decision = scope.authorize(host)
            if not decision.allowed:
                print(f"  GATE 2 DENY: {host} -> {decision.reason} ({final_url} not persisted)")
                return

            domain_node = Node(type="domain", value=host)
            await storage.save_node(domain_node)

            url_node = Node(
                type="url",
                value=final_url,
                attributes={"status": data["status"], "server": data.get("server", "")},
            )
            await storage.save_node(url_node)
            await storage.save_relationship(
                Relationship(from_id=domain_node.id, to_id=url_node.id, type="SERVES")
            )
            print(f"  SAVED: {host} --SERVES--> {final_url} [{data['status']}]")

        else:
            print(f"  (no handler yet for discovery kind={kind!r})")

    return handle_discovery