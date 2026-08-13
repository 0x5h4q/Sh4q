

from httpx import URL as HttpURL

from sh4q.events import Event
from sh4q.scope import ScopeEngine
from sh4q.storage import Node, Relationship, StorageRepository
from sh4q.storage.evidence import Evidence, EvidenceStore


def make_discovery_handler(scope: ScopeEngine, storage: StorageRepository, evidence_store: EvidenceStore):

    async def handle_discovery(event: Event) -> None:
        kind = event.payload["kind"]
        data = event.payload["data"]
        source_plugin = event.payload.get("source_plugin", "unknown")
        scan_target = event.payload.get("scan_target", "")
        await evidence_store.append(
            Evidence(
                id=event.id,
                target=scan_target,   # the actual scan target, not inferred from discovery content
                plugin=source_plugin,
                kind=kind,
                content=data,
            )
        )

        if kind == "dns_resolution":
            domain = data["domain"]
            ip = data["ip"]

            # The domain itself was already Gate-1-authorized before the plugin ran, so it's saved unconditionally.
            domain_node = Node(type="domain", value=domain)
            await storage.save_node(domain_node)

            # Gate 2: the IP is a NEWLY discovered target. A domain being in scope does not automatically mean its resolved IP is 
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