from httpx import URL as HttpURL

from sh4q.events import Event
from sh4q.scope import ScopeEngine
from sh4q.storage import Node, Relationship, StorageRepository
from sh4q.storage.evidence import Evidence, EvidenceStore


def make_discovery_handler(
    scope: ScopeEngine,
    storage: StorageRepository,
    evidence_store: EvidenceStore,
    stats: dict | None = None,
):
    async def handle_discovery(event: Event) -> None:
        kind = event.payload["kind"]
        data = event.payload["data"]
        source_plugin = event.payload.get("source_plugin", "unknown")
        scan_target = event.payload.get("scan_target", "")

        await evidence_store.append(
            Evidence(
                id=event.id,
                target=scan_target,
                plugin=source_plugin,
                kind=kind,
                content=data,
            )
        )

        if kind == "dns_resolution":
            domain = data["domain"]
            ip = data["ip"]

            domain_node = Node(type="domain", value=domain)
            await storage.save_node(domain_node)

            decision = scope.authorize(ip)

            if not decision.allowed:
                print(
                    f"  GATE 2 DENY: {ip} -> {decision.reason} "
                    f"(not persisted as an asset)"
                )
                return

            ip_node = Node(type="ip", value=ip)
            await storage.save_node(ip_node)

            await storage.save_relationship(
                Relationship(from_id=domain_node.id, to_id=ip_node.id, type="RESOLVES_TO")
            )

            if stats is not None:
                stats["relationships"] = stats.get("relationships", 0) + 1

            print(f"  SAVED: {domain} --RESOLVES_TO--> {ip}")

        elif kind == "http_probe":
            final_url = data["final_url"]
            host = HttpURL(final_url).host

            decision = scope.authorize(host)

            if not decision.allowed:
                print(
                    f"  GATE 2 DENY: {host} -> {decision.reason} "
                    f"({final_url} not persisted)"
                )
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

            if stats is not None:
                stats["relationships"] = stats.get("relationships", 0) + 1

            print(f"  SAVED: {host} --SERVES--> {final_url} [{data['status']}]")

        elif kind == "subdomain_found":
            hostname = data["hostname"]
            root_domain = data["domain"]
            root_node = Node(type="domain", value=root_domain)
            await storage.save_node(root_node)

            decision = scope.authorize(hostname)

            if not decision.allowed:
                print(
                    f"  GATE 2 DENY: {hostname} -> {decision.reason} "
                    f"(not persisted as an asset)"
                )
                return

            sub_node = Node(
                type="domain",
                value=hostname,
                attributes={"source": data.get("source", "")},
            )
            await storage.save_node(sub_node)

            await storage.save_relationship(
                Relationship(from_id=root_node.id, to_id=sub_node.id, type="HAS_SUBDOMAIN")
            )

            if stats is not None:
                stats["relationships"] = stats.get("relationships", 0) + 1

            print(f"  SAVED: {root_domain} --HAS_SUBDOMAIN--> {hostname}")

        elif kind == "ct_rate_limited":
            source = data.get("source") or source_plugin or "unknown"
            retry_after = data.get("retry_after")

            if retry_after is not None:
                print(f"  CT RATE LIMITED: {source} (Retry-After: {retry_after}s)")
            else:
                print(f"  CT RATE LIMITED: {source}")

        elif kind in ("http_error", "dns_error", "ct_error"):
            print(f"  FAILED  {kind}: {data.get('error', 'unknown error')}")

        else:
            print(f"  (no handler yet for discovery kind={kind!r})")

    return handle_discovery