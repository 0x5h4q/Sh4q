from httpx import URL as HttpURL

from sh4q.events import Event
from sh4q.scope import ScopeEngine
from sh4q.storage import Node, Relationship, StorageRepository
from sh4q.storage.evidence import Evidence, EvidenceStore


def _canonical_url(value: str) -> str:
    url = HttpURL(value)
    scheme = url.scheme.lower()
    host = (url.host or "").lower().rstrip(".")
    default_port = (scheme == "https" and url.port == 443) or (scheme == "http" and url.port == 80)
    authority = host if url.port is None or default_port else f"{host}:{url.port}"
    path = url.path.rstrip("/") or "/"
    return f"{scheme}://{authority}{path}" + (f"?{url.query.decode()}" if url.query else "")


def make_discovery_handler(
    scope: ScopeEngine,
    storage: StorageRepository,
    evidence_store: EvidenceStore,
    stats: dict | None = None,
):
    def record_asset(counter: str, asset_id: str, relationship_id: str) -> bool:
        if stats is None:
            return True
        source_assets = stats.setdefault(f"_{counter}_ids", set())
        all_assets = stats.setdefault("_asset_ids", set())
        relationships = stats.setdefault("_relationship_ids", set())
        is_new_relationship = relationship_id not in relationships
        source_assets.add(asset_id)
        all_assets.add(asset_id)
        relationships.add(relationship_id)
        stats[counter] = len(source_assets)
        stats["discoveries"] = len(all_assets)
        stats["relationships"] = len(relationships)
        return is_new_relationship

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

            # The hostname was authorized at Gate 1. The resolved IP is
            # checked against address safety policy, not hostname scope.
            decision = scope.authorize_resolved_address(ip)

            if not decision.allowed:
                print(
                    f"  GATE 2 DENY: {ip} -> {decision.reason} "
                    f"(not persisted as an asset)"
                )
                return

            ip_node = Node(type="ip", value=ip)
            await storage.save_node(ip_node)

            relationship = Relationship(from_id=domain_node.id, to_id=ip_node.id, type="RESOLVES_TO")
            await storage.save_relationship(relationship)
            if record_asset("dns_addresses", ip_node.id, relationship.id):
                print(f"  SAVED: {domain} --RESOLVES_TO--> {ip}")

        elif kind == "http_probe":
            final_url = _canonical_url(data["final_url"])
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

            relationship = Relationship(from_id=domain_node.id, to_id=url_node.id, type="SERVES")
            await storage.save_relationship(relationship)
            if record_asset("http_endpoints", url_node.id, relationship.id):
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

            relationship = Relationship(from_id=root_node.id, to_id=sub_node.id, type="HAS_SUBDOMAIN")
            await storage.save_relationship(relationship)
            counter = "ct_names" if source_plugin == "ct" else "adapter_names"
            record_asset(counter, sub_node.id, relationship.id)

        elif kind == "ct_provider_status":
            # CTPlugin prints one compact provider table. The event remains
            # durable evidence, but does not add duplicate console output.
            return

        elif kind == "adapter_execution":
            # Raw execution details are already preserved as evidence. Keep
            # terminal output compact; parsed discoveries are reported below.
            return

        elif kind == "ct_rate_limited":
            source = data.get("source") or source_plugin or "unknown"
            retry_after = data.get("retry_after")

            if retry_after is not None:
                print(f"  CT RATE LIMITED: {source} (Retry-After: {retry_after}s)")
            else:
                print(f"  CT RATE LIMITED: {source}")

        elif kind in ("http_error", "dns_error", "ct_error"):
            phase = data.get("phase")
            suffix = f" [{phase}]" if phase else ""
            print(f"  FAILED  {kind}{suffix}: {data.get('error', 'unknown error')}")

        else:
            print(f"  (no handler yet for discovery kind={kind!r})")

    return handle_discovery
