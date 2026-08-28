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
    scan_asset_store=None,
    scan_run_id: str | None = None,
):
    display_counts: dict[str, int] = {}

    def display_bounded(category: str, message: str, limit: int = 10) -> None:
        count = display_counts.get(category, 0) + 1
        display_counts[category] = count
        if count <= limit:
            print(message)
        elif count == limit + 1:
            print(f"  ... additional {category} results suppressed; full details remain in evidence")

    async def record_asset(
        counter: str,
        asset_id: str,
        relationship_id: str,
        source_plugin: str,
        scan_run_id: str | None,
    ) -> bool:
        if stats is None:
            return True
        source_assets = stats.setdefault(f"_{counter}_ids", set())
        all_assets = stats.setdefault("_asset_ids", set())
        relationships = stats.setdefault("_relationship_ids", set())
        is_new_relationship = relationship_id not in relationships
        if scan_asset_store is not None:
            await scan_asset_store.record(
                scan_run_id, asset_id, relationship_id, source_plugin
            )
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
        event_scan_run_id = event.payload.get("scan_run_id") or scan_run_id

        await evidence_store.append(
            Evidence(
                id=event.id,
                target=scan_target,
                plugin=source_plugin,
                kind=kind,
                content=data,
                scan_run_id=event_scan_run_id,
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
            if await record_asset("dns_addresses", ip_node.id, relationship.id, source_plugin, event_scan_run_id):
                print(f"  SAVED: {domain} --RESOLVES_TO--> {ip}")

        elif kind == "discovered_dns_resolution":
            domain = data["domain"]
            ip = data["ip"]
            if stats is not None:
                stats["resolved_discovered_attempted"] = stats.get("resolved_discovered_attempted", 0) + 1
            decision = scope.authorize(domain)
            if not decision.allowed:
                if stats is not None:
                    stats["resolved_discovered_failures"] = stats.get("resolved_discovered_failures", 0) + 1
                print(f"  GATE 2 DENY: {domain} -> {decision.reason} (not persisted as an asset)")
                return
            address_decision = scope.authorize_resolved_address(ip)
            if not address_decision.allowed:
                if stats is not None:
                    stats["resolved_discovered_failures"] = stats.get("resolved_discovered_failures", 0) + 1
                print(f"  GATE 2 DENY: {ip} -> {address_decision.reason} (not persisted as an asset)")
                return
            domain_node = Node(type="domain", value=domain)
            ip_node = Node(type="ip", value=ip)
            await storage.save_node(domain_node)
            await storage.save_node(ip_node)
            relationship = Relationship(from_id=domain_node.id, to_id=ip_node.id, type="RESOLVES_TO")
            await storage.save_relationship(relationship)
            await record_asset("resolved_discovered_addresses", domain_node.id, relationship.id, source_plugin, event_scan_run_id)
            display_bounded("discovered DNS success", f"  SAVED: {domain} --RESOLVES_TO--> {ip}")

        elif kind == "discovered_dns_error":
            if stats is not None:
                stats["resolved_discovered_failures"] = stats.get("resolved_discovered_failures", 0) + 1
            display_bounded(
                "discovered DNS failure",
                f"  FAILED  discovered_dns_error: {data.get('domain')}: {data.get('error', 'unknown error')}",
            )

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
            if await record_asset("http_endpoints", url_node.id, relationship.id, source_plugin, event_scan_run_id):
                print(f"  SAVED: {host} --SERVES--> {final_url} [{data['status']}]")

        elif kind == "http_fingerprint":
            endpoint = _canonical_url(data["endpoint"])
            host = HttpURL(endpoint).host
            decision = scope.authorize(host)
            if not decision.allowed:
                print(
                    f"  GATE 2 DENY: {host} -> {decision.reason} "
                    f"(fingerprint not persisted)"
                )
                return

            url_node = Node(type="url", value=endpoint)
            await storage.save_node(url_node)
            for technology in sorted(set(data.get("technologies") or [])):
                normalized = str(technology).strip().lower()
                if not normalized:
                    continue
                technology_node = Node(
                    type="technology",
                    value=normalized,
                    attributes={"observed_name": str(technology).strip()},
                )
                await storage.save_node(technology_node)
                relationship = Relationship(
                    from_id=url_node.id,
                    to_id=technology_node.id,
                    type="DETECTED_TECHNOLOGY",
                    attributes={
                        "detection_method": data.get("detection_method", ""),
                        "confidence": data.get("confidence", "tool-reported"),
                        "status": data.get("status"),
                        "title": data.get("title", ""),
                        "source": data.get("source", source_plugin),
                    },
                )
                await storage.save_relationship(relationship)
                await record_asset(
                    "technologies",
                    technology_node.id,
                    relationship.id,
                    source_plugin,
                    event_scan_run_id,
                )

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
            await record_asset(counter, sub_node.id, relationship.id, source_plugin, event_scan_run_id)

        elif kind == "ct_provider_status":
            # CTPlugin prints one compact provider table. The event remains
            # durable evidence, but does not add duplicate console output.
            return

        elif kind == "adapter_execution":
            if data.get("timed_out"):
                print(
                    f"  FAILED  {data.get('adapter', 'adapter')}: "
                    f"execution timed out after {data.get('duration_seconds', '?')}s"
                )
            elif data.get("output_limited"):
                print(f"  FAILED  {data.get('adapter', 'adapter')}: output limit exceeded")
            elif data.get("returncode") != 0:
                detail = (data.get("stderr") or "").strip().splitlines()
                suffix = f": {detail[0]}" if detail else ""
                print(
                    f"  FAILED  {data.get('adapter', 'adapter')}: "
                    f"exit {data.get('returncode')}{suffix}"
                )
            elif not (data.get("stdout") or "").strip():
                print(f"  {data.get('adapter', 'adapter')}: completed with no output")
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
