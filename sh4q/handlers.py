from httpx import URL as HttpURL

from sh4q.events import Event
from sh4q.scope import ScopeEngine
from sh4q.storage import Node, Relationship, StorageRepository
from sh4q.storage.evidence import Evidence, EvidenceStore
from sh4q.cli.branding import status_line
from sh4q.fingerprints.normalize import normalize_external_technology


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
                print(status_line(f"SAVED: {domain} --RESOLVES_TO--> {ip}", "ok"))

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
            display_bounded("discovered DNS success", status_line(f"SAVED: {domain} --RESOLVES_TO--> {ip}", "ok"))

        elif kind == "discovered_dns_error":
            if stats is not None:
                stats["resolved_discovered_failures"] = stats.get("resolved_discovered_failures", 0) + 1
                reason = data.get("reason") or (
                    "timeout" if "timed out" in data.get("error", "").lower() else "resolver_error"
                )
                reasons = stats.setdefault("dns_failure_reasons", {})
                reasons[reason] = reasons.get(reason, 0) + 1
            display_bounded(
                "discovered DNS failure",
                status_line(f"FAILED discovered_dns_error: {data.get('domain')}: {data.get('error', 'unknown error')}", "error"),
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
                attributes={
                    "status": data["status"],
                    "server": data.get("server", ""),
                    "title": data.get("title", ""),
                    "content_type": data.get("content_type", ""),
                    "cookie_names": data.get("cookie_names", []),
                    "sample_bytes": data.get("sample_bytes", 0),
                    "sample_truncated": data.get("sample_truncated", False),
                },
            )
            await storage.save_node(url_node)

            relationship = Relationship(from_id=domain_node.id, to_id=url_node.id, type="SERVES")
            await storage.save_relationship(relationship)
            if await record_asset("http_endpoints", url_node.id, relationship.id, source_plugin, event_scan_run_id):
                message = status_line(
                    f"SAVED: {host} --SERVES--> {final_url} [{data['status']}]",
                    "ok",
                )
                if source_plugin == "discovered-http":
                    display_bounded("discovered HTTP success", message)
                else:
                    print(message)

        elif kind == "url_history_batch":
            accepted_nodes = []
            accepted_relationships = []
            ownership = []
            seen_relationships = set()
            for raw_url in data.get("urls", []):
                try:
                    historical_url = _canonical_url(raw_url)
                    host = HttpURL(historical_url).host
                except Exception:
                    continue
                decision = scope.authorize(host)
                if not decision.allowed:
                    if stats is not None:
                        stats["historical_urls_rejected"] = stats.get("historical_urls_rejected", 0) + 1
                    continue
                domain_node = Node(type="domain", value=host)
                url_node = Node(type="url", value=historical_url, attributes={"historical": True, "source": data.get("source", source_plugin)})
                relationship = Relationship(domain_node.id, url_node.id, "HISTORICAL_URL", {"source": data.get("source", source_plugin)})
                if relationship.id in seen_relationships:
                    continue
                seen_relationships.add(relationship.id)
                accepted_nodes.extend((domain_node, url_node))
                accepted_relationships.append(relationship)
                ownership.append((url_node.id, relationship.id, source_plugin))
            if hasattr(storage, "save_nodes_batch"):
                await storage.save_nodes_batch(accepted_nodes)
                await storage.save_relationships_batch(accepted_relationships)
            else:
                for node in accepted_nodes:
                    await storage.save_node(node)
                for relationship in accepted_relationships:
                    await storage.save_relationship(relationship)
            if scan_asset_store is not None and hasattr(scan_asset_store, "record_batch"):
                await scan_asset_store.record_batch(event_scan_run_id, ownership)
            elif scan_asset_store is not None:
                for asset_id, relationship_id, plugin in ownership:
                    await scan_asset_store.record(event_scan_run_id, asset_id, relationship_id, plugin)
            if stats is not None:
                ids = stats.setdefault("_historical_urls_ids", set())
                relationships = stats.setdefault("_relationship_ids", set())
                for node, relationship in zip(accepted_nodes[1::2], accepted_relationships):
                    ids.add(node.id)
                    stats.setdefault("_asset_ids", set()).add(node.id)
                    relationships.add(relationship.id)
                stats["historical_urls"] = len(ids)
                stats["discoveries"] = len(stats["_asset_ids"])
                stats["relationships"] = len(relationships)
            if accepted_relationships:
                print(status_line(f"SAVED: {len(accepted_relationships)} historical URLs (batched)", "ok"))

        elif kind == "url_history_found":
            raw_url = data.get("url", "")
            try:
                historical_url = _canonical_url(raw_url)
                host = HttpURL(historical_url).host
            except Exception:
                print(status_line(f"FAILED url_history_found: invalid URL {raw_url!r}", "error"))
                return
            decision = scope.authorize(host)
            if not decision.allowed:
                if stats is not None:
                    stats["historical_urls_rejected"] = stats.get("historical_urls_rejected", 0) + 1
                await evidence_store.append(Evidence(
                    id=f"{event.id}:scope-deny",
                    target=scan_target,
                    plugin=source_plugin,
                    kind="url_history_rejected",
                    content={"domain": host, "url": historical_url, "reason": decision.reason},
                    scan_run_id=event_scan_run_id,
                ))
                print(
                    f"  GATE 2 DENY: {host} -> {decision.reason} "
                    f"({historical_url} not persisted)"
                )
                return
            domain_node = Node(type="domain", value=host)
            await storage.save_node(domain_node)
            url_node = Node(
                type="url",
                value=historical_url,
                attributes={"historical": True, "source": data.get("source", source_plugin)},
            )
            await storage.save_node(url_node)
            relationship = Relationship(
                from_id=domain_node.id,
                to_id=url_node.id,
                type="HISTORICAL_URL",
                attributes={"source": data.get("source", source_plugin)},
            )
            await storage.save_relationship(relationship)
            if await record_asset("historical_urls", url_node.id, relationship.id, source_plugin, event_scan_run_id):
                persisted = (stats or {}).get("historical_urls", 0)
                if persisted and persisted % 250 == 0:
                    print(status_line(
                        f"URL history persistence: {persisted} accepted URLs stored",
                    ))
                display_bounded(
                    "historical URL success",
                    status_line(f"SAVED: {host} --HISTORICAL_URL--> {historical_url}", "ok"),
                )

        elif kind == "url_history_truncated":
            if stats is not None:
                stats["historical_urls_truncated"] = data.get("available", 0) - data.get("retained", 0)
            display_bounded(
                "historical URL notices",
                status_line(
                    f"URL history limited to {data.get('retained', 0)} of {data.get('available', '?')} URLs; "
                    "raw provider output remains in evidence", "error"
                ),
                limit=1,
            )

        elif kind == "javascript_secret_like_pattern":
            display_bounded(
                "JavaScript secret-like observations",
                status_line(
                    f"OBSERVED JavaScript pattern: {data.get('pattern', data.get('value', 'unknown'))} "
                    "(not validated or persisted as a secret)",
                ),
            )

        elif kind in {"javascript_script_url", "javascript_endpoint_reference"}:
            raw_url = data.get("value")
            if not raw_url:
                return
            try:
                reference_url = _canonical_url(raw_url)
                host = HttpURL(reference_url).host
            except Exception:
                return
            decision = scope.authorize(host)
            if not decision.allowed:
                print(f"  GATE 2 DENY: {host} -> {decision.reason} ({reference_url} not persisted)")
                return
            domain_node = Node(type="domain", value=host)
            url_node = Node(type="url", value=reference_url, attributes={"javascript_reference": True})
            relationship = Relationship(
                from_id=domain_node.id,
                to_id=url_node.id,
                type="JAVASCRIPT_REFERENCE",
                attributes={"source_endpoint": data.get("source_endpoint", "")},
            )
            await storage.save_node(domain_node)
            await storage.save_node(url_node)
            await storage.save_relationship(relationship)
            await record_asset("javascript_references", url_node.id, relationship.id, source_plugin, event_scan_run_id)

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
                observed_name = str(technology).strip()
                normalized, observed_version, inferred_category = (
                    normalize_external_technology(observed_name)
                )
                if not normalized:
                    continue
                technology_node = Node(
                    type="technology",
                    value=normalized,
                    attributes={"observed_name": observed_name},
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
                        "raw_observation": data.get("raw_observation", ""),
                        "category": data.get("category", "") or inferred_category,
                        "version": data.get("version", "") or observed_version,
                        "signals": data.get("signals", []),
                        "signature_version": data.get("signature_version", ""),
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
                print(status_line(
                    f"FAILED {data.get('adapter', 'adapter')}: "
                    f"execution timed out after {data.get('duration_seconds', '?')}s"
                , "error"))
            elif data.get("output_limited"):
                print(status_line(f"FAILED {data.get('adapter', 'adapter')}: output limit exceeded", "error"))
            elif data.get("returncode") != 0:
                detail = (data.get("stderr") or "").strip().splitlines()
                suffix = f": {detail[0]}" if detail else ""
                print(status_line(
                    f"FAILED {data.get('adapter', 'adapter')}: "
                    f"exit {data.get('returncode')}{suffix}"
                , "error"))
            elif not (data.get("stdout") or "").strip():
                print(status_line(f"{data.get('adapter', 'adapter')}: completed with no output"))
            return

        elif kind == "ct_rate_limited":
            source = data.get("source") or source_plugin or "unknown"
            retry_after = data.get("retry_after")

            if retry_after is not None:
                print(status_line(f"CT RATE LIMITED: {source} (Retry-After: {retry_after}s)", "error"))
            else:
                print(status_line(f"CT RATE LIMITED: {source}", "error"))

        elif kind in ("http_error", "dns_error", "ct_error"):
            phase = data.get("phase")
            suffix = f" [{phase}]" if phase else ""
            error = data.get("error") or "unknown error"
            message = status_line(f"FAILED {kind}{suffix}: {error}", "error")
            if source_plugin == "discovered-http":
                display_bounded("discovered HTTP failure", message)
            else:
                print(message)

        else:
            print(status_line(f"(no handler yet for discovery kind={kind!r})", "error"))

    return handle_discovery
