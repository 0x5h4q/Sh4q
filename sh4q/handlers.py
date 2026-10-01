from httpx import URL as HttpURL

from sh4q.events import Event
from sh4q.scope import ScopeEngine
from sh4q.storage import Node, Relationship, StorageRepository
from sh4q.storage.evidence import Evidence, EvidenceStore
from sh4q.cli.branding import gate_line, observation_line, status_line
from sh4q.fingerprints.normalize import normalize_external_technology
from sh4q.network import probe_url


def _effective_port(value: str) -> int | None:
    """The port a URL would be contacted on, or None when it cannot be known.

    `scope.ports` authorizes origins, and the asset graph is the authorized
    subset, so a port belongs in the persistence check and not only in the
    contact check. Returning None for anything that is not an absolute http(s)
    URL -- a relative JavaScript reference, say -- makes `authorize` skip the
    port rule, which keeps those references behaving exactly as they did.
    """
    try:
        url = HttpURL(value)
    except Exception:
        return None
    scheme = url.scheme.lower()
    if scheme not in {"http", "https"} or not url.host:
        return None
    return url.port or (443 if scheme == "https" else 80)


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
    javascript_displayed: set[str] = set()

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

    async def _dns_resolution(kind, data, source_plugin, scan_target, event_scan_run_id, event) -> None:
        domain = data["domain"]
        ip = data["ip"]

        # This used to save the domain node first and check only the address,
        # on the reasoning that Gate 1 had already authorized the hostname.
        # That holds only while the event belongs to the scan now running.
        # Delivery is durable and `recover_unfinished` filters on neither
        # target nor scan run, so one database can hand this handler an
        # unfinished event from a scan of an entirely different target --
        # which then entered the new scan's graph unauthorized. Authorize the
        # hostname here, under the scope that is handling it, and persist
        # nothing before both checks have passed.
        decision = scope.authorize(domain)
        if not decision.allowed:
            print(gate_line(domain, decision.reason, "not persisted"))
            return

        # Hostname scope and address safety are separate policies: an
        # authorized name may still resolve somewhere it may not be contacted.
        address_decision = scope.authorize_resolved_address(ip)
        if not address_decision.allowed:
            print(gate_line(ip, address_decision.reason, "not persisted"))
            return

        domain_node = Node(type="domain", value=domain)
        ip_node = Node(type="ip", value=ip)
        await storage.save_node(domain_node)
        await storage.save_node(ip_node)

        relationship = Relationship(from_id=domain_node.id, to_id=ip_node.id, type="RESOLVES_TO")
        await storage.save_relationship(relationship)
        if await record_asset("dns_addresses", ip_node.id, relationship.id, source_plugin, event_scan_run_id):
            print(status_line(f"SAVED: {domain} --RESOLVES_TO--> {ip}", "ok"))

    async def _discovered_dns_resolution(kind, data, source_plugin, scan_target, event_scan_run_id, event) -> None:
        domain = data["domain"]
        ip = data["ip"]
        if stats is not None:
            stats["resolved_discovered_attempted"] = stats.get("resolved_discovered_attempted", 0) + 1
        decision = scope.authorize(domain)
        if not decision.allowed:
            if stats is not None:
                stats["resolved_discovered_failures"] = stats.get("resolved_discovered_failures", 0) + 1
            print(gate_line(domain, decision.reason, "not persisted"))
            return
        address_decision = scope.authorize_resolved_address(ip)
        if not address_decision.allowed:
            if stats is not None:
                stats["resolved_discovered_failures"] = stats.get("resolved_discovered_failures", 0) + 1
            print(gate_line(ip, address_decision.reason, "not persisted"))
            return
        domain_node = Node(type="domain", value=domain)
        ip_node = Node(type="ip", value=ip)
        await storage.save_node(domain_node)
        await storage.save_node(ip_node)
        relationship = Relationship(from_id=domain_node.id, to_id=ip_node.id, type="RESOLVES_TO")
        await storage.save_relationship(relationship)
        await record_asset("resolved_discovered_addresses", domain_node.id, relationship.id, source_plugin, event_scan_run_id)
        display_bounded("discovered DNS success", status_line(f"SAVED: {domain} --RESOLVES_TO--> {ip}", "ok"))

    async def _discovered_dns_error(kind, data, source_plugin, scan_target, event_scan_run_id, event) -> None:
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

    async def _http_probe(kind, data, source_plugin, scan_target, event_scan_run_id, event) -> None:
        final_url = _canonical_url(data["final_url"])
        host = HttpURL(final_url).host

        decision = scope.authorize(host, _effective_port(final_url))

        if not decision.allowed:
            print(gate_line(host, decision.reason, f"{final_url} not persisted"))
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
                "cookies": data.get("cookies", []),
                "security_headers": data.get("security_headers", {}),
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

    async def _url_history_batch(kind, data, source_plugin, scan_target, event_scan_run_id, event) -> None:
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
            decision = scope.authorize(host, _effective_port(historical_url))
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

    async def _url_history_found(kind, data, source_plugin, scan_target, event_scan_run_id, event) -> None:
        raw_url = data.get("url", "")
        try:
            historical_url = _canonical_url(raw_url)
            host = HttpURL(historical_url).host
        except Exception:
            print(status_line(f"FAILED url_history_found: invalid URL {raw_url!r}", "error"))
            return
        decision = scope.authorize(host, _effective_port(historical_url))
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
            print(gate_line(host, decision.reason, f"{historical_url} not persisted"))
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

    async def _url_history_truncated(kind, data, source_plugin, scan_target, event_scan_run_id, event) -> None:
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

    async def _javascript_secret_like_pattern(kind, data, source_plugin, scan_target, event_scan_run_id, event) -> None:
        display_bounded(
            "JavaScript secret-like observations",
            status_line(
                f"OBSERVED JavaScript pattern: {data.get('pattern', data.get('value', 'unknown'))} "
                "(not validated or persisted as a secret)",
            ),
        )

    async def _javascript_reference(kind, data, source_plugin, scan_target, event_scan_run_id, event) -> None:
        raw_url = data.get("value")
        if not raw_url:
            return
        try:
            reference_url = _canonical_url(raw_url)
            host = HttpURL(reference_url).host
        except Exception:
            return
        decision = scope.authorize(host, _effective_port(reference_url))
        if not decision.allowed:
            display_bounded(
                "JavaScript scope denials",
                gate_line(host, decision.reason, f"{reference_url} not persisted"),
            )
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
        if reference_url not in javascript_displayed:
            javascript_displayed.add(reference_url)
            display_bounded(
                "JavaScript references",
                status_line(f"SAVED: {host} --JAVASCRIPT_REFERENCE--> {reference_url}", "ok"),
            )

    async def _http_fingerprint(kind, data, source_plugin, scan_target, event_scan_run_id, event) -> None:
        endpoint = _canonical_url(data["endpoint"])
        host = HttpURL(endpoint).host
        decision = scope.authorize(host, _effective_port(endpoint))
        if not decision.allowed:
            print(gate_line(host, decision.reason, "fingerprint not persisted"))
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

    async def _vhost_baseline(kind, data, source_plugin, scan_target, event_scan_run_id, event) -> None:
        display_bounded("vhost notices", status_line(f"baseline recorded for {data.get('endpoint', '-')}", "info"), limit=1)

    async def _vhost_rejected(kind, data, source_plugin, scan_target, event_scan_run_id, event) -> None:
        display_bounded("vhost rejections", gate_line(data.get("candidate", "-"), data.get("reason", "out of scope")))

    async def _vhost_observation(kind, data, source_plugin, scan_target, event_scan_run_id, event) -> None:
        candidate = data.get("candidate", "")
        endpoint = data.get("endpoint", "")
        endpoint_parts = HttpURL(endpoint) if endpoint else None
        # Record the origin that was actually contacted. Dropping the port
        # stored a URL that was never requested and that points at a
        # different service on the default port -- and the port has to be
        # known before the decision, because it is part of it.
        scheme = endpoint_parts.scheme if endpoint_parts else "https"
        port = _effective_port(endpoint) if endpoint else None
        decision = scope.authorize(candidate, port) if candidate and endpoint else None
        if decision is not None and not decision.allowed:
            display_bounded(
                "vhost scope denials",
                gate_line(candidate, decision.reason, f"{endpoint} not persisted"),
            )
        if decision is not None and decision.allowed:
            domain_node = Node(type="domain", value=candidate)
            candidate_url = probe_url(scheme, candidate, port or (443 if scheme == "https" else 80), "/")
            url_node = Node(type="url", value=candidate_url, attributes={
                "vhost_candidate": candidate,
                "probe_endpoint": endpoint,
                "status": data.get("status"),
                "classification": data.get("classification", "candidate_observation"),
            })
            await storage.save_node(domain_node)
            await storage.save_node(url_node)
            relationship = Relationship(
                from_id=domain_node.id,
                to_id=url_node.id,
                type="VHOST_SERVES",
                attributes={"classification": data.get("classification", "candidate_observation")},
            )
            await storage.save_relationship(relationship)
            await record_asset("vhost_observations", url_node.id, relationship.id, source_plugin, event_scan_run_id)
        notable = data.get("classification", "candidate_observation") == "candidate_observation"
        display_bounded(
            "vhost observations",
            observation_line(
                "VHOST" if notable else "vhost",
                data.get("candidate", "-"),
                data.get("status"),
                "responds differently to this name" if notable else "same as the default host",
                notable=notable,
            ),
        )

    async def _vhost_error(kind, data, source_plugin, scan_target, event_scan_run_id, event) -> None:
        display_bounded("vhost failures", status_line(f"FAILED vhost {data.get('candidate', '-')}: {data.get('error', 'unknown error')}", "error"))

    async def _vhost_budget_denied(kind, data, source_plugin, scan_target, event_scan_run_id, event) -> None:
        display_bounded(
            "vhost budget denials",
            status_line(
                f"BUDGET DENY vhost {data.get('candidate', '-')} -> "
                f"{data.get('reason', 'request budget exhausted')}",
                "deny",
            ),
        )

    async def _discovered_http_truncated(kind, data, source_plugin, scan_target, event_scan_run_id, event) -> None:
        not_reached = data.get("not_reached", 0)
        if stats is not None:
            stats["http_not_reached"] = not_reached
        print(status_line(
            f"INCOMPLETE discovered-http reached {data.get('reached', 0)} of "
            f"{data.get('total', 0)} host(s) before its deadline; "
            f"{not_reached} were not contacted",
            "error",
        ))

    async def _directory_truncated(kind, data, source_plugin, scan_target, event_scan_run_id, event) -> None:
        not_swept = data.get("not_swept", 0)
        if stats is not None:
            stats["directory_not_swept"] = not_swept
        print(status_line(
            f"INCOMPLETE directory-discovery swept {data.get('swept', 0)} of "
            f"{data.get('total', 0)} candidate(s) before its deadline; "
            f"{not_swept} were not probed",
            "error",
        ))

    async def _vhost_partial(kind, data, source_plugin, scan_target, event_scan_run_id, event) -> None:
        display_bounded("vhost notices", status_line(f"vhost stage retained {data.get('captured', 0)} partial observations", "info"), limit=1)

    async def _directory_observation(kind, data, source_plugin, scan_target, event_scan_run_id, event) -> None:
        url = data.get("url", "")
        parsed = HttpURL(url)
        decision = scope.authorize(parsed.host or "", _effective_port(url))
        if not decision.allowed:
            # This returned silently. A refusal that leaves no trace in the
            # output is indistinguishable from a path that was never probed,
            # which is the one thing an auditable tool must not do.
            display_bounded(
                "directory scope denials",
                gate_line(parsed.host or url, decision.reason, f"{url} not persisted"),
            )
            return
        # A path that matched the server's not-found response is a
        # negative result. It stays in evidence, where the record of what
        # was probed belongs, but it is not inventory.
        if data.get("classification") == "not_found_match":
            display_bounded(
                "directory not-found results",
                observation_line(
                    "path",
                    data.get("path", url),
                    data.get("status"),
                    "matches this server's not-found response",
                    notable=False,
                ),
            )
            return
        node = Node(type="url", value=url, attributes={"status": data.get("status"), "classification": data.get("classification", "candidate_observation")})
        await storage.save_node(node)
        # Anchor the edge at the origin that was actually swept. This was a
        # hardcoded `https://<target>/`, so a sweep of http://host:8081/ wrote
        # a root URL that had never been contacted -- and, once ports are part
        # of the persistence check, one this very scope denies: port 443 under
        # `ports: [8081]`. Deriving it from the observation keeps the root
        # authorized by construction.
        root_port = _effective_port(url) or (443 if parsed.scheme == "https" else 80)
        root = Node(type="url", value=probe_url(
            parsed.scheme or "https",
            parsed.host or scope.normalize_target(scan_target),
            root_port,
            "/",
        ))
        await storage.save_node(root)
        relationship = Relationship(root.id, node.id, "DIRECTORY_OBSERVATION")
        await storage.save_relationship(relationship)
        await record_asset("directory_observations", node.id, relationship.id, source_plugin, event_scan_run_id)
        display_bounded(
            "directory observations",
            observation_line(
                "PATH",
                data.get("path", url),
                data.get("status"),
                "distinct response",
                notable=True,
            ),
        )

    async def _directory_error(kind, data, source_plugin, scan_target, event_scan_run_id, event) -> None:
        display_bounded("directory failures", status_line(f"FAILED path {data.get('url', '-')}: {data.get('error', 'unknown error')}", "error"))

    async def _directory_rejected(kind, data, source_plugin, scan_target, event_scan_run_id, event) -> None:
        display_bounded("directory rejections", gate_line(data.get("path", "-"), data.get("reason", "rejected")))

    async def _directory_budget_denied(kind, data, source_plugin, scan_target, event_scan_run_id, event) -> None:
        display_bounded("directory budget denials", status_line(f"BUDGET DENY path {data.get('path', '-')} -> {data.get('reason', 'budget exhausted')}", "deny"))

    async def _directory_baseline(kind, data, source_plugin, scan_target, event_scan_run_id, event) -> None:
        display_bounded("directory notices", status_line(f"baseline recorded for {data.get('endpoint', '-')}", "info"), limit=1)

    async def _subdomain_found(kind, data, source_plugin, scan_target, event_scan_run_id, event) -> None:
        hostname = data["hostname"]
        root_domain = data["domain"]

        # Both ends of the edge are plugin-supplied, and adapter output is
        # untrusted. Authorize the parent before it is persisted: an
        # unauthorized root must never enter the graph, nor anchor an edge.
        root_decision = scope.authorize(root_domain)
        if not root_decision.allowed:
            print(gate_line(root_domain, root_decision.reason, f"parent of {hostname}; not persisted"))
            return

        root_node = Node(type="domain", value=root_domain)
        await storage.save_node(root_node)

        decision = scope.authorize(hostname)

        if not decision.allowed:
            print(gate_line(hostname, decision.reason, "not persisted"))
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

    async def _ct_provider_status(kind, data, source_plugin, scan_target, event_scan_run_id, event) -> None:
        # CTPlugin prints one compact provider table. The event remains
        # durable evidence, but does not add duplicate console output.
        return

    async def _adapter_execution(kind, data, source_plugin, scan_target, event_scan_run_id, event) -> None:
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

    async def _ct_rate_limited(kind, data, source_plugin, scan_target, event_scan_run_id, event) -> None:
        source = data.get("source") or source_plugin or "unknown"
        retry_after = data.get("retry_after")

        if retry_after is not None:
            print(status_line(f"CT RATE LIMITED: {source} (Retry-After: {retry_after}s)", "error"))
        else:
            print(status_line(f"CT RATE LIMITED: {source}", "error"))

    async def _javascript_bundle_error(kind, data, source_plugin, scan_target, event_scan_run_id, event) -> None:
        display_bounded(
            "JavaScript bundle failures",
            status_line(
                f"FAILED javascript bundle {data.get('url', 'unknown')}: "
                f"{data.get('error', 'unknown error')}",
                "error",
            ),
        )

    async def _http_error(kind, data, source_plugin, scan_target, event_scan_run_id, event) -> None:
        phase = data.get("phase")
        suffix = f" [{phase}]" if phase else ""
        error = data.get("error") or "unknown error"
        message = status_line(f"FAILED {kind}{suffix}: {error}", "error")
        if source_plugin == "discovered-http":
            display_bounded("discovered HTTP failure", message)
        else:
            print(message)

    async def _unhandled(kind, data, source_plugin, scan_target, event_scan_run_id, event) -> None:
        print(status_line(f"(no handler yet for discovery kind={kind!r})", "error"))

    # One function per discovery kind. A new kind is added by writing a
    # function and registering it here, rather than by extending a chain.
    _BY_KIND = {
        "dns_resolution": _dns_resolution,
        "discovered_dns_resolution": _discovered_dns_resolution,
        "discovered_dns_error": _discovered_dns_error,
        "http_probe": _http_probe,
        "url_history_batch": _url_history_batch,
        "url_history_found": _url_history_found,
        "url_history_truncated": _url_history_truncated,
        "javascript_secret_like_pattern": _javascript_secret_like_pattern,
        "http_fingerprint": _http_fingerprint,
        "vhost_baseline": _vhost_baseline,
        "vhost_rejected": _vhost_rejected,
        "vhost_observation": _vhost_observation,
        "vhost_error": _vhost_error,
        "vhost_budget_denied": _vhost_budget_denied,
        "discovered_http_truncated": _discovered_http_truncated,
        "vhost_partial": _vhost_partial,
        "directory_observation": _directory_observation,
        "directory_error": _directory_error,
        "directory_rejected": _directory_rejected,
        "directory_budget_denied": _directory_budget_denied,
        "directory_baseline": _directory_baseline,
        "directory_truncated": _directory_truncated,
        "subdomain_found": _subdomain_found,
        "ct_provider_status": _ct_provider_status,
        "adapter_execution": _adapter_execution,
        "ct_rate_limited": _ct_rate_limited,
        "javascript_bundle_error": _javascript_bundle_error,
        "http_error": _http_error,
        "dns_error": _http_error,
        "ct_error": _http_error,
    }

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
        handler = _BY_KIND.get(kind)
        if handler is None and kind.startswith("javascript_"):
            # The javascript_* family shares one reference handler, except for
            # the two kinds registered above.
            handler = _javascript_reference
        await (handler or _unhandled)(
            kind, data, source_plugin, scan_target, event_scan_run_id, event
        )
    return handle_discovery
