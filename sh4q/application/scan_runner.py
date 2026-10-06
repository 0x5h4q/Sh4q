

import shutil
import os
import textwrap
import time
import httpx
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from sh4q.cli.branding import status_line
from sh4q.config import Sh4qConfig, load_config
from sh4q.events import EventBus
from sh4q.events.event_log import DurableEventLog
from sh4q.handlers import make_discovery_handler
from sh4q.network import RequestLimiter, ScopedHTTPClient, primary_probe_target
from sh4q.plugins.ct_plugin import CTPlugin
from sh4q.plugins.discovered_dns_plugin import DiscoveredDNSPlugin, load_host_names
from sh4q.plugins.discovered_http_plugin import DiscoveredHTTPPlugin
from sh4q.plugins.dns_plugin import DNSPlugin
from sh4q.plugins.http_plugin import HTTPPlugin
from sh4q.plugins.javascript_extraction_plugin import JavaScriptExtractionPlugin
from sh4q.plugins.javascript_bundle_plugin import JavaScriptBundlePlugin
from sh4q.plugins import VhostDiscoveryPlugin, DirectoryDiscoveryPlugin
from sh4q.javascript_extraction import JavaScriptExtractionLimits
from sh4q.scheduler import Scheduler
from sh4q.scope import ScopeEngine
from sh4q.storage import SQLiteStorage
from sh4q.storage.evidence import SQLiteEvidenceStore
from sh4q.storage.scan_runs import create_scan, finish_scan
from sh4q.storage.scan_assets import SQLiteScanAssetStore
from sh4q.storage.db import open_sync_database
from sh4q.storage.db import ensure_schema_version
from sh4q.application.disclosure import planned_disclosures
from sh4q.application.request_metrics import persist_request_metrics
from sh4q.application.stage_metrics import persist_stage_metrics
from sh4q.adapters import (
    AdapterContext,
    AdapterExecutionError,
    ControlledProcessRunner,
    ExternalAdapterPlugin,
    HttpxFingerprintPlugin,
    SubfinderAdapter,
    URLHistoryAdapter,
    KatanaAdapter,
    validate_projectdiscovery_httpx,
)
from sh4q.dependencies import format_missing, missing_dependencies


@dataclass
class ScanSummary:
    scan_run_id: str
    target: str
    scope_allowed: bool
    scope_reason: str
    discoveries: int
    dns_addresses: int
    http_endpoints: int
    ct_names: int
    adapter_names: int
    resolved_discovered_addresses: int
    resolved_discovered_attempted: int
    resolved_discovered_failures: int
    technologies: int
    dns_failure_reasons: dict[str, int]
    relationships: int
    evidence: int
    evidence_this_scan: int
    recovered_events: int
    duration_seconds: float
    database_path: str
    requests_admitted: int
    requests_denied: int
    requests_completed: int
    requests_failed: int
    peak_request_concurrency: int
    stage_durations: dict[str, float]
    historical_urls: int = 0
    historical_urls_rejected: int = 0
    historical_urls_truncated: int = 0


def javascript_http_observations(evidence: list) -> list[dict]:
    """Return HTML samples from every HTTP host in the current scan."""
    return [
        {
            "endpoint": item.content.get("final_url"),
            "content": item.content.get("html_sample", ""),
        }
        for item in evidence
        if item.content.get("html_sample")
    ]


def _default_config(target: str) -> Sh4qConfig:
    return Sh4qConfig(**{
        "scope": {"targets": [target], "ports": [80, 443]},
    })


def _secure_output_paths(directory: str, database: str) -> None:
    os.makedirs(directory, mode=0o700, exist_ok=True)
    try:
        os.chmod(directory, 0o700)
        os.chmod(database, 0o600)
    except OSError as error:
        raise AdapterExecutionError(
            f"unable to secure output/database permissions: {error}"
        ) from error


async def run_scan(
    target: str,
    config_path: str | None = None,
    *,
    include_subfinder: bool = False,
    include_resolve: bool = False,
    hosts_file: str | None = None,
    include_httpx: bool = False,
    include_url_history: bool = False,
    include_javascript: bool = False,
    include_javascript_bundles: bool = False,
    include_katana: bool = False,
    include_vhosts: bool = False,
    vhosts_file: str | None = None,
    vhosts_scan_id: str | None = None,
    include_directories: bool = False,
    directories_file: str | None = None,
    progress_callback=None,
) -> ScanSummary:
    start = time.monotonic()
    scan_started_at = datetime.now(timezone.utc).isoformat()

    config = load_config(config_path) if config_path else _default_config(target)
    if config.scope.allow_private_addresses:
        print(
            "  WARNING: private/reserved address access is enabled; "
            "use only in an authorised lab scope."
        )
    if include_vhosts:
        if vhosts_file and vhosts_scan_id:
            raise AdapterExecutionError("--vhosts-file and --vhosts-from-scan cannot be combined")
        if vhosts_file:
            candidate_path = Path(vhosts_file).expanduser()
            if not candidate_path.is_file():
                raise AdapterExecutionError(f"vhost candidate file not found: {candidate_path}")
            vhosts_file = str(candidate_path)
    if include_directories and not directories_file:
        raise AdapterExecutionError("--directories requires --directories-file")
    supplied_hosts: tuple[str, ...] = ()
    if hosts_file:
        try:
            loaded_hosts = load_host_names(hosts_file)
        except ValueError as error:
            raise AdapterExecutionError(str(error)) from error
        supplied_hosts = loaded_hosts.accepted
        print(
            f"  HOSTS    {len(supplied_hosts)} name(s) from {hosts_file}"
            + (f"; {len(loaded_hosts.rejected)} rejected" if loaded_hosts.rejected else "")
            + (f"; {loaded_hosts.duplicates} duplicate(s)" if loaded_hosts.duplicates else "")
        )
    missing = missing_dependencies(
        subfinder=include_subfinder,
        httpx=include_httpx,
        url_history=include_url_history,
        katana=include_katana,
    )
    if missing:
        raise AdapterExecutionError(format_missing(missing))
    os.makedirs(config.output.directory, mode=0o700, exist_ok=True)
    db_path = os.path.join(config.output.directory, "sh4q.db")
    ensure_schema_version(db_path)
    _secure_output_paths(config.output.directory, db_path)

    scope = ScopeEngine(config)
    limiter = RequestLimiter(
        config.rate_limit.max_concurrent,
        config.rate_limit.requests_per_second,
        config.rate_limit.budget,
    )
    storage = SQLiteStorage(db_path)
    await storage.init()
    evidence_store = SQLiteEvidenceStore(db_path)
    await evidence_store.init()
    event_log = DurableEventLog(db_path)
    await event_log.init()
    scan_run = create_scan(db_path, target)
    scan_asset_store = SQLiteScanAssetStore(db_path)
    await scan_asset_store.init()

    bus = EventBus(event_log=event_log)

    stats: dict = {
        "relationships": 0,
        "dns_addresses": 0,
        "http_endpoints": 0,
        "ct_names": 0,
        "adapter_names": 0,
        "discoveries": 0,
        "resolved_discovered_addresses": 0,
        "resolved_discovered_attempted": 0,
        "resolved_discovered_failures": 0,
        "technologies": 0,
        "historical_urls": 0,
        "historical_urls_rejected": 0,
        "historical_urls_truncated": 0,
        "dns_failure_reasons": {},
    }

    bus.subscribe(
        "discovery",
        make_discovery_handler(
            scope,
            storage,
            evidence_store,
            stats=stats,
            scan_asset_store=scan_asset_store,
            scan_run_id=scan_run.id,
        ),
    )
    recovered = await bus.recover()

    bus.start()

    outcome = "completed"
    scheduler = None
    try:
        vhost_candidates = None
        if include_vhosts and vhosts_scan_id:
            with open_sync_database(db_path) as db:
                vhost_candidates = [row[0] for row in db.execute(
                    """SELECT DISTINCT n.value FROM scan_assets sa JOIN nodes n ON n.id = sa.asset_id
                    WHERE sa.scan_run_id = ? AND n.type = 'domain' ORDER BY n.value""",
                    (vhosts_scan_id,),
                ).fetchall()]
            if not vhost_candidates:
                raise AdapterExecutionError(f"no domain candidates found for scan {vhosts_scan_id}")
        include_html_sample = include_javascript or include_javascript_bundles
        plugins = [
            DNSPlugin(),
            HTTPPlugin(
                scope,
                limiter=limiter,
                include_html_sample=include_html_sample,
                timeout=config.timeout.http_seconds,
            ),
        ]
        plugins.append(CTPlugin(limiter=limiter, config=config))
        if include_subfinder:
            executable = shutil.which("subfinder")
            if executable is None:
                raise AdapterExecutionError(
                    "Subfinder is not installed or is not available on PATH"
                )
            adapter = SubfinderAdapter(executable=executable)
            adapter_home = Path(config.output.directory) / "adapters" / "subfinder-home"
            adapter_home.mkdir(parents=True, exist_ok=True)
            plugins.append(
                ExternalAdapterPlugin(
                    adapter,
                    AdapterContext(scope, Path(config.output.directory)),
                    ControlledProcessRunner(
                        {executable},
                        max_output_bytes=4_000_000,
                        environment={"HOME": str(adapter_home.resolve())},
                    ),
                )
            )
        # Both stages sweep a single origin rather than every authorized port,
        # so a candidate list is not multiplied by the port count. HTTPS is
        # preferred when authorized, keeping default 80/443 behaviour.
        sweep_scheme, sweep_port = primary_probe_target(scope.authorized_ports)
        if include_vhosts:
            plugins.append(VhostDiscoveryPlugin(
                scope, vhosts_file, candidates=vhost_candidates, limiter=limiter,
                endpoint_scheme=sweep_scheme, endpoint_port=sweep_port,
            ))
        if include_directories:
            plugins.append(DirectoryDiscoveryPlugin(
                scope, directories_file, limiter=limiter,
                endpoint_scheme=sweep_scheme, endpoint_port=sweep_port,
            ))
        if include_url_history:
            executable = shutil.which("waybackurls")
            if executable is None:
                raise AdapterExecutionError(
                    "waybackurls is not installed or is not available on PATH"
                )
            adapter_home = Path(config.output.directory) / "adapters" / "waybackurls-home"
            adapter_home.mkdir(parents=True, exist_ok=True)
            plugins.append(
                ExternalAdapterPlugin(
                    URLHistoryAdapter(executable=executable),
                    AdapterContext(scope, Path(config.output.directory)),
                    ControlledProcessRunner(
                        {executable},
                        max_output_bytes=16_000_000,
                        environment={"HOME": str(adapter_home.resolve())},
                    ),
                    timeout=60.0,
                )
            )
        if include_katana:
            executable = shutil.which("katana")
            if executable is None:
                raise AdapterExecutionError("Katana is not installed or is not available on PATH")
            adapter_home = Path(config.output.directory) / "adapters" / "katana-home"
            adapter_home.mkdir(parents=True, exist_ok=True)
            plugins.append(
                ExternalAdapterPlugin(
                    KatanaAdapter(executable=executable),
                    AdapterContext(scope, Path(config.output.directory)),
                    ControlledProcessRunner(
                        {executable},
                        max_output_bytes=16_000_000,
                        environment={"HOME": str(adapter_home.resolve())},
                    ),
                    timeout=60.0,
                )
            )
        # Resolving discovered names is a large traffic increase, so it stays
        # opt-in rather than following automatically from certificate
        # transparency running by default. --sub implies it, since a subdomain
        # list nobody resolves is not what that flag is for.
        if include_subfinder or include_resolve or supplied_hosts:
            plugins.append(DiscoveredDNSPlugin(
                scope=scope, names=supplied_hosts,
                max_names=config.enrichment.max_names_resolved,
            ))
            plugins.append(DiscoveredHTTPPlugin(
                scope=scope,
                limiter=limiter,
                max_names=config.enrichment.max_hosts_probed,
                include_html_sample=include_html_sample,
                http_timeout=config.timeout.http_seconds,
            ))
        if include_javascript or include_javascript_bundles:
            async def http_observations(scan_target: str) -> list[dict]:
                evidence = await evidence_store.list_for_scan(scan_run.id, kind="http_probe")
                return javascript_http_observations(evidence)

            plugins.append(JavaScriptExtractionPlugin(http_observations, after_discovered_http=include_subfinder or include_resolve or bool(supplied_hosts)))
            if include_javascript_bundles:
                async def fetch_bundle(url: str) -> str | None:
                    parsed = httpx.URL(url)
                    default_port = 443 if parsed.scheme == "https" else 80
                    if not parsed.host or not scope.authorize(parsed.host, parsed.port or default_port).allowed:
                        return None
                    async with ScopedHTTPClient(
                        scope,
                        timeout=config.timeout.http_seconds,
                        limiter=limiter,
                    ) as client:
                        response, body, truncated = await client.get_text_bounded(
                            url, JavaScriptExtractionLimits().max_script_bytes
                        )
                        if response.status_code >= 400:
                            return None
                        content_type = response.headers.get("content-type", "").lower()
                        if content_type and not any(
                            marker in content_type
                            for marker in ("javascript", "ecmascript", "text/plain")
                        ):
                            return None
                        declared_length = response.headers.get("content-length")
                        if declared_length and declared_length.isdigit() and int(declared_length) > JavaScriptExtractionLimits().max_script_bytes:
                            return None
                        if truncated:
                            return None
                        return body

                plugins.append(
                    JavaScriptBundlePlugin(
                        http_observations,
                        fetch_bundle,
                        limits=JavaScriptExtractionLimits(),
                        # The stage deadline is derived from these, so it has
                        # to see the same rate and per-request timeout the
                        # fetches will actually run under.
                        limiter=limiter,
                        per_request_timeout=config.timeout.http_seconds,
                    )
                )
        if include_httpx:
            candidates = []
            for directory in os.environ.get("PATH", "").split(os.pathsep):
                candidate = Path(directory or ".") / "httpx"
                if candidate.is_file() and os.access(candidate, os.X_OK):
                    resolved = str(candidate.resolve())
                    if resolved not in candidates:
                        candidates.append(resolved)
            if not candidates:
                raise AdapterExecutionError("httpx is not installed or is not available on PATH")
            adapter_home = Path(config.output.directory) / "adapters" / "httpx-home"
            adapter_home.mkdir(parents=True, exist_ok=True)
            runner = ControlledProcessRunner(
                set(candidates), environment={"HOME": str(adapter_home.resolve())}
            )
            executable = None
            for candidate in candidates:
                try:
                    await validate_projectdiscovery_httpx(
                        candidate, runner, cwd=Path(config.output.directory)
                    )
                    executable = candidate
                    break
                except AdapterExecutionError:
                    continue
            if executable is None:
                raise AdapterExecutionError(
                    "--httpx requires the ProjectDiscovery httpx CLI; "
                    f"found no compatible executable among {', '.join(candidates)}"
                )
            plugins.append(
                HttpxFingerprintPlugin(
                    AdapterContext(scope, Path(config.output.directory)),
                    runner,
                    executable=executable,
                    max_endpoints=config.adapters.httpx.max_endpoints,
                    timeout=config.adapters.httpx.timeout_seconds,
                )
            )
        scheduler = Scheduler(
            plugins=plugins,
            scope=scope,
            bus=bus,
            scan_run_id=scan_run.id,
            progress_callback=progress_callback,
        )
        notices = []
        if include_subfinder or include_resolve or supplied_hosts:
            notices.append(status_line(
                f"ENRICH   up to {config.enrichment.max_names_resolved} name(s) to resolve "
                f"and {config.enrichment.max_hosts_probed} to probe, "
                f"at {config.rate_limit.requests_per_second:g} request(s)/second"
            ))
        # State who this scan will tell about the target before it tells them.
        # Printed, not prompted: the same command runs under --progress jsonl
        # and from a scheduled job, and a confirmation would hang both.
        planned = planned_disclosures(
            ct_sources=tuple(config.certificate_transparency.sources),
            adapters=tuple(
                name for name, enabled in (
                    ("subfinder", include_subfinder),
                    ("url-history", include_url_history),
                    ("katana", include_katana),
                    ("httpx-fingerprint", include_httpx),
                ) if enabled
            ),
            resolves_names=True,
        )
        if planned:
            services = list(dict.fromkeys(item.service for item in planned))
            # One 130-character line is not a declaration anyone reads. Count
            # them, then wrap, so the number registers before the list does.
            wrapped = textwrap.wrap(
                ", ".join(services), width=84,
                initial_indent="           ", subsequent_indent="           ",
            )
            notices.append(
                status_line(
                    f"DISCLOSE {len(services)} third part(ies) will learn this target:"
                )
                + "\n"
                + "\n".join(wrapped)
            )
        enrichment_notice = "\n".join(notices) if notices else None
        decision = await scheduler.run(target, before_stages=enrichment_notice)
        await bus.drain()
    except BaseException:
        outcome = "interrupted"
        raise
    finally:
        # On Ctrl+C, queued events remain PENDING and an interrupted active
        # event remains PROCESSING. Both are recoverable on the next scan.
        await bus.shutdown()
        request_metrics = await limiter.metrics()
        await persist_request_metrics(
            evidence_store,
            target=target,
            limits=config.rate_limit,
            metrics=request_metrics,
            duration_seconds=time.monotonic() - start,
            outcome=outcome,
            scan_run_id=scan_run.id,
        )
        if scheduler is not None:
            await persist_stage_metrics(
                evidence_store,
                target=target,
                durations=scheduler.stage_durations,
                outcomes=scheduler.stage_outcomes,
                scan_run_id=scan_run.id,
            )
        finish_scan(db_path, scan_run.id, "COMPLETED" if outcome == "completed" else "INTERRUPTED")

    evidence_records = await evidence_store.list_for_target(target)
    scan_evidence_records = await evidence_store.list_for_target(
        target, captured_after=scan_started_at
    )

    return ScanSummary(
        scan_run_id=scan_run.id,
        target=target,
        scope_allowed=decision.allowed,
        scope_reason=decision.reason,
        discoveries=stats["discoveries"],
        dns_addresses=stats["dns_addresses"],
        http_endpoints=stats["http_endpoints"],
        ct_names=stats["ct_names"],
        adapter_names=stats["adapter_names"],
        resolved_discovered_addresses=stats["resolved_discovered_addresses"],
        resolved_discovered_attempted=stats["resolved_discovered_attempted"],
        resolved_discovered_failures=stats["resolved_discovered_failures"],
        technologies=stats["technologies"],
        historical_urls=stats["historical_urls"],
        historical_urls_rejected=stats["historical_urls_rejected"],
        historical_urls_truncated=stats["historical_urls_truncated"],
        dns_failure_reasons=dict(stats["dns_failure_reasons"]),
        relationships=stats["relationships"],
        evidence=len(evidence_records),
        evidence_this_scan=len(scan_evidence_records),
        recovered_events=recovered,
        duration_seconds=time.monotonic() - start,
        database_path=db_path,
        requests_admitted=request_metrics.admitted,
        requests_denied=request_metrics.denied,
        requests_completed=request_metrics.completed,
        requests_failed=request_metrics.failed,
        peak_request_concurrency=request_metrics.peak_concurrency,
        stage_durations=scheduler.stage_durations,
    )
