

import os
import shutil
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from sh4q.config import Sh4qConfig, load_config
from sh4q.events import EventBus
from sh4q.events.event_log import DurableEventLog
from sh4q.handlers import make_discovery_handler
from sh4q.network import RequestLimiter
from sh4q.plugins.ct_plugin import CTPlugin
from sh4q.plugins.discovered_dns_plugin import DiscoveredDNSPlugin
from sh4q.plugins.discovered_http_plugin import DiscoveredHTTPPlugin
from sh4q.plugins.dns_plugin import DNSPlugin
from sh4q.plugins.http_plugin import HTTPPlugin
from sh4q.scheduler import Scheduler
from sh4q.scope import ScopeEngine
from sh4q.storage import SQLiteStorage
from sh4q.storage.evidence import SQLiteEvidenceStore
from sh4q.storage.scan_runs import create_scan, finish_scan
from sh4q.storage.scan_assets import SQLiteScanAssetStore
from sh4q.storage.db import ensure_schema_version
from sh4q.application.request_metrics import persist_request_metrics
from sh4q.application.stage_metrics import persist_stage_metrics
from sh4q.adapters import (
    AdapterContext,
    AdapterExecutionError,
    ControlledProcessRunner,
    ExternalAdapterPlugin,
    HttpxFingerprintPlugin,
    SubfinderAdapter,
    validate_projectdiscovery_httpx,
)


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


def _default_config(target: str) -> Sh4qConfig:
    return Sh4qConfig(**{
        "scope": {"targets": [target], "ports": [80, 443]},
    })


async def run_scan(
    target: str,
    config_path: str | None = None,
    *,
    include_subfinder: bool = False,
    include_httpx: bool = False,
) -> ScanSummary:
    start = time.monotonic()
    scan_started_at = datetime.now(timezone.utc).isoformat()

    config = load_config(config_path) if config_path else _default_config(target)
    os.makedirs(config.output.directory, exist_ok=True)
    db_path = os.path.join(config.output.directory, "sh4q.db")
    ensure_schema_version(db_path)

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
        plugins = [DNSPlugin(), HTTPPlugin(scope, limiter=limiter), CTPlugin(limiter=limiter)]
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
                        {executable}, environment={"HOME": str(adapter_home.resolve())}
                    ),
                )
            )
            plugins.append(DiscoveredDNSPlugin(scope=scope))
            plugins.append(DiscoveredHTTPPlugin(scope=scope, limiter=limiter))
        if include_httpx:
            executable = shutil.which("httpx")
            if executable is None:
                raise AdapterExecutionError("httpx is not installed or is not available on PATH")
            adapter_home = Path(config.output.directory) / "adapters" / "httpx-home"
            adapter_home.mkdir(parents=True, exist_ok=True)
            runner = ControlledProcessRunner(
                {executable}, environment={"HOME": str(adapter_home.resolve())}
            )
            await validate_projectdiscovery_httpx(
                executable, runner, cwd=Path(config.output.directory)
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
        )
        decision = await scheduler.run(target)
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
