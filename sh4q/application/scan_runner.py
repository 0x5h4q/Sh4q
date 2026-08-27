

import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from sh4q.config import Sh4qConfig, load_config
from sh4q.events import EventBus
from sh4q.events.event_log import DurableEventLog
from sh4q.handlers import make_discovery_handler
from sh4q.network import RequestLimiter
from sh4q.plugins.ct_plugin import CTPlugin
from sh4q.plugins.dns_plugin import DNSPlugin
from sh4q.plugins.http_plugin import HTTPPlugin
from sh4q.scheduler import Scheduler
from sh4q.scope import ScopeEngine
from sh4q.storage import SQLiteStorage
from sh4q.storage.evidence import SQLiteEvidenceStore
from sh4q.application.request_metrics import persist_request_metrics
from sh4q.adapters import (
    AdapterContext,
    AdapterExecutionError,
    ControlledProcessRunner,
    ExternalAdapterPlugin,
    SubfinderAdapter,
)


@dataclass
class ScanSummary:
    target: str
    scope_allowed: bool
    scope_reason: str
    discoveries: int
    dns_addresses: int
    http_endpoints: int
    ct_names: int
    adapter_names: int
    relationships: int
    evidence: int
    recovered_events: int
    duration_seconds: float
    database_path: str
    requests_admitted: int
    requests_denied: int
    requests_completed: int
    requests_failed: int
    peak_request_concurrency: int


def _default_config(target: str) -> Sh4qConfig:
    return Sh4qConfig(**{
        "scope": {"targets": [target], "ports": [80, 443]},
    })


async def run_scan(
    target: str,
    config_path: str | None = None,
    *,
    include_subfinder: bool = False,
) -> ScanSummary:
    start = time.monotonic()

    config = load_config(config_path) if config_path else _default_config(target)
    os.makedirs(config.output.directory, exist_ok=True)
    db_path = os.path.join(config.output.directory, "sh4q.db")

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

    bus = EventBus(event_log=event_log)

    stats: dict = {
        "relationships": 0,
        "dns_addresses": 0,
        "http_endpoints": 0,
        "ct_names": 0,
        "adapter_names": 0,
    }

    bus.subscribe("discovery", make_discovery_handler(scope, storage, evidence_store, stats=stats))
    recovered = await bus.recover()

    bus.start()

    outcome = "completed"
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
        scheduler = Scheduler(
            plugins=plugins,
            scope=scope,
            bus=bus,
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
        )

    evidence_records = await evidence_store.list_for_target(target)

    return ScanSummary(
        target=target,
        scope_allowed=decision.allowed,
        scope_reason=decision.reason,
        discoveries=(
            stats["dns_addresses"]
            + stats["http_endpoints"]
            + stats["ct_names"]
            + stats["adapter_names"]
        ),
        dns_addresses=stats["dns_addresses"],
        http_endpoints=stats["http_endpoints"],
        ct_names=stats["ct_names"],
        adapter_names=stats["adapter_names"],
        relationships=stats["relationships"],
        evidence=len(evidence_records),
        recovered_events=recovered,
        duration_seconds=time.monotonic() - start,
        database_path=db_path,
        requests_admitted=request_metrics.admitted,
        requests_denied=request_metrics.denied,
        requests_completed=request_metrics.completed,
        requests_failed=request_metrics.failed,
        peak_request_concurrency=request_metrics.peak_concurrency,
    )
