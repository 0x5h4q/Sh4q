from __future__ import annotations

from uuid import uuid4

from sh4q.config.schema import RateLimitConfig
from sh4q.network import LimiterMetrics
from sh4q.storage.evidence import Evidence, EvidenceStore


async def persist_request_metrics(
    evidence_store: EvidenceStore,
    *,
    target: str,
    limits: RateLimitConfig,
    metrics: LimiterMetrics,
    duration_seconds: float,
    outcome: str,
) -> Evidence:
    evidence = Evidence(
        id=uuid4().hex,
        target=target,
        plugin="sh4q",
        kind="request_metrics",
        content={
            "outcome": outcome,
            "duration_seconds": round(duration_seconds, 3),
            "configured": {
                "max_concurrent": limits.max_concurrent,
                "requests_per_second": limits.requests_per_second,
                "budget": limits.budget,
            },
            "observed": {
                "admitted": metrics.admitted,
                "budget_denied": metrics.denied,
                "completed": metrics.completed,
                "failed": metrics.failed,
                "active_at_capture": metrics.active,
                "peak_concurrency": metrics.peak_concurrency,
            },
        },
    )
    await evidence_store.append(evidence)
    return evidence
