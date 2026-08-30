from __future__ import annotations

from uuid import uuid4

from sh4q.storage.evidence import Evidence, EvidenceStore


async def persist_stage_metrics(
    evidence_store: EvidenceStore,
    *,
    target: str,
    durations: dict[str, float],
    outcomes: dict[str, dict],
    scan_run_id: str | None,
) -> Evidence:
    stages = []
    for name, duration in durations.items():
        stages.append({
            "name": name,
            "duration_seconds": duration,
            **outcomes.get(name, {"status": "unknown", "attempts": 0, "discoveries": 0}),
        })
    evidence = Evidence(
        id=uuid4().hex,
        target=target,
        plugin="sh4q",
        kind="stage_metrics",
        content={"stages": stages},
        scan_run_id=scan_run_id,
    )
    await evidence_store.append(evidence)
    return evidence
