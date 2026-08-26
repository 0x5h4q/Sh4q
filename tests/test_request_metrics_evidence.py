import asyncio
from sh4q.application.request_metrics import persist_request_metrics
from sh4q.config.schema import RateLimitConfig
from sh4q.network import LimiterMetrics


class MemoryEvidenceStore:
    def __init__(self):
        self.records = {}

    async def append(self, evidence):
        self.records[evidence.id] = evidence

    async def get(self, evidence_id):
        return self.records.get(evidence_id)

    async def list_for_target(self, target):
        return [record for record in self.records.values() if record.target == target]


async def main() -> None:
    store = MemoryEvidenceStore()
    metrics = LimiterMetrics(
            admitted=20,
            denied=1,
            completed=11,
            failed=9,
            active=0,
            peak_concurrency=2,
        )
    evidence = await persist_request_metrics(
        store,
        target="example.com",
        limits=RateLimitConfig(max_concurrent=3, requests_per_second=2, budget=1000),
        metrics=metrics,
        duration_seconds=46.5219,
        outcome="completed",
    )

    saved = await store.get(evidence.id)
    assert saved is not None
    assert saved.kind == "request_metrics"
    assert saved.plugin == "sh4q"
    assert saved.content["outcome"] == "completed"
    assert saved.content["duration_seconds"] == 46.522
    assert saved.content["configured"] == {
        "max_concurrent": 3,
        "requests_per_second": 2.0,
        "budget": 1000,
    }
    assert saved.content["observed"] == {
        "admitted": 20,
        "budget_denied": 1,
        "completed": 11,
        "failed": 9,
        "active_at_capture": 0,
        "peak_concurrency": 2,
    }
    print("request metrics evidence test passed")


asyncio.run(main())
