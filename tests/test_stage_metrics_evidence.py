import asyncio

from sh4q.application.stage_metrics import persist_stage_metrics


class MemoryEvidenceStore:
    def __init__(self):
        self.records = []

    async def append(self, evidence):
        self.records.append(evidence)


async def main():
    store = MemoryEvidenceStore()
    evidence = await persist_stage_metrics(
        store,
        target="example.com",
        durations={"dns": 0.5, "http": 1.25},
        outcomes={
            "dns": {"status": "completed", "attempts": 1, "discoveries": 2},
            "http": {"status": "timeout_exhausted", "attempts": 3, "discoveries": 0},
        },
        scan_run_id="scan-1",
    )
    assert evidence.kind == "stage_metrics"
    assert evidence.scan_run_id == "scan-1"
    assert evidence.content["stages"][0]["name"] == "dns"
    assert evidence.content["stages"][1]["status"] == "timeout_exhausted"
    assert store.records == [evidence]
    print("stage metrics evidence test passed")


asyncio.run(main())
