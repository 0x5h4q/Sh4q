"""What a scan told third parties about the target.

Detection export answers "what would a defender see?". This answers the
other half: "what did your tool tell other people about my engagement?" --
a question a client or a bug-bounty programme actually asks, and one sh4q
could not answer at all.

It reads durable evidence rather than adding instrumentation, because the
record already exists: `ct_provider_status` names every CT service
contacted, `adapter_execution` names every external tool run, and the
resolution events name every hostname the system resolver was asked about.
Reading means it also works on scans already recorded, so "what did last
week's scan disclose?" is answerable today. The network layer stays
unaware of events, which is the existing dependency direction.

Two fidelity tiers, because sh4q cannot honestly claim more:

- observed: sh4q made the call itself through TrustedServiceHTTPClient, so
  the service and the subject are known.
- declared: an external tool made calls sh4q never saw. Only what the tool
  is documented to contact can be stated, and that is version-dependent.

The resolver is included deliberately. By volume it is the largest
disclosure a scan makes -- one lookup per name -- and it is the one an
engagement is most likely to ask about.
"""

import asyncio
import json
import os
import tempfile

from sh4q.application.disclosure import (
    DECLARED,
    OBSERVED,
    planned_disclosures,
    summarize_disclosures,
)
from sh4q.storage.evidence import Evidence, SQLiteEvidenceStore

SCAN = "scan-1"
TARGET = "example.com"


def evidence(kind, content, plugin, eid):
    return Evidence(
        id=eid, target=TARGET, plugin=plugin, kind=kind,
        content=content, scan_run_id=SCAN,
    )


async def main() -> None:
    handle, db_path = tempfile.mkstemp(prefix="sh4q_disclosure_", suffix=".db")
    os.close(handle)
    os.remove(db_path)
    try:
        store = SQLiteEvidenceStore(db_path)
        await store.init()

        records = [
            # Two CT services answered; one failed but was still contacted.
            evidence("ct_provider_status", {"source": "certspotter", "status": "success", "names": 176}, "ct", "e1"),
            evidence("ct_provider_status", {"source": "crt.sh", "status": "degraded", "names": 0}, "ct", "e2"),
            evidence("ct_provider_status", {"source": "crt.name", "status": "success", "names": 1750}, "ct", "e3"),
            # Two external tools ran.
            evidence("adapter_execution", {"adapter": "subfinder", "returncode": 0}, "subfinder", "e4"),
            evidence("adapter_execution", {"adapter": "url-history", "returncode": 0}, "url-history", "e5"),
            # One tool that contacts only the target, not a third party.
            evidence("adapter_execution", {"adapter": "httpx-fingerprint", "returncode": 0}, "httpx-fingerprint", "e6"),
            # The resolver was asked about three distinct names, several answers each.
            evidence("dns_resolution", {"domain": TARGET, "ip": "1.1.1.1"}, "dns", "e7"),
            evidence("dns_resolution", {"domain": TARGET, "ip": "1.0.0.1"}, "dns", "e8"),
            evidence("discovered_dns_resolution", {"domain": f"api.{TARGET}", "ip": "1.1.1.1"}, "discovered-dns", "e9"),
            evidence("discovered_dns_error", {"domain": f"gone.{TARGET}", "error": "no A answer"}, "discovered-dns", "e10"),
        ]
        for record in records:
            await store.append(record)

        ledger = summarize_disclosures(db_path, scan_id=SCAN)
        by_service = {d.service: d for d in ledger.disclosures}

        # --- observed: sh4q's own calls ----------------------------------
        assert by_service["api.certspotter.com"].fidelity == OBSERVED
        assert by_service["crt.sh"].fidelity == OBSERVED
        assert by_service["crt.name"].fidelity == OBSERVED
        assert by_service["crt.sh"].subjects == 1, (
            "a provider that failed was still told the target"
        )

        # --- declared: what a subprocess is documented to contact --------
        archive = by_service["web.archive.org"]
        assert archive.fidelity == DECLARED
        assert archive.via == "url-history"
        subfinder = next(d for d in ledger.disclosures if d.via == "subfinder")
        assert subfinder.fidelity == DECLARED
        assert "version" in subfinder.detail.lower(), (
            "a tool's real source list is version-dependent and must say so"
        )

        # --- a tool that only contacts the target is not a disclosure ----
        assert not any(d.via == "httpx-fingerprint" for d in ledger.disclosures), (
            "httpx contacts the scan's own endpoints, not a third party"
        )

        # --- the resolver, counted by distinct name ----------------------
        resolver = by_service["system resolver"]
        assert resolver.fidelity == OBSERVED
        assert resolver.subjects == 3, (
            f"three distinct names were looked up, not the event count: {resolver.subjects}"
        )

        assert ledger.scan_id == SCAN
        assert len(ledger.observed) == 4 and len(ledger.declared) == 2, (
            [(d.service, d.fidelity) for d in ledger.disclosures]
        )

        # --- a scan that disclosed nothing says so -----------------------
        empty = summarize_disclosures(db_path, scan_id="absent")
        assert empty.disclosures == (), empty.disclosures

        # --- the report is machine readable ------------------------------
        lines = [json.loads(line) for line in ledger.to_jsonl().splitlines()]
        assert len(lines) == len(ledger.disclosures)
        assert {"scan_id", "target", "service", "fidelity", "via", "subjects", "detail"} <= set(lines[0])

        print("disclosure ledger test passed")
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


asyncio.run(main())


# --- the pre-scan declaration ----------------------------------------------
# Printed, never prompted: the same tool runs under --progress jsonl and from
# a scheduled job, and a blocking "continue?" would hang them.
planned = planned_disclosures(
    ct_sources=("certspotter", "crt.sh"),
    adapters=("subfinder", "url-history"),
    resolves_names=True,
)
services = {d.service for d in planned}
assert {"api.certspotter.com", "crt.sh", "web.archive.org", "system resolver"} <= services, services
assert all(d.subjects == 0 for d in planned), "nothing has been disclosed yet"

# A scan with no CT and no adapters still tells the resolver.
minimal = {d.service for d in planned_disclosures(ct_sources=(), adapters=(), resolves_names=True)}
assert minimal == {"system resolver"}, minimal

# And one that resolves nothing discloses to nobody.
assert planned_disclosures(ct_sources=(), adapters=(), resolves_names=False) == ()

print("pre-scan disclosure declaration test passed")
