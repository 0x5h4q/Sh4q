"""What a scan told third parties about its target.

Detection export records what a defender would see. This records the other
half of the same accountability story: which external services learned which
domain an operator was interested in. sh4q could not previously answer that
at all, and it is a question a client or a bug-bounty programme asks.

Built as a reader over durable evidence rather than new instrumentation. The
record already exists -- `ct_provider_status` names every certificate
transparency service contacted, `adapter_execution` names every external tool
run, and the resolution events name every hostname looked up -- so reading it
also answers the question for scans already on disk. It keeps the network
layer unaware of the event bus, which is the existing dependency direction.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from sh4q.storage.db import open_sync_database

#: sh4q made the call itself, so the service and the subject are known.
OBSERVED = "observed"

#: An external process made calls sh4q never saw. Only what the tool is
#: documented to contact can be stated, and that is version-dependent.
DECLARED = "declared"

#: The host a certificate-transparency source is actually contacted on. The
#: config names sources; this maps them to what appears in network logs.
CT_SERVICE_HOSTS = {
    "certspotter": "api.certspotter.com",
    "crt.sh": "crt.sh",
    "crt.name": "crt.name",
}

#: Evidence kinds that mean the system resolver was asked about a hostname.
_RESOLUTION_KINDS = (
    "dns_resolution",
    "dns_error",
    "discovered_dns_resolution",
    "discovered_dns_error",
)

RESOLVER_SERVICE = "system resolver"


@dataclass(frozen=True)
class Disclosure:
    """One external party, and what it was told."""

    service: str
    fidelity: str
    via: str
    subjects: int
    detail: str


@dataclass(frozen=True)
class DisclosureLedger:
    scan_id: str | None
    target: str | None
    disclosures: tuple[Disclosure, ...]

    @property
    def observed(self) -> tuple[Disclosure, ...]:
        return tuple(d for d in self.disclosures if d.fidelity == OBSERVED)

    @property
    def declared(self) -> tuple[Disclosure, ...]:
        return tuple(d for d in self.disclosures if d.fidelity == DECLARED)

    def to_jsonl(self) -> str:
        return "".join(
            json.dumps({
                "scan_id": self.scan_id,
                "target": self.target,
                "service": d.service,
                "fidelity": d.fidelity,
                "via": d.via,
                "subjects": d.subjects,
                "detail": d.detail,
            }, sort_keys=True) + "\n"
            for d in self.disclosures
        )


def _adapter_manifest() -> dict[str, tuple[tuple[str, ...], str]]:
    """Which third parties each external tool is documented to contact.

    Imported lazily: the adapters pull in the network and scope layers, and
    this module is also used by the CLI's read-only views.
    """
    from sh4q.adapters import ADAPTER_DISCLOSURES

    return ADAPTER_DISCLOSURES


def summarize_disclosures(
    database: str, *, target: str | None = None, scan_id: str | None = None
) -> DisclosureLedger:
    """Read the disclosure ledger for a recorded scan."""
    clause = []
    params: list[object] = []
    if scan_id:
        clause.append("scan_run_id = ?")
        params.append(scan_id)
    if target:
        clause.append("target = ?")
        params.append(target)
    where = (" AND " + " AND ".join(clause)) if clause else ""

    ct_subjects: dict[str, set[str]] = {}
    adapters_run: set[str] = set()
    resolved_names: set[str] = set()

    with open_sync_database(database) as db:
        rows = db.execute(
            "SELECT kind, target, content FROM evidence WHERE kind IN "
            "('ct_provider_status', 'adapter_execution', "
            "'dns_resolution', 'dns_error', "
            "'discovered_dns_resolution', 'discovered_dns_error')" + where,
            params,
        ).fetchall()

    for kind, row_target, raw in rows:
        try:
            content = json.loads(raw)
        except (TypeError, ValueError):
            continue
        if kind == "ct_provider_status":
            source = content.get("source")
            if source:
                subject = content.get("domain") or row_target
                ct_subjects.setdefault(source, set()).add(subject)
        elif kind == "adapter_execution":
            adapter = content.get("adapter")
            if adapter:
                adapters_run.add(adapter)
        elif kind in _RESOLUTION_KINDS:
            # Distinct names, not event count: one name resolving to six
            # addresses is six events and one disclosure.
            domain = content.get("domain")
            if domain:
                resolved_names.add(domain)

    disclosures: list[Disclosure] = []

    for source in sorted(ct_subjects):
        disclosures.append(Disclosure(
            service=CT_SERVICE_HOSTS.get(source, source),
            fidelity=OBSERVED,
            via="native",
            subjects=len(ct_subjects[source]),
            detail="certificate transparency query",
        ))

    manifest = _adapter_manifest()
    for adapter in sorted(adapters_run):
        services, detail = manifest.get(adapter, ((), ""))
        for service in services:
            disclosures.append(Disclosure(
                service=service,
                fidelity=DECLARED,
                via=adapter,
                subjects=1,
                detail=detail,
            ))

    if resolved_names:
        disclosures.append(Disclosure(
            service=RESOLVER_SERVICE,
            fidelity=OBSERVED,
            via="native",
            subjects=len(resolved_names),
            detail="one lookup per hostname, to whichever resolver this host uses",
        ))

    return DisclosureLedger(scan_id=scan_id, target=target, disclosures=tuple(disclosures))


def planned_disclosures(
    *,
    ct_sources=(),
    adapters=(),
    resolves_names: bool = False,
) -> tuple[Disclosure, ...]:
    """What a scan is about to disclose, before it runs.

    Printed, never prompted. The same tool runs under `--progress jsonl` and
    from a scheduled job, and a blocking confirmation would hang both.
    """
    planned: list[Disclosure] = []
    for source in ct_sources:
        planned.append(Disclosure(
            service=CT_SERVICE_HOSTS.get(source, source),
            fidelity=OBSERVED,
            via="native",
            subjects=0,
            detail="certificate transparency query",
        ))
    manifest = _adapter_manifest()
    for adapter in adapters:
        services, detail = manifest.get(adapter, ((), ""))
        for service in services:
            planned.append(Disclosure(
                service=service, fidelity=DECLARED, via=adapter,
                subjects=0, detail=detail,
            ))
    if resolves_names:
        planned.append(Disclosure(
            service=RESOLVER_SERVICE, fidelity=OBSERVED, via="native",
            subjects=0,
            detail="one lookup per hostname, to whichever resolver this host uses",
        ))
    return tuple(planned)
