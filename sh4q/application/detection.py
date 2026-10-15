"""What a defender would see, derived from what a scan actually did.

The disclosure ledger answers "who did this tell about my target". This
answers the question a blue team asks instead: "what does this look like
from my side, and could I have caught it?"

Two things make this worth more than a folder of hand-written rules.

**The thresholds are measured.** A scan that made 1500 DNS lookups in 166
seconds produces a rule whose threshold comes from that, not from a guess
about what a scanner might do. Nobody has to argue about whether the number
is realistic; it is what the tool did.

**It states what a defender cannot see.** Certificate transparency, Subfinder
and URL history never touch the target, so no log on that side records them.
Claiming coverage of passive reconnaissance would be false, and the gap is the
useful half: you cannot detect the stage that found your subdomains, only the
stage that went on to probe them.

Read from durable evidence like `disclosure.py`, so it also answers for scans
already on disk, and so nothing here can influence what a scan does.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime

from sh4q.storage.db import open_sync_database


#: The window a generated rule queries over. A defender writes rules against
#: minutes, not against however long a particular scan happened to run.
RULE_WINDOW_SECONDS = 60

#: No rule fires below this, whatever the measured rate projects to. A
#: threshold of two would alert on ordinary traffic.
MINIMUM_THRESHOLD = 5


@dataclass(frozen=True)
class _Signal:
    """One sh4q behaviour, and where a defender would look for it."""

    signal: str
    kinds: tuple[str, ...]
    log_source: str          # empty when the target sees nothing
    attack: tuple[str, ...]
    description: str
    #: Sigma `detection:` body, formatted with the measured threshold.
    rule_body: str = ""


#: Ordered so the most specific behaviour is reported first. `log_source` is
#: empty exactly when the stage never contacts the target -- that is what
#: `visible_to_target` is derived from, rather than a separate flag that could
#: disagree with it.
SIGNALS = (
    _Signal(
        signal="subdomain_enumeration",
        kinds=("discovered_dns_resolution", "discovered_dns_error"),
        log_source="dns",
        attack=("attack.reconnaissance", "attack.t1590.002"),
        description="Many DNS lookups for distinct names in one zone, in a short window.",
        rule_body=(
            "  selection:\n"
            "    query_type: 'A'\n"
            "  timeframe: {window}s\n"
            "  condition: selection | count(query_name) by src_ip > {threshold}\n"
        ),
    ),
    _Signal(
        signal="http_probing",
        kinds=("http_probe",),
        log_source="webserver",
        attack=("attack.reconnaissance", "attack.t1595"),
        description="Requests to many distinct hosts in one estate from a single source.",
        rule_body=(
            "  selection:\n"
            "    cs-method: 'GET'\n"
            "  timeframe: {window}s\n"
            "  condition: selection | count(cs-host) by c-ip > {threshold}\n"
        ),
    ),
    _Signal(
        signal="virtual_host_probing",
        kinds=("vhost_observation", "vhost_baseline"),
        log_source="webserver",
        attack=("attack.reconnaissance", "attack.t1595.003"),
        description="Repeated requests to one address with a changing Host header.",
        rule_body=(
            "  selection:\n"
            "    cs-method: 'GET'\n"
            "  timeframe: {window}s\n"
            "  condition: selection | count(cs-host) by c-ip > {threshold}\n"
        ),
    ),
    _Signal(
        signal="directory_enumeration",
        kinds=("directory_observation",),
        log_source="webserver",
        attack=("attack.reconnaissance", "attack.t1595.003"),
        description="Many distinct paths requested on one host, most of them absent.",
        rule_body=(
            "  selection:\n"
            "    sc-status: 404\n"
            "  timeframe: {window}s\n"
            "  condition: selection | count(cs-uri-stem) by c-ip > {threshold}\n"
        ),
    ),
    # Passive stages. The target is never contacted, so there is nothing for it
    # to log and no rule to write. Reported anyway: the absence is the finding.
    _Signal(
        signal="certificate_transparency",
        kinds=("subdomain_found",),
        log_source="",
        attack=("attack.reconnaissance", "attack.t1596.003"),
        description=(
            "Names read from public certificate logs. The target is never "
            "contacted and sees nothing."
        ),
    ),
    _Signal(
        signal="historical_url_retrieval",
        kinds=("url_history_batch", "url_history_found"),
        log_source="",
        attack=("attack.reconnaissance", "attack.t1596"),
        description=(
            "URLs read from a public archive. The target is never contacted "
            "and sees nothing."
        ),
    ),
)


@dataclass(frozen=True)
class Detection:
    signal: str
    observed: int
    window_seconds: float
    rate: float
    log_source: str
    attack: tuple[str, ...]
    description: str
    _rule_body: str = ""

    @property
    def visible_to_target(self) -> bool:
        """Whether the target could see this at all.

        Derived from having a log source rather than stored separately, so the
        two can never disagree.
        """
        return bool(self.log_source)


@dataclass(frozen=True)
class DetectionReport:
    scan_id: str | None
    target: str | None
    detections: tuple[Detection, ...]
    #: How many scans the evidence came from. More than one means every rate
    #: here is an average across runs and not any single scan's behaviour,
    #: which the generated rules say rather than quietly averaging.
    scans: int = 1

    @property
    def visible(self) -> tuple[Detection, ...]:
        return tuple(d for d in self.detections if d.visible_to_target)

    @property
    def invisible(self) -> tuple[Detection, ...]:
        return tuple(d for d in self.detections if not d.visible_to_target)

    def to_telemetry_jsonl(self) -> str:
        return "".join(
            json.dumps({
                "scan_id": self.scan_id,
                "target": self.target,
                "signal": d.signal,
                "observed": d.observed,
                "window_seconds": d.window_seconds,
                "rate_per_second": round(d.rate, 3),
                "visible_to_target": d.visible_to_target,
                "scans": self.scans,
                "log_source": d.log_source,
                "attack": list(d.attack),
            }, sort_keys=True) + "\n"
            for d in self.detections
        )

    def to_sigma_rules(self) -> dict[str, str]:
        """One rule per behaviour a defender could actually observe.

        Nothing is emitted for a passive stage. A rule for an action the
        target never sees would be a rule that can never fire.
        """
        rules: dict[str, str] = {}
        for item in self.visible:
            # The scan's own span is not a detection window. A stage that ran
            # for 166 seconds would give `timeframe: 166s`, and one read from a
            # database holding several scans gave `timeframe: 62813s` with a
            # threshold of 1887 -- a rule that can never fire. Project the
            # measured rate onto a window a defender would actually query.
            window = RULE_WINDOW_SECONDS
            expected = item.rate * window
            # Half the observed rate, so a scan run more slowly than this one
            # still trips it, and never below a floor that noise would clear.
            threshold = max(MINIMUM_THRESHOLD, int(expected * 0.5))
            body = item._rule_body.format(window=window, threshold=threshold)
            rules[f"sh4q_{item.signal}.yml"] = (
                f"title: {item.description.rstrip('.')}\n"
                f"id: sh4q-{item.signal.replace('_', '-')}\n"
                "status: experimental\n"
                f"description: >\n"
                f"  Derived from a real Sh4q scan of {self.target or 'a target'}, which\n"
                f"  produced {item.observed} observable event(s) over "
                f"{item.window_seconds:.0f}s ({item.rate:.2f}/s).\n"
                f"  At that rate a {window}s window sees about {expected:.0f}; the\n"
                f"  threshold is half, so a slower scan still trips it.\n"
                + (
                    "  Measured across more than one scan, so the rate is an "
                    "average rather\n  than any single run's behaviour.\n"
                    if self.scans > 1 else ""
                )
                + f"logsource:\n"
                f"  category: {item.log_source}\n"
                f"detection:\n"
                f"{body}"
                f"level: medium\n"
                f"tags:\n"
                + "".join(f"  - {tag}\n" for tag in item.attack)
            )
        return rules


def _parsed(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def summarize_detections(
    database: str, *, target: str | None = None, scan_id: str | None = None
) -> DetectionReport:
    """Read the detection picture for a recorded scan."""
    clause = []
    params: list[object] = []
    if scan_id:
        clause.append("scan_run_id = ?")
        params.append(scan_id)
    if target:
        clause.append("target = ?")
        params.append(target)
    where = (" WHERE " + " AND ".join(clause)) if clause else ""

    with open_sync_database(database) as db:
        rows = db.execute(
            f"SELECT kind, captured_at FROM evidence{where}", params
        ).fetchall()
        scans = db.execute(
            f"SELECT COUNT(DISTINCT scan_run_id) FROM evidence{where}", params
        ).fetchone()[0]

    seen: dict[str, list[datetime]] = {}
    for kind, captured_at in rows:
        moment = _parsed(captured_at)
        if moment is not None:
            seen.setdefault(kind, []).append(moment)

    detections: list[Detection] = []
    for spec in SIGNALS:
        moments = sorted(m for kind in spec.kinds for m in seen.get(kind, []))
        if not moments:
            continue
        window = (moments[-1] - moments[0]).total_seconds()
        detections.append(Detection(
            signal=spec.signal,
            observed=len(moments),
            window_seconds=round(window, 3),
            # A single event has no window; report its rate as the count so a
            # threshold derived from it is not a division by zero.
            rate=(len(moments) / window) if window else float(len(moments)),
            log_source=spec.log_source,
            attack=spec.attack,
            description=spec.description,
            _rule_body=spec.rule_body,
        ))

    return DetectionReport(
        scan_id=scan_id, target=target, detections=tuple(detections),
        scans=max(1, scans),
    )
