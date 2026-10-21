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
import uuid
from dataclasses import dataclass

from sh4q.storage.db import open_sync_database


#: The window a generated rule queries over. A defender writes rules against
#: minutes, not against however long a particular scan happened to run.
#: Namespace for rule identifiers. The Sigma specification requires `id` to be
#: a UUID, and pySigma rejects anything else -- `sh4q-subdomain-enumeration`
#: read fine to a human and was not a valid rule. Deriving it with uuid5 over a
#: fixed namespace keeps it deterministic: the same signal always exports the
#: same id, so a defender's tooling tracks one rule across re-exports instead
#: of seeing a new rule each time. A random uuid4 would validate and break that.
_ID_NAMESPACE = uuid.UUID("5f4e3d2c-1b0a-4987-8765-432110fedcba")


def _rule_id(signal: str) -> uuid.UUID:
    """The stable UUID for one signal's rule."""
    return uuid.uuid5(_ID_NAMESPACE, signal)


RULE_WINDOW_SECONDS = 60

#: No rule fires below this, whatever the measured rate projects to. A
#: threshold of two would alert on ordinary traffic.
MINIMUM_THRESHOLD = 5

#: Below this many observations a rate is arithmetic on noise, not a
#: measurement. A real scan probed two endpoints in 4.85s and the rate came
#: out at 0.41/s -- indistinguishable in the output from the 302-event
#: measurement beside it, and extrapolated to a threshold of 12 distinct
#: hosts a minute, which ordinary CDN or proxy traffic clears. The rate is
#: still reported; what changes is that the rule says what it rests on.
MINIMUM_OBSERVATIONS = 30


@dataclass(frozen=True)
class _Signal:
    """One sh4q behaviour, and where a defender would look for it."""

    signal: str
    kinds: tuple[str, ...]
    #: Plugins whose evidence counts toward this signal. `subdomain_found` is
    #: emitted by both `ct` and `subfinder`, so matching on kind alone made
    #: the certificate-transparency row absorb 1211 Subfinder names and call
    #: them certificate transparency. It also names the stages whose recorded
    #: duration is this signal's window.
    plugins: tuple[str, ...]
    log_source: str          # empty when the target sees nothing
    attack: tuple[str, ...]
    description: str
    #: Sigma `detection:` selection for the base event rule. The threshold
    #: lives in the correlation rule, not here.
    selection: str = ""
    #: Field whose *distinct* values are counted. Recon is characterised by
    #: breadth -- many names, many hosts, many paths -- not by request volume,
    #: so `value_count` over this field is the shape, not `event_count`.
    count_field: str = ""
    #: Field the count is grouped by: the single source doing the looking.
    group_by: str = ""


#: Ordered so the most specific behaviour is reported first. `log_source` is
#: empty exactly when the stage never contacts the target -- that is what
#: `visible_to_target` is derived from, rather than a separate flag that could
#: disagree with it.
SIGNALS = (
    _Signal(
        signal="subdomain_enumeration",
        plugins=("discovered-dns",),
        kinds=("discovered_dns_resolution", "discovered_dns_error"),
        log_source="dns",
        attack=("attack.reconnaissance", "attack.t1590.002"),
        description="Many DNS lookups for distinct names in one zone, in a short window.",
        selection=(
            "    query_type: 'A'\n"
        ),
        count_field="query_name",
        group_by="src_ip",
    ),
    _Signal(
        signal="http_probing",
        plugins=("http", "discovered-http"),
        kinds=("http_probe",),
        log_source="webserver",
        attack=("attack.reconnaissance", "attack.t1595"),
        description="Requests to many distinct hosts in one estate from a single source.",
        selection=(
            "    cs-method: 'GET'\n"
        ),
        count_field="cs-host",
        group_by="c-ip",
    ),
    _Signal(
        signal="virtual_host_probing",
        plugins=("vhost-discovery",),
        kinds=("vhost_observation", "vhost_baseline"),
        log_source="webserver",
        attack=("attack.reconnaissance", "attack.t1595.003"),
        description="Repeated requests to one address with a changing Host header.",
        selection=(
            "    cs-method: 'GET'\n"
        ),
        count_field="cs-host",
        group_by="c-ip",
    ),
    _Signal(
        signal="directory_enumeration",
        plugins=("directory-discovery",),
        kinds=("directory_observation",),
        log_source="webserver",
        attack=("attack.reconnaissance", "attack.t1595.003"),
        description="Many distinct paths requested on one host, most of them absent.",
        selection=(
            "    sc-status: 404\n"
        ),
        count_field="cs-uri-stem",
        group_by="c-ip",
    ),
    # Passive stages. The target is never contacted, so there is nothing for it
    # to log and no rule to write. Reported anyway: the absence is the finding.
    _Signal(
        signal="certificate_transparency",
        plugins=("ct",),
        kinds=("subdomain_found",),
        log_source="",
        attack=("attack.reconnaissance", "attack.t1596.003"),
        description=(
            "Names read from public certificate logs. The target is never "
            "contacted and sees nothing."
        ),
    ),
    _Signal(
        signal="passive_subdomain_adapter",
        kinds=("subdomain_found",),
        plugins=("subfinder",),
        log_source="",
        attack=("attack.reconnaissance", "attack.t1590.002"),
        description=(
            "Names supplied by an external passive adapter. Its own providers "
            "are contacted, never the target, which sees nothing."
        ),
    ),
    _Signal(
        signal="historical_url_retrieval",
        plugins=("url-history",),
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
    _selection: str = ""
    _count_field: str = ""
    _group_by: str = ""

    @property
    def rate_measured(self) -> bool:
        """Whether a rate could be derived at all.

        False when the stage left no duration in `stage_metrics` -- an
        interrupted run, or a scan recorded before that evidence existed.
        A rate of zero and an unmeasurable rate are different claims.
        """
        return self.window_seconds > 0

    @property
    def rate_well_sampled(self) -> bool:
        """Whether enough events were seen for the rate to mean anything.

        A measured rate and a well-measured rate are different claims, and
        two observations produce the first without the second.
        """
        return self.rate_measured and self.observed >= MINIMUM_OBSERVATIONS

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

    def _detection_groups(self) -> list[tuple[Detection, ...]]:
        """Visible detections grouped by the rule they would generate.

        `http_probing` and `virtual_host_probing` produce byte-identical
        Sigma -- `category: webserver`, `cs-method: GET`, distinct `cs-host`
        per `c-ip` -- because in a webserver log they *are* the same
        observable: nothing in that taxonomy separates fuzzing a Host header
        from probing many hosts. Exported separately they became two rules
        over the same events with thresholds of 12 and 16, so the lower one
        always fired first and the other could never contribute. One
        behaviour, one rule, one threshold from the combined measurement.
        """
        grouped: dict[tuple[str, str, str, str], list[Detection]] = {}
        for item in self.visible:
            key = (item.log_source, item._selection, item._count_field, item._group_by)
            grouped.setdefault(key, []).append(item)
        return [tuple(members) for members in grouped.values()]

    def to_sigma_rules(self) -> dict[str, str]:
        """One rule per behaviour a defender could actually observe.

        Each file is two YAML documents: the base rule matching the individual
        events, and a correlation rule counting them. The single-document
        aggregation form -- `condition: selection | count(x) by y > n` -- is
        deprecated Sigma and pySigma rejects it outright, so the earlier
        version of this exporter produced files no Sigma pipeline would load.

        Nothing is emitted for a passive stage. A rule for an action the
        target never sees would be a rule that can never fire.
        """
        rules: dict[str, str] = {}
        for group in self._detection_groups():
            item = _merged(group)
            # The scan's own span is not a detection window. A stage that ran
            # for 166 seconds would give `timespan: 166s`, and one read from a
            # database holding several scans gave 62813s with a threshold of
            # 1887 -- a rule that can never fire. Project the measured rate
            # onto a window a defender would actually query.
            window = RULE_WINDOW_SECONDS
            expected = item.rate * window if item.rate_measured else 0.0
            # Half the observed rate, so a scan run more slowly than this one
            # still trips it, and never below a floor that noise would clear.
            threshold = max(MINIMUM_THRESHOLD, int(expected * 0.5))
            events_name = f"sh4q_{item.signal}_events"
            contributors = (
                ""
                if len(group) == 1 else
                "  Covers " + ", ".join(d.signal for d in group) + ".\n"
                "  Those stages are one behaviour in a webserver log, so this is\n"
                "  one rule rather than two firing on the same events.\n"
            )
            provenance = (
                f"  Derived from a real Sh4q scan of {self.target or 'a target'}, which\n"
                f"  produced {item.observed} observable event(s)"
                + (
                    f" over {item.window_seconds:.0f}s "
                    f"({item.rate:.2f}/s).\n"
                    f"  At that rate a {window}s window sees about {expected:.0f}; the\n"
                    f"  threshold is half, so a slower scan still trips it.\n"
                    + (
                        ""
                        if item.rate_well_sampled else
                        f"  That rests on only {item.observed} event(s), too few for the\n"
                        "  rate to be reliable, so treat this threshold as a starting\n"
                        "  point and tune it against your own traffic.\n"
                    )
                    if item.rate_measured else
                    ".\n  That scan left no stage duration behind, so no rate could be\n"
                    f"  measured and this threshold is the floor of {MINIMUM_THRESHOLD},\n"
                    "  not a measurement. Tune it before use.\n"
                )
                + contributors
                + (
                    "  Measured across more than one scan, so the rate is an "
                    "average rather\n  than any single run's behaviour.\n"
                    if self.scans > 1 else ""
                )
            )
            tags = "".join(f"  - {tag}\n" for tag in item.attack)
            title = item.description.rstrip(".")
            # Named for every signal it covers. Called after the primary
            # alone, the listing would show no virtual-host rule and a
            # defender would reasonably conclude none was written.
            filename = "sh4q_" + "_and_".join(d.signal for d in group) + ".yml"
            rules[filename] = (
                # --- the events the correlation counts --------------------
                f"title: {title} (events)\n"
                f"id: {_rule_id(item.signal)}\n"
                f"name: {events_name}\n"
                "status: experimental\n"
                "description: >\n"
                f"  Individual events the {item.signal} correlation counts. On its\n"
                "  own this matches ordinary traffic and is not an alert.\n"
                "logsource:\n"
                f"  category: {item.log_source}\n"
                "detection:\n"
                "  selection:\n"
                f"{item._selection}"
                "  condition: selection\n"
                "level: informational\n"
                f"tags:\n{tags}"
                "---\n"
                # --- the correlation that actually alerts -----------------
                f"title: {title}\n"
                f"id: {_rule_id(item.signal + ':correlation')}\n"
                "status: experimental\n"
                "description: >\n"
                f"{provenance}"
                "correlation:\n"
                # Recon is breadth, not volume: many distinct names from one
                # source, not many requests. `value_count` is that shape.
                "  type: value_count\n"
                "  rules:\n"
                f"    - {events_name}\n"
                "  group-by:\n"
                f"    - {item._group_by}\n"
                f"  timespan: {window}s\n"
                "  condition:\n"
                f"    gte: {threshold}\n"
                f"    field: {item._count_field}\n"
                "level: medium\n"
                f"tags:\n{tags}"
            )
        return rules



def _stage_durations(db, where: str, params: list[object]) -> dict[str, float]:
    """Seconds each stage spent running, from its own durable record.

    This is the denominator the rate needs. Evidence `captured_at` records
    when a row was *written*, not when the request happened: the directory
    stage probes every candidate, returns them together, and the handler
    appends all six rows inside 0.2s of each other. Dividing by that span
    measured the speed of a SQLite write loop and reported 30.89 requests
    per second for a stage that made six requests in 31 seconds -- which
    projected to a threshold of 926 and would never have fired.

    Summed across scans when several are in view, so events and seconds
    cover the same runs.
    """
    totals: dict[str, float] = {}
    rows = db.execute(
        f"SELECT content FROM evidence{where}"
        + (" AND " if where else " WHERE ") + "kind = 'stage_metrics'",
        params,
    ).fetchall()
    for (content,) in rows:
        try:
            stages = json.loads(content).get("stages", [])
        except (json.JSONDecodeError, TypeError, AttributeError):
            continue
        for stage in stages:
            name, seconds = stage.get("name"), stage.get("duration_seconds")
            if isinstance(name, str) and isinstance(seconds, (int, float)):
                totals[name] = totals.get(name, 0.0) + float(seconds)
    return totals


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
            f"SELECT kind, plugin, content FROM evidence{where}", params
        ).fetchall()
        scans = db.execute(
            f"SELECT COUNT(DISTINCT scan_run_id) FROM evidence{where}", params
        ).fetchone()[0]
        durations = _stage_durations(db, where, list(params))

    # Keyed on (kind, plugin): `subdomain_found` is emitted by both `ct` and
    # `subfinder`, and matching on kind alone reported 1211 Subfinder names
    # as certificate transparency.
    counts: dict[tuple[str, str], int] = {}
    subjects: dict[tuple[str, str], int] = {}
    for kind, plugin, content in rows:
        key = (kind, plugin)
        counts[key] = counts.get(key, 0) + 1
        subjects[key] = subjects.get(key, 0) + _subject_count(content)

    detections: list[Detection] = []
    for spec in SIGNALS:
        keys = [(kind, plugin) for kind in spec.kinds for plugin in spec.plugins]
        records = sum(counts.get(key, 0) for key in keys)
        if not records:
            continue
        # One batched record can stand for thousands of observations, so the
        # record count alone understated url-history as "1 event" beside the
        # 4996 URLs it had just saved.
        observed = max(records, sum(subjects.get(key, 0) for key in keys))
        window = sum(durations.get(name, 0.0) for name in spec.plugins)
        detections.append(Detection(
            signal=spec.signal,
            observed=observed,
            # 0.0 means the stage left no duration behind, and the rate is
            # unknown rather than zero. `rate_measured` is what reads it.
            window_seconds=round(window, 3),
            rate=(observed / window) if window > 0 else 0.0,
            log_source=spec.log_source,
            attack=spec.attack,
            description=spec.description,
            _selection=spec.selection,
            _count_field=spec.count_field,
            _group_by=spec.group_by,
        ))

    return DetectionReport(
        scan_id=scan_id, target=target, detections=tuple(detections),
        scans=max(1, scans),
    )


def _merged(group: tuple[Detection, ...]) -> Detection:
    """One detection standing for a group that generates the same rule.

    Events and seconds are summed so the rate covers the same work, which
    also means a thinly-sampled stage is measured together with whatever
    shares its detection logic instead of extrapolating from a handful of
    events on its own.
    """
    first = group[0]
    if len(group) == 1:
        return first
    observed = sum(d.observed for d in group)
    window = round(sum(d.window_seconds for d in group), 3)
    return Detection(
        signal=first.signal,
        observed=observed,
        window_seconds=window,
        rate=(observed / window) if window > 0 else 0.0,
        log_source=first.log_source,
        attack=tuple(sorted({tag for d in group for tag in d.attack})),
        description=first.description,
        _selection=first._selection,
        _count_field=first._count_field,
        _group_by=first._group_by,
    )


def _subject_count(content: str | None) -> int:
    """How many observations one evidence record actually stands for."""
    try:
        payload = json.loads(content or "{}")
    except (json.JSONDecodeError, TypeError):
        return 1
    if isinstance(payload, dict):
        for field in ("urls", "names", "paths"):
            value = payload.get(field)
            if isinstance(value, list) and value:
                return len(value)
    return 1
