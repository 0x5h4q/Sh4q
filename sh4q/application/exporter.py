from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path

from sh4q.storage.scan_runs import ScanRun
from sh4q.application.results import list_technology_observations
from sh4q.storage.db import node_timestamp_columns, open_sync_database, row_identifier
from sh4q.storage.errors import CorruptRecordError
from sh4q.storage.json_fields import MALFORMED, decode_object
from sh4q.application.html_report import render_html_report
from sh4q.application.detection import summarize_detections
from sh4q.application.redaction import Redactor


class ScanOwnershipUnavailableError(Exception):
    pass


def _skipped_keys(skipped: list[CorruptRecordError]) -> tuple[str, ...]:
    """Identify each bad row once, even when two read paths saw it."""
    return tuple(
        dict.fromkeys(str(item.record_id or item.field) for item in skipped)
    )


def _javascript_observations(
    db, scan_id: str, *, skipped: list[CorruptRecordError] | None = None
) -> list[dict]:
    columns = {row[1] for row in db.execute("PRAGMA table_info(evidence)").fetchall()}
    if not {"kind", "content", "captured_at"}.issubset(columns):
        return []
    rows = db.execute(
        f"SELECT {row_identifier(db, 'evidence')} AS record_id, kind, content, "
        "captured_at FROM evidence WHERE scan_run_id = ? "
        "AND kind LIKE 'javascript_%' ORDER BY captured_at",
        (scan_id,),
    ).fetchall()
    from sh4q.application.triage import classify_javascript_reference

    observations = []
    for record_id, kind, raw_content, captured_at in rows:
        content = decode_object(
            raw_content,
            field="content",
            record_id=record_id,
            skipped=skipped,
        )
        if content is MALFORMED:
            continue
        value = content.get("value", "")
        source_endpoint = content.get("source_endpoint", "")
        observations.append(
            {
                "kind": kind,
                "value": value,
                "source_endpoint": source_endpoint,
                "pattern": content.get("pattern", ""),
                "relevance": classify_javascript_reference(
                    value, source_endpoint
                )[0],
                "captured_at": captured_at,
            }
        )
    return observations


def _http_inventory(
    db, scan_id: str, *, skipped: list[CorruptRecordError] | None = None
) -> list[dict]:
    endpoint_first_seen, endpoint_last_seen = node_timestamp_columns(db, "endpoint")
    endpoint_rows = db.execute(
        f"""SELECT DISTINCT domain.id, domain.value, endpoint.id, endpoint.value,
        endpoint.attributes, {endpoint_first_seen}, {endpoint_last_seen}
        FROM scan_assets sa
        JOIN relationships serves ON serves.id = sa.relationship_id
        JOIN nodes domain ON domain.id = serves.from_id
        JOIN nodes endpoint ON endpoint.id = serves.to_id
        WHERE sa.scan_run_id = ? AND serves.type = 'SERVES'
          AND domain.type = 'domain' AND endpoint.type = 'url'
        ORDER BY endpoint.value""",
        (scan_id,),
    ).fetchall()
    inventory = []
    for (
        domain_id, domain, endpoint_id, endpoint, raw_endpoint_attributes,
        first_seen, last_seen,
    ) in endpoint_rows:
        address_rows = db.execute(
            """SELECT DISTINCT address.value
            FROM scan_assets sa
            JOIN relationships resolves ON resolves.id = sa.relationship_id
            JOIN nodes address ON address.id = resolves.to_id
            WHERE sa.scan_run_id = ? AND resolves.type = 'RESOLVES_TO'
              AND resolves.from_id = ? AND address.type = 'ip'
            ORDER BY address.value""",
            (scan_id, domain_id),
        ).fetchall()
        technology_rows = db.execute(
            """SELECT technology.value, detection.attributes, sa.source_plugin
            FROM scan_assets sa
            JOIN relationships detection ON detection.id = sa.relationship_id
            JOIN nodes technology ON technology.id = detection.to_id
            WHERE sa.scan_run_id = ? AND detection.type = 'DETECTED_TECHNOLOGY'
              AND detection.from_id = ? AND technology.type = 'technology'
            ORDER BY technology.value""",
            (scan_id, endpoint_id),
        ).fetchall()
        source_rows = db.execute(
            """SELECT DISTINCT sa.source_plugin
            FROM scan_assets sa JOIN relationships r ON r.id = sa.relationship_id
            WHERE sa.scan_run_id = ? AND (r.to_id = ? OR r.from_id = ?)
            ORDER BY sa.source_plugin""",
            (scan_id, endpoint_id, endpoint_id),
        ).fetchall()
        technologies = []
        sources = {row[0] for row in source_rows if row[0]}
        for technology, raw_attributes, source in technology_rows:
            attributes = decode_object(
                raw_attributes,
                field="attributes",
                record_id=technology,
                skipped=skipped,
            )
            if attributes is MALFORMED:
                continue
            technologies.append({
                "name": technology,
                "category": attributes.get("category", ""),
                "version": attributes.get("version", ""),
                "confidence": attributes.get("confidence", ""),
                "signal": attributes.get("raw_observation", ""),
                "source": attributes.get("source", source),
            })
            if source:
                sources.add(source)
        endpoint_attributes = decode_object(
            raw_endpoint_attributes,
            field="attributes",
            record_id=endpoint_id,
            skipped=skipped,
        )
        if endpoint_attributes is MALFORMED:
            continue
        inventory.append({
            "type": "http-inventory",
            "domain": domain,
            "endpoint": endpoint,
            "http_status": endpoint_attributes.get("status"),
            "resolved_addresses": [row[0] for row in address_rows],
            "technologies": technologies,
            "sources": sorted(sources),
            "first_seen": first_seen,
            "last_seen": last_seen,
        })
    return inventory


REDACTABLE_ASSET_TYPES = frozenset({"url", "historical-url"})


def _redact_asset(item: dict, redactor: Redactor) -> dict:
    if item.get("type") not in REDACTABLE_ASSET_TYPES:
        return item
    return item | {"value": redactor.url(item["value"])}


@dataclass(frozen=True)
class ExportResult:
    """What an export wrote, including what redaction changed.

    `export_scan` returned a bare asset count, so `--redact` printed the same
    line whether it rewrote four hundred values or none.
    """

    asset_count: int
    redaction_enabled: bool = False
    fields_considered: int = 0
    fields_redacted: int = 0
    #: Stored JSON rows skipped because they could not be decoded. The export
    #: is still useful; silently omitting the row would not be.
    skipped_records: int = 0
    skipped_examples: tuple[str, ...] = ()

    @property
    def skipped_summary(self) -> str:
        if not self.skipped_records:
            return ""
        example = f" ({', '.join(self.skipped_examples)})" if self.skipped_examples else ""
        return (
            f"Skipped {self.skipped_records} malformed record(s) while reading "
            f"this scan{example}."
        )

    def __int__(self) -> int:
        return self.asset_count

    def __eq__(self, other) -> bool:
        # Callers that only care how many assets went out compare against an
        # int, and several tests already do.
        if isinstance(other, int):
            return self.asset_count == other
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.asset_count)

    @property
    def redaction_summary(self) -> str:
        if not self.redaction_enabled:
            return ""
        if not self.fields_considered:
            return "Redaction was on; no URL-bearing field was exported."
        return (
            f"Redaction rewrote {self.fields_redacted} of "
            f"{self.fields_considered} URL-bearing field(s)."
        )


def export_scan(
    database: str,
    run: ScanRun,
    *,
    format: str,
    output: Path,
    force: bool = False,
    alive: str | None = None,
    asset_type: str | None = None,
    redact: bool = False,
) -> ExportResult:
    redactor = Redactor(enabled=redact)
    skipped: list[CorruptRecordError] = []
    if alive not in (None, "http", "dns"):
        raise ValueError(f"unsupported alive filter: {alive}")
    if alive and asset_type:
        raise ValueError("--alive and --type cannot be combined")
    with open_sync_database(database) as db:
        n_first_seen, n_last_seen = node_timestamp_columns(db, "n")
        domain_first_seen, domain_last_seen = node_timestamp_columns(db, "domain")
        inventory_assets = (
            _http_inventory(db, run.id, skipped=skipped)
            if asset_type == "http-inventory"
            else None
        )
        javascript_observations = _javascript_observations(db, run.id, skipped=skipped)
        if alive in ("http", "dns"):
            relationship_type = "SERVES" if alive == "http" else "RESOLVES_TO"
            endpoint_type = "url" if alive == "http" else "ip"
            rows = db.execute(
                f"""SELECT domain.type, domain.value, domain.attributes,
                group_concat(DISTINCT sa.source_plugin), endpoint.value, endpoint.attributes,
                {domain_first_seen}, {domain_last_seen}
                FROM scan_assets sa
                JOIN relationships r ON r.id = sa.relationship_id
                JOIN nodes domain ON domain.id = r.from_id
                JOIN nodes endpoint ON endpoint.id = r.to_id
                WHERE sa.scan_run_id = ? AND r.type = ?
                  AND domain.type = 'domain' AND endpoint.type = ?
                GROUP BY domain.id, domain.type, domain.value, domain.attributes,
                  endpoint.id, endpoint.value, endpoint.attributes,
                  {domain_first_seen}, {domain_last_seen}
                ORDER BY domain.value, endpoint.value""",
                (run.id, relationship_type, endpoint_type),
            ).fetchall()
        else:
            rows = db.execute(
                f"""SELECT n.type, n.value, n.attributes,
                group_concat(DISTINCT sa.source_plugin),
                MAX(CASE WHEN r.type = 'HISTORICAL_URL' THEN 1 ELSE 0 END),
                MAX(CASE WHEN r.type = 'SERVES' THEN 1 ELSE 0 END),
                {n_first_seen}, {n_last_seen}
                FROM scan_assets sa JOIN nodes n ON n.id = sa.asset_id
                LEFT JOIN relationships r ON r.id = sa.relationship_id
                WHERE sa.scan_run_id = ?
                GROUP BY n.id, n.type, n.value, n.attributes, {n_first_seen}, {n_last_seen}
                ORDER BY n.type, n.value""",
                (run.id,),
            ).fetchall()
        owned_asset_count = db.execute(
            "SELECT COUNT(*) FROM scan_assets WHERE scan_run_id = ?", (run.id,)
        ).fetchone()[0]
        evidence_count = db.execute(
            "SELECT COUNT(*) FROM evidence WHERE scan_run_id = ?", (run.id,)
        ).fetchone()[0]
    if not owned_asset_count and evidence_count:
        raise ScanOwnershipUnavailableError(
            f"scan {run.id} contains {evidence_count} evidence record(s) but no "
            "scan-owned assets; it predates the asset-ownership migration"
        )
    if output.exists() and not force:
        raise FileExistsError(f"output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    if asset_type == "http-inventory":
        assets = inventory_assets or []
    elif asset_type == "technology":
        # No cap: an export is the record handed to someone else, and a
        # silently shortened one is worse than none. Terminal listings cap
        # because they are read on screen; this is not.
        observations = list_technology_observations(
            database, scan_id=run.id, limit=None, skipped=skipped
        )
        assets = [
            {
                "type": "technology",
                "value": item.technology,
                "endpoint": item.endpoint,
                "category": item.category,
                "version": item.version,
                "confidence": item.confidence,
                "http_status": item.status,
                "signal": item.signal,
                "source": item.source,
                "first_seen": item.first_seen,
                "last_seen": item.last_seen,
            }
            for item in observations
        ]
    else:
        assets = []
        for row in rows:
            attributes = decode_object(
                row[2],
                field="attributes",
                record_id=row[1],
                skipped=skipped,
            )
            if attributes is MALFORMED:
                continue
            asset = {
                "type": "historical-url" if row[0] == "url" and row[4] and not row[5] else row[0],
                "value": row[1],
                "attributes": attributes,
                "sources": sorted((row[3] or "").split(",")),
                "first_seen": row[6],
                "last_seen": row[7],
            }
            if alive in ("http", "dns"):
                endpoint_attributes = decode_object(
                    row[5],
                    field="attributes",
                    record_id=row[1],
                    skipped=skipped,
                )
                if endpoint_attributes is MALFORMED:
                    continue
                asset |= {
                    "endpoint": row[4],
                    "endpoint_attributes": endpoint_attributes,
                }
            assets.append(asset)

    if format == "sigma":
        # The only format whose output is a directory: one rule per detectable
        # behaviour plus the telemetry they were derived from. Writing them to
        # a single file would mean a defender had to split it before use.
        report = summarize_detections(database, target=run.target, scan_id=run.id)
        # The path given is the directory, verbatim. Deriving one by stripping a
        # suffix would mean `--output rules.d` quietly wrote to `rules`, and a
        # surprising output path is worse than an oddly named one.
        destination = output
        destination.mkdir(parents=True, exist_ok=True)
        rules = report.to_sigma_rules()
        # Re-exporting over an earlier run would otherwise leave that run's
        # rules behind for any signal this one lacks, and the operator would
        # ship a rule derived from a scan they did not export. Only files this
        # exporter names are removed; anything else in the directory is theirs.
        for stale in destination.glob("sh4q_*.yml"):
            if stale.name not in rules:
                stale.unlink()
        for name, rule in rules.items():
            (destination / name).write_text(rule, encoding="utf-8")
        (destination / "telemetry.jsonl").write_text(
            report.to_telemetry_jsonl(), encoding="utf-8"
        )
        return ExportResult(
            asset_count=len(rules),
            redaction_enabled=redactor.enabled,
            fields_considered=redactor.considered,
            fields_redacted=redactor.redacted,
            skipped_records=len(_skipped_keys(skipped)),
            skipped_examples=_skipped_keys(skipped)[:3],
        )

    if format == "html":
        output.write_text(
            render_html_report(
                database, run, redactor=redactor, skipped=skipped
            ), encoding="utf-8"
        )
    elif format == "json":
        document = {
            "scan": {
                "id": run.id,
                "target": run.target,
                "started_at": run.started_at,
                "completed_at": run.completed_at,
                "status": run.status,
            },
            "asset_count": len(assets),
            "assets": [_redact_asset(item, redactor) for item in assets],
            "javascript_observations": [
                observation | {
                    "value": redactor.url(observation.get("value", "")),
                    "source_endpoint": redactor.url(observation.get("source_endpoint", "")),
                }
                for observation in javascript_observations
            ],
        }
        output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    elif format == "csv":
        with output.open("w", newline="", encoding="utf-8") as stream:
            if asset_type == "technology":
                fieldnames = [
                    "scan_id", "target", "endpoint", "technology", "category",
                    "version", "confidence", "http_status", "signal",
                    "source", "first_seen", "last_seen",
                ]
            elif asset_type == "http-inventory":
                fieldnames = [
                    "scan_id", "target", "domain", "endpoint", "http_status",
                    "resolved_addresses", "technologies", "technology_categories",
                    "technology_versions", "technology_confidences",
                    "technology_signals", "sources", "first_seen", "last_seen",
                ]
            else:
                fieldnames = [
                    "scan_id", "target", "type", "value", "sources", "attributes",
                    "first_seen", "last_seen",
                ]
                if alive == "http":
                    fieldnames.extend(["endpoint", "http_status"])
                elif alive == "dns":
                    fieldnames.append("resolved_address")
            writer = csv.DictWriter(
                stream,
                fieldnames=fieldnames,
            )
            writer.writeheader()
            for item in assets:
                if asset_type == "technology":
                    writer.writerow({
                        "scan_id": run.id,
                        "target": run.target,
                        "endpoint": redactor.url(item["endpoint"]),
                        "technology": item["value"],
                        "category": item["category"],
                        "version": item["version"],
                        "confidence": item["confidence"],
                        "http_status": item["http_status"],
                        "signal": item["signal"],
                        "source": item["source"],
                        "first_seen": item["first_seen"],
                        "last_seen": item["last_seen"],
                    })
                elif asset_type == "http-inventory":
                    observations = item["technologies"]
                    writer.writerow({
                        "scan_id": run.id,
                        "target": run.target,
                        "domain": item["domain"],
                        "endpoint": redactor.url(item["endpoint"]),
                        "http_status": item["http_status"],
                        "resolved_addresses": ";".join(item["resolved_addresses"]),
                        "technologies": ";".join(value["name"] for value in observations),
                        "technology_categories": ";".join(value["category"] for value in observations),
                        "technology_versions": ";".join(value["version"] for value in observations),
                        "technology_confidences": ";".join(value["confidence"] for value in observations),
                        "technology_signals": ";".join(value["signal"] for value in observations),
                        "sources": ";".join(item["sources"]),
                        "first_seen": item["first_seen"],
                        "last_seen": item["last_seen"],
                    })
                else:
                    item = _redact_asset(item, redactor)
                    if "endpoint" in item and alive == "http":
                        item = item | {"endpoint": redactor.url(item["endpoint"])}
                    writer.writerow({
                        "scan_id": run.id,
                        "target": run.target,
                        "type": item["type"],
                        "value": item["value"],
                        "sources": ",".join(item["sources"]),
                        "attributes": json.dumps(item["attributes"], sort_keys=True),
                        "first_seen": item["first_seen"],
                        "last_seen": item["last_seen"],
                        **({"endpoint": item["endpoint"], "http_status": item["endpoint_attributes"].get("status")} if alive == "http" else {"resolved_address": item["endpoint"]} if alive == "dns" else {}),
                    })
    else:
        raise ValueError(f"unsupported export format: {format}")
    return ExportResult(
        asset_count=len(assets),
        redaction_enabled=redactor.enabled,
        fields_considered=redactor.considered,
        fields_redacted=redactor.redacted,
        skipped_records=len(_skipped_keys(skipped)),
        skipped_examples=_skipped_keys(skipped)[:3],
    )
