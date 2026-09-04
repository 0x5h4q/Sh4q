
import argparse
import asyncio
import json
import csv
import json
import csv
import shutil
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from sh4q.application import run_scan
from sh4q.adapters import AdapterExecutionError
from sh4q.events.event_log import DurableEventLog
from sh4q.storage.scan_runs import get_scan, latest_scan, list_scans, scan_asset_count
from sh4q.application.results import friendly_technology_source, list_assets, list_failures, list_technology_observations, summarize_technology_observations
from sh4q.application.exporter import ScanOwnershipUnavailableError, export_scan
from sh4q.application.scan_report import build_scan_report
from sh4q.application.diff import build_scan_diff, diff_document
from sh4q.storage.db import SchemaVersionError, ensure_schema_version
from sh4q.cli.branding import render_scan_banner


def _fit(value: object, width: int) -> str:
    text = str(value if value not in (None, "") else "-")
    if len(text) <= width:
        return text
    return text[: max(1, width - 3)] + "..."


def _terminal_is_narrow(minimum_width: int) -> bool:
    return sys.stdout.isatty() and shutil.get_terminal_size((80, 24)).columns < minimum_width


def _narrow_value(value: object, indent: int = 4) -> str:
    width = max(20, shutil.get_terminal_size((80, 24)).columns - indent)
    return _fit(value, width)


def render_technology_results(rows) -> None:
    if _terminal_is_narrow(100):
        print()
        for row in rows:
            technology = f"{row.technology} {row.version}".strip()
            print(f"  {_narrow_value(row.endpoint, 2)}")
            print(f"    Technology  {technology}")
            print(f"    Category    {row.category}")
            print(f"    Confidence  {row.confidence}")
            print(f"    Source      {friendly_technology_source(row.source)}")
            print(f"    Status      {row.status}")
            print(f"    Signal      {_narrow_value(row.signal, 16)}")
        return
    columns = (
        ("ENDPOINT", 44),
        ("TECHNOLOGY", 16),
        ("CATEGORY", 14),
        ("CONFIDENCE", 10),
        ("SOURCE", 18),
        ("STATUS", 6),
        ("SIGNAL", 34),
    )
    header = "  " + "  ".join(label.ljust(width) for label, width in columns)
    print()
    print(header)
    print("  " + "  ".join("-" * width for _, width in columns))
    for row in rows:
        technology = f"{row.technology} {row.version}".strip()
        values = (
            row.endpoint,
            technology,
            row.category,
            row.confidence,
            friendly_technology_source(row.source),
            row.status,
            row.signal,
        )
        print(
            "  "
            + "  ".join(
                _fit(value, width).ljust(width)
                for value, (_, width) in zip(values, columns)
            )
        )


def render_technology_summary(rows) -> None:
    columns = (("TECHNOLOGY", 24), ("VERSION", 14), ("CATEGORY", 20), ("SOURCE", 12), ("ENDPOINTS", 9))
    print()
    print("  " + "  ".join(label.ljust(width) for label, width in columns))
    print("  " + "  ".join("-" * width for _, width in columns))
    for row in rows:
        values = (row.technology, row.version, row.category, row.source, row.endpoints)
        print("  " + "  ".join(_fit(value, width).ljust(width) for value, (_, width) in zip(values, columns)))


def render_asset_results(rows) -> None:
    columns = (("TYPE", 10), ("VALUE", 64))
    print()
    print("  " + "  ".join(label.ljust(width) for label, width in columns))
    print("  " + "  ".join("-" * width for _, width in columns))
    for row in rows:
        print(
            "  "
            + "  ".join(
                _fit(value, width).ljust(width)
                for value, (_, width) in zip((row.type, row.value), columns)
            )
        )


def render_event_results(records) -> None:
    if _terminal_is_narrow(120):
        for record in records:
            print(f"  {record.status}  {record.source_plugin or '-'}  {record.discovery_kind or record.type}  attempts={record.attempts}")
            print(f"    Target    {_narrow_value(record.target or '-', 14)}")
            print(f"    Event ID  {_narrow_value(record.id, 14)}")
            if record.error:
                print(f"    Error     {_narrow_value(record.error, 14)}")
        return
    columns = (("STATUS", 12), ("SOURCE", 18), ("KIND", 24), ("TARGET", 28), ("ATTEMPTS", 8), ("EVENT ID", 32))
    print("  " + "  ".join(label.ljust(width) for label, width in columns))
    print("  " + "  ".join("-" * width for _, width in columns))
    for record in records:
        values = (record.status, record.source_plugin or "-", record.discovery_kind or record.type, record.target or "-", record.attempts, record.id)
        print("  " + "  ".join(_fit(value, width).ljust(width) for value, (_, width) in zip(values, columns)))
        if record.error:
            print(f"    error: {_fit(record.error, 100)}")


def render_event_summary(rows) -> None:
    if _terminal_is_narrow(100):
        for row in rows:
            print(f"  {row.status}  {row.source_plugin or '-'}  count={row.count}  retried={row.retried}")
            print(f"    Kind    {_narrow_value(row.discovery_kind, 12)}")
            print(f"    Target  {_narrow_value(row.target or '-', 12)}")
        return
    columns = (("STATUS", 12), ("SOURCE", 18), ("KIND", 24), ("TARGET", 28), ("COUNT", 7), ("RETRIED", 7))
    print("  " + "  ".join(label.ljust(width) for label, width in columns))
    print("  " + "  ".join("-" * width for _, width in columns))
    for row in rows:
        values = (row.status, row.source_plugin or "-", row.discovery_kind, row.target or "-", row.count, row.retried)
        print("  " + "  ".join(_fit(value, width).ljust(width) for value, (_, width) in zip(values, columns)))


def render_scan_runs(rows) -> None:
    if _terminal_is_narrow(100):
        for run, assets in rows:
            print(f"  {run.status}  {_narrow_value(run.target, 28)}  assets={assets}")
            print(f"    Started  {_narrow_value(run.started_at, 14)}")
            print(f"    Scan ID  {_narrow_value(run.id, 14)}")
        return
    columns = (("STATUS", 12), ("ASSETS", 7), ("TARGET", 34), ("STARTED", 22), ("SCAN ID", 32))
    print("  " + "  ".join(label.ljust(width) for label, width in columns))
    print("  " + "  ".join("-" * width for _, width in columns))
    for run, assets in rows:
        values = (run.status, assets, run.target, run.started_at, run.id)
        print("  " + "  ".join(_fit(value, width).ljust(width) for value, (_, width) in zip(values, columns)))


def render_failure_results(rows) -> None:
    if _terminal_is_narrow(100):
        for plugin, kind, content in rows:
            print(f"  {plugin}  {kind}")
            print(f"    {_narrow_value(content, 4)}")
        return
    columns = (("PLUGIN", 18), ("KIND", 24), ("DETAIL", 72))
    print("  " + "  ".join(label.ljust(width) for label, width in columns))
    print("  " + "  ".join("-" * width for _, width in columns))
    for row in rows:
        print("  " + "  ".join(_fit(value, width).ljust(width) for value, (_, width) in zip(row, columns)))


def render_metrics(title: str, rows) -> None:
    print(f"\n  {title}")
    print("  " + "-" * len(title))
    print("  METRIC                         VALUE")
    print("  -----------------------------  ----------")
    for label, value in rows:
        print(f"  {_fit(label, 29):<29}  {value:>10}")


def render_identity() -> None:
    if sys.stdout.isatty():
        print("\n" + render_scan_banner(colored=True))
def render_scan_report(report) -> None:
    run = report.run
    observed = report.request_metrics.get("observed", {})
    configured = report.request_metrics.get("configured", {})
    duration = report.request_metrics.get("duration_seconds")
    print("\n  SH4Q SCAN OVERVIEW")
    print("  ==================")
    print(f"  Target       {_narrow_value(run.target, 14) if _terminal_is_narrow(100) else run.target}")
    print(f"  Scan ID      {_narrow_value(run.id, 14) if _terminal_is_narrow(100) else run.id}")
    print(f"  Status       {run.status}")
    print(f"  Started      {_narrow_value(run.started_at, 14) if _terminal_is_narrow(100) else run.started_at}")
    print(f"  Completed    {_narrow_value(run.completed_at or '-', 14) if _terminal_is_narrow(100) else run.completed_at or '-'}")
    if duration is not None:
        print(f"  Duration     {duration:.2f}s")

    print("\n  Verified Surface")
    print(f"    DNS hostnames          {report.dns_hostnames:>6}")
    print(f"    DNS addresses          {report.dns_addresses:>6}")
    print(f"    HTTP hosts             {report.http_hosts:>6}")
    print(f"    HTTP endpoints         {report.http_endpoints:>6}")
    print(f"    Historical URLs        {getattr(report, 'historical_urls', 0):>6}")
    print(f"    Technologies           {report.technology_assets:>6}")
    print(f"    Tech observations      {report.technology_observations:>6}")

    print("\n  Stored Record")
    print(f"    Unique assets          {sum(report.asset_types.values()):>6}")
    print(f"    Relationships          {report.relationships:>6}")
    print(f"    Evidence               {report.evidence:>6}")
    if report.source_assets:
        print("    Owned assets by source")
        for source, count in sorted(report.source_assets.items()):
            print(f"      {source:<18} {count:>6}")

    print("\n  Failures")
    print(f"    HTTP                    {report.http_failures:>6}")
    print(f"    DNS                     {sum(report.dns_failures.values()):>6}")
    for reason, count in sorted(report.dns_failures.items()):
        print(f"      {reason:<18} {count:>6}")

    if observed:
        print("\n  Native Requests")
        print(f"    Admitted                {observed.get('admitted', 0):>6}")
        print(f"    Completed               {observed.get('completed', 0):>6}")
        print(f"    Failed                  {observed.get('failed', 0):>6}")
        print(f"    Budget denied           {observed.get('budget_denied', 0):>6}")
        print(f"    Peak concurrent         {observed.get('peak_concurrency', 0):>6}")
        print(
            f"    Limits                  {configured.get('requests_per_second', '-')} req/s, "
            f"{configured.get('max_concurrent', '-')} concurrent, budget {configured.get('budget', '-')}"
        )
    if report.external_adapter_metrics:
        metrics = report.external_adapter_metrics
        print("\n  External Adapter Requests")
        print(f"    Adapter                 {metrics.get('adapter', '-')}")
        print(f"    Input endpoints         {metrics.get('input_endpoints', 0):>6}")
        print(f"    Reported responses      {metrics.get('reported_responses', 0):>6}")
        print(f"    Unreported endpoints    {metrics.get('unreported_endpoints', 0):>6}")
        print(f"    Tool processes          {metrics.get('tool_processes', 0):>6}")
    if report.stages:
        print("\n  Stages")
        print("    NAME                STATUS               ATTEMPTS  FINDINGS  DURATION")
        print("    ------------------  -------------------  --------  --------  --------")
        for stage in report.stages:
            print(
                f"    {_fit(stage.get('name'), 18):<18}  "
                f"{_fit(stage.get('status'), 19):<19}  "
                f"{stage.get('attempts', 0):>8}  "
                f"{stage.get('discoveries', 0):>8}  "
                f"{stage.get('duration_seconds', 0):>7.2f}s"
            )
    print()
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sh4q",
        description="Sh4q (*_*)/ - policy-controlled reconnaissance with evidence and scope checks.",
    )
    try:
        package_version = version("sh4q")
    except PackageNotFoundError:
        package_version = "development"
    parser.add_argument("--version", action="version", version=f"sh4q {package_version}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan a target")
    scan.add_argument("target", help="Hostname to scan, e.g. example.com")
    scan.add_argument(
        "--config",
        default=None,
        help="Path to a YAML config file. If omitted, scope defaults to just the target itself (and its subdomains) on ports 80/443.",
    )
    scan.add_argument(
        "--sub",
        action="store_true",
        help="Run the optional passive Subfinder adapter.",
    )
    scan.add_argument(
        "--httpx",
        action="store_true",
        help="Run optional httpx technology enrichment on approved HTTP endpoints.",
    )
    scan.add_argument(
        "--amass",
        action="store_true",
        help="Run experimental Amass passive discovery (bounded to 20 seconds).",
    )
    scan.add_argument(
        "--url-history",
        action="store_true",
        help="Run the opt-in passive Wayback URL-history adapter.",
    )
    scan.add_argument(
        "--javascript",
        action="store_true",
        help="Run bounded passive extraction on authorised HTTP response samples.",
    )

    events = subparsers.add_parser("events", help="Inspect durable event state")
    events.add_argument(
        "--database",
        default="./sh4q-output/sh4q.db",
        help="Path to the Sh4q SQLite database.",
    )
    events.add_argument(
        "--status",
        choices=["PENDING", "PROCESSING", "FAILED", "DEAD_LETTER", "COMPLETED"],
        help="Show only events with this status.",
    )
    events.add_argument("--limit", type=int, default=25)
    events.add_argument("--target", help="Filter events by scan target.")
    events.add_argument("--details", action="store_true", help="Show individual durable event records and IDs")

    results = subparsers.add_parser("results", help="View stored assets without writing SQL")
    results.add_argument("--database", default="./sh4q-output/sh4q.db")
    results.add_argument("--type", choices=["domain", "ip", "url", "technology"])
    results.add_argument("--limit", type=int, default=100)
    results.add_argument("--failures", action="store_true", help="Show recorded errors and provider failures")
    results.add_argument("--target", help="Filter assets or failures by root target")
    results.add_argument("--source", help="Filter results by source plugin")
    results.add_argument("--category", help="Filter technology observations by category")
    results.add_argument("--status", type=int, help="Filter technology observations by HTTP status")
    results.add_argument("--details", action="store_true", help="Show endpoint-level technology observations")
    scan_selection = results.add_mutually_exclusive_group()
    scan_selection.add_argument("--scan", help="Show assets observed in one scan run")
    scan_selection.add_argument("--latest", action="store_true", help="Show the latest recorded scan")

    scans = subparsers.add_parser("scans", help="List recorded scan runs")
    scans.add_argument("--database", default="./sh4q-output/sh4q.db")
    scans.add_argument("--limit", type=int, default=50)

    show = subparsers.add_parser("show", help="Show a persisted overview of one scan")
    show.add_argument("--database", default="./sh4q-output/sh4q.db")
    show.add_argument("--target", help="Select the latest completed scan for this target")
    show_selection = show.add_mutually_exclusive_group()
    show_selection.add_argument("--scan", help="Show one scan run ID")
    show_selection.add_argument("--latest", action="store_true", help="Show the latest completed scan")

    export = subparsers.add_parser("export", help="Export one scan to JSON or CSV")
    export.add_argument("--database", default="./sh4q-output/sh4q.db")
    export.add_argument("--format", choices=["json", "csv", "html"], required=True)
    export.add_argument("--output", type=Path, required=True)
    export.add_argument("--target", help="Select the latest scan for this target")
    export_selection = export.add_mutually_exclusive_group(required=True)
    export_selection.add_argument("--scan", help="Export one scan run ID")
    export_selection.add_argument("--latest", action="store_true", help="Export the latest scan")
    export.add_argument("--force", action="store_true", help="Overwrite an existing output file")
    export.add_argument("--redact", action="store_true", help="Redact URL query values in the exported report")
    export.add_argument("--alive", choices=["http", "dns"], help="Export only domains with observed HTTP or DNS liveness evidence")
    export.add_argument(
        "--type",
        choices=["technology", "http-inventory"],
        help="Export a structured technology or combined HTTP inventory view",
    )

    diff = subparsers.add_parser("diff", help="Compare scan-owned assets between two scans")
    diff.add_argument("--database", default="./sh4q-output/sh4q.db")
    diff.add_argument("--before", required=True, help="Earlier scan run ID")
    diff.add_argument("--after", required=True, help="Later scan run ID")
    diff.add_argument("--format", choices=["text", "json", "csv"], default="text")

    return parser


def render_summary(summary) -> None:
    print()
    print("  SH4Q SCAN SUMMARY")
    print("  =================")
    print(f"  Target   {summary.target}")
    print(f"  Scan ID  {summary.scan_run_id}")

    if not summary.scope_allowed:
        print(f"  Scope    DENIED - {summary.scope_reason}")
        print()
        print("  Scan did not run: target is not authorized.")
        print()
        return

    print("  Scope    AUTHORIZED")
    if summary.recovered_events:
        print(f"  Resume   recovered {summary.recovered_events} event(s)")
    asset_rows = [
        ("DNS addresses", summary.dns_addresses),
        ("HTTP endpoints", summary.http_endpoints),
        ("CT names", summary.ct_names),
        ("Adapter names", summary.adapter_names),
        ("Resolved names", summary.resolved_discovered_addresses),
        ("DNS failures", summary.resolved_discovered_failures),
    ]
    for reason, count in sorted(summary.dns_failure_reasons.items()):
        asset_rows.append((f"DNS failure: {reason}", count))
    asset_rows.extend([
        ("Technologies", summary.technologies),
        ("Historical URLs", getattr(summary, "historical_urls", 0)),
        ("Historical URLs rejected", getattr(summary, "historical_urls_rejected", 0)),
        ("Historical URLs truncated", getattr(summary, "historical_urls_truncated", 0)),
        ("Total unique assets", summary.discoveries),
        ("Asset links (relationships)", summary.relationships),
        ("Evidence from this scan", summary.evidence_this_scan),
        ("Evidence stored", summary.evidence),
    ])
    render_metrics("Inventory", asset_rows)
    render_metrics("Network Requests", [
        ("Admitted (native)", summary.requests_admitted),
        ("Budget denied", summary.requests_denied),
        ("Completed", summary.requests_completed),
        ("Failed", summary.requests_failed),
        ("Peak concurrent", summary.peak_request_concurrency),
    ])
    if summary.stage_durations:
        print("\n  Stage Durations")
        print("  ---------------")
        print("  STAGE                         DURATION")
        print("  ----------------------------  ----------")
        for stage, duration in summary.stage_durations.items():
            print(f"  {_fit(stage, 28):<28}  {duration:>9.2f}s")
    print(f"\n  Duration  {summary.duration_seconds:.2f}s")
    database = _narrow_value(summary.database_path, 12) if _terminal_is_narrow(100) else summary.database_path
    print(f"  Database  {database}")
    print()
    print("  Scan complete.")
    print()


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "results" and any(
        value is not None for value in (args.category, args.status)
    ) and args.type != "technology":
        parser.error("--category and --status require --type technology")

    if args.command != "scan" and hasattr(args, "database"):
        database = Path(args.database)
        if database.exists():
            try:
                ensure_schema_version(str(database))
            except (SchemaVersionError, ValueError) as error:
                parser.error(str(error))

    if args.command == "scan":
        render_identity()
        try:
            summary = asyncio.run(
                run_scan(
                    args.target,
                    args.config,
                    include_subfinder=args.sub,
                    include_amass=args.amass,
                    include_httpx=args.httpx,
                    include_url_history=args.url_history,
                    include_javascript=args.javascript,
                )
            )
        except KeyboardInterrupt:
            print()
            print("  Scan interrupted by user.")
            print("  Unfinished durable events will be recovered on the next scan.")
            print()
            sys.exit(130)
        except (AdapterExecutionError, SchemaVersionError) as error:
            print(f"  Scan could not start: {error}")
            sys.exit(2)
        render_summary(summary)
        sys.exit(0 if summary.scope_allowed else 1)

    if args.command == "diff":
        before_run = get_scan(args.database, args.before)
        after_run = get_scan(args.database, args.after)
        if before_run is None or after_run is None:
            parser.error("both scan IDs must exist")
        if before_run.target != after_run.target:
            parser.error("scan diff requires both scans to have the same target")
        result = build_scan_diff(args.database, args.before, args.after)
        if args.format == "json":
            print(json.dumps(diff_document(result), indent=2, sort_keys=True))
            sys.exit(0)
        if args.format == "csv":
            writer = csv.writer(sys.stdout)
            writer.writerow(("change", "kind", "from", "type", "to", "value"))
            for change, rows in (("added", result.added_assets), ("removed", result.removed_assets)):
                for item in rows:
                    writer.writerow((change, "asset", "", item["type"], "", item["value"]))
            for change, rows in (("added", result.added_relationships), ("removed", result.removed_relationships)):
                for item in rows:
                    writer.writerow((change, "relationship", item["from"], item["type"], item["to"], ""))
            sys.exit(0)
        print(f"\n  SH4Q SCAN DIFF\n  ==============\n  Before  {result.before}\n  After   {result.after}")
        print(f"\n  Added assets          {len(result.added_assets)}")
        print(f"  Removed assets        {len(result.removed_assets)}")
        print(f"  Added relationships   {len(result.added_relationships)}")
        print(f"  Removed relationships {len(result.removed_relationships)}")
        for label, rows in (("Added assets", result.added_assets), ("Removed assets", result.removed_assets)):
            if rows:
                print(f"\n  {label}")
                for item in rows[:100]:
                    print(f"    {item['type']:<14} {item['value']}")
        sys.exit(0)

    if args.command == "events":
        database = Path(args.database)
        if not database.exists():
            parser.error(f"database not found: {database}")
        event_log = DurableEventLog(str(database))
        print()
        print("  SH4Q EVENT LOG")
        print("  ===============")
        if args.details:
            records = asyncio.run(event_log.list_records(status=args.status, target=args.target, limit=args.limit))
            if not records:
                print("  No matching events.")
            else:
                render_event_results(records)
        else:
            rows = asyncio.run(event_log.summarize(status=args.status, target=args.target, limit=args.limit))
            if not rows:
                print("  No matching events.")
            else:
                render_event_summary(rows)
                print("\n  Use --details to inspect individual durable records and event IDs.")
        print()
        return

    if args.command == "results":
        database = Path(args.database)
        if not database.exists():
            parser.error(f"database not found: {database}")
        print()
        print("  SH4Q RESULTS")
        print("  ============")
        if args.failures:
            scan_id = args.scan
            if args.latest:
                latest = latest_scan(str(database), args.target)
                if latest is None:
                    print("  No recorded scan run matches this query.\n")
                    return
                scan_id = latest.id
                print(f"  Scan     {latest.id} ({latest.target})")
            rows = list_failures(
                str(database), target=args.target, scan_id=scan_id, limit=args.limit
            )
            if not rows:
                print("  No recorded failures.")
            else:
                render_failure_results(rows)
                print(f"\n  Showing {len(rows)} failure record(s). Use --limit to increase the view.")
        else:
            scan_id = args.scan
            if args.latest:
                latest = latest_scan(str(database), args.target)
                if latest is None:
                    print("  No recorded scan run matches this query.\n")
                    return
                scan_id = latest.id
                print(f"  Scan     {latest.id} ({latest.target})")
            if args.type == "technology":
                rows = list_technology_observations(
                    str(database), target=args.target, scan_id=scan_id,
                    source=args.source, category=args.category, status=args.status,
                    limit=args.limit if args.details else None,
                )
                if args.details:
                    render_technology_results(rows)
                    print(f"\n  Showing {len(rows)} technology observation(s). Use --limit to increase the view.")
                else:
                    summaries = summarize_technology_observations(rows)[: max(1, min(args.limit, 1000))]
                    render_technology_summary(summaries)
                    print(f"\n  Showing {len(summaries)} technology group(s). Use --details for endpoints.")
            else:
                rows = list_assets(
                    str(database), asset_type=args.type, target=args.target,
                    scan_id=scan_id, source=args.source, limit=args.limit
                )
                render_asset_results(rows)
                print(f"\n  Showing {len(rows)} asset(s). Use --limit to increase the view.")
        print()
        return

    if args.command == "show":
        database = Path(args.database)
        if not database.exists():
            parser.error(f"database not found: {database}")
        run = get_scan(str(database), args.scan) if args.scan else latest_scan(
            str(database), args.target
        )
        if run is None:
            parser.error("no matching scan run was found")
        render_scan_report(build_scan_report(str(database), run))
        return

    if args.command == "scans":
        database = Path(args.database)
        if not database.exists():
            parser.error(f"database not found: {database}")
        print("\n  SH4Q SCAN RUNS\n  ============== ")
        runs = list_scans(str(database), args.limit)
        render_scan_runs([(run, scan_asset_count(str(database), run.id)) for run in runs])
        print()
        return

    if args.command == "export":
        database = Path(args.database)
        if not database.exists():
            parser.error(f"database not found: {database}")
        run = get_scan(str(database), args.scan) if args.scan else latest_scan(
            str(database), args.target
        )
        if run is None:
            parser.error("no matching scan run was found")
        if args.alive and args.type:
            parser.error("--alive and --type cannot be combined")
        try:
            count = export_scan(
                str(database), run, format=args.format, output=args.output,
                force=args.force, alive=args.alive, asset_type=args.type, redact=args.redact
            )
        except FileExistsError as error:
            parser.error(f"{error}; pass --force to overwrite it")
        except ScanOwnershipUnavailableError as error:
            parser.error(f"{error}; run a new scan before exporting exact assets")
        print(f"\n  Exported {count} asset(s) from scan {run.id} to {args.output}\n")
        return


if __name__ == "__main__":
    main()
