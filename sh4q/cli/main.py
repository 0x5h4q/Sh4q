
import argparse
import asyncio
import sys
from pathlib import Path

from sh4q.application import run_scan
from sh4q.adapters import AdapterExecutionError
from sh4q.events.event_log import DurableEventLog
from sh4q.storage.scan_runs import get_scan, latest_scan, list_scans, scan_asset_count
from sh4q.application.results import list_assets, list_failures
from sh4q.application.exporter import ScanOwnershipUnavailableError, export_scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sh4q", description="Sh4q —> Your very own scope-aware recon engine ('_')/")
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

    results = subparsers.add_parser("results", help="View stored assets without writing SQL")
    results.add_argument("--database", default="./sh4q-output/sh4q.db")
    results.add_argument("--type", choices=["domain", "ip", "url"])
    results.add_argument("--limit", type=int, default=100)
    results.add_argument("--failures", action="store_true", help="Show recorded errors and provider failures")
    results.add_argument("--target", help="Filter assets or failures by root target")
    scan_selection = results.add_mutually_exclusive_group()
    scan_selection.add_argument("--scan", help="Show assets observed in one scan run")
    scan_selection.add_argument("--latest", action="store_true", help="Show the latest recorded scan")

    scans = subparsers.add_parser("scans", help="List recorded scan runs")
    scans.add_argument("--database", default="./sh4q-output/sh4q.db")
    scans.add_argument("--limit", type=int, default=50)

    export = subparsers.add_parser("export", help="Export one scan to JSON or CSV")
    export.add_argument("--database", default="./sh4q-output/sh4q.db")
    export.add_argument("--format", choices=["json", "csv"], required=True)
    export.add_argument("--output", type=Path, required=True)
    export.add_argument("--target", help="Select the latest scan for this target")
    export_selection = export.add_mutually_exclusive_group(required=True)
    export_selection.add_argument("--scan", help="Export one scan run ID")
    export_selection.add_argument("--latest", action="store_true", help="Export the latest scan")
    export.add_argument("--force", action="store_true", help="Overwrite an existing output file")
    export.add_argument("--alive", choices=["http", "dns"], help="Export only domains with observed HTTP or DNS liveness evidence")

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
    print()
    print("  Assets")
    print(f"    DNS addresses   {summary.dns_addresses:>5}")
    print(f"    HTTP endpoints  {summary.http_endpoints:>5}")
    print(f"    CT names        {summary.ct_names:>5}")
    print(f"    Adapter names   {summary.adapter_names:>5}")
    print(f"    Resolved names  {summary.resolved_discovered_addresses:>5}")
    print(f"    DNS failures    {summary.resolved_discovered_failures:>5}")
    print(f"    Total           {summary.discoveries:>5}")
    print()
    print(f"  Relationships     {summary.relationships:>5}")
    print(f"  Evidence (scan)   {summary.evidence_this_scan:>5}")
    print(f"  Evidence (stored)  {summary.evidence:>5}")
    print()
    print("  Network requests")
    print(f"    Admitted (native) {summary.requests_admitted:>4}")
    print(f"    Budget denied    {summary.requests_denied:>5}")
    print(f"    Completed        {summary.requests_completed:>5}")
    print(f"    Failed           {summary.requests_failed:>5}")
    print(f"    Peak concurrent  {summary.peak_request_concurrency:>5}")
    if summary.stage_durations:
        print()
        print("  Stage durations")
        for stage, duration in summary.stage_durations.items():
            print(f"    {stage:<18} {duration:>8.2f}s")
    print(f"  Duration       {summary.duration_seconds:>8.2f}s")
    print(f"  Database       {summary.database_path}")
    print()
    print("  Scan complete.")
    print()


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        try:
            summary = asyncio.run(
                run_scan(args.target, args.config, include_subfinder=args.sub)
            )
        except KeyboardInterrupt:
            print()
            print("  Scan interrupted by user.")
            print("  Unfinished durable events will be recovered on the next scan.")
            print()
            sys.exit(130)
        except AdapterExecutionError as error:
            print(f"  Scan could not start: {error}")
            sys.exit(2)
        render_summary(summary)
        sys.exit(0 if summary.scope_allowed else 1)

    if args.command == "events":
        database = Path(args.database)
        if not database.exists():
            parser.error(f"database not found: {database}")
        records = asyncio.run(
            DurableEventLog(str(database)).list_records(
                status=args.status,
                target=args.target,
                limit=args.limit,
            )
        )
        print()
        print("  SH4Q EVENT LOG")
        print("  ===============")
        if not records:
            print("  No matching events.")
        for record in records:
            print(
                f"  {record.status:<11} {record.type:<12} "
                f"event-attempts={record.attempts:<2} {record.target or '-':<30} {record.id}"
            )
            if record.error:
                print(f"    error: {record.error}")
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
            rows = list_failures(str(database), target=args.target, limit=args.limit)
            for plugin, kind, content in rows:
                print(f"  {plugin:<14} {kind:<24} {content}")
            if not rows:
                print("  No recorded failures.")
        else:
            scan_id = args.scan
            if args.latest:
                latest = latest_scan(str(database), args.target)
                if latest is None:
                    print("  No recorded scan run matches this query.\n")
                    return
                scan_id = latest.id
                print(f"  Scan     {latest.id} ({latest.target})")
            rows = list_assets(
                str(database), asset_type=args.type, target=args.target,
                scan_id=scan_id, limit=args.limit
            )
            for row in rows:
                print(f"  {row.type:<8} {row.value}")
            print(f"\n  Showing {len(rows)} asset(s). Use --limit to increase the view.")
        print()
        return

    if args.command == "scans":
        database = Path(args.database)
        if not database.exists():
            parser.error(f"database not found: {database}")
        print("\n  SH4Q SCAN RUNS\n  ============== ")
        for run in list_scans(str(database), args.limit):
            assets = scan_asset_count(str(database), run.id)
            print(
                f"  {run.status:<11} assets={assets:<5} {run.target:<35} "
                f"{run.started_at}  {run.id}"
            )
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
        try:
            count = export_scan(
                str(database), run, format=args.format, output=args.output, force=args.force, alive=args.alive
            )
        except FileExistsError as error:
            parser.error(f"{error}; pass --force to overwrite it")
        except ScanOwnershipUnavailableError as error:
            parser.error(f"{error}; run a new scan before exporting exact assets")
        print(f"\n  Exported {count} asset(s) from scan {run.id} to {args.output}\n")
        return


if __name__ == "__main__":
    main()
