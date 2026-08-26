
import argparse
import asyncio
import sys

from sh4q.application import run_scan


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

    return parser


def render_summary(summary) -> None:
    print()
    print("  SH4Q SCAN SUMMARY")
    print("  =================")
    print(f"  Target   {summary.target}")

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
    print(f"    Total           {summary.discoveries:>5}")
    print()
    print(f"  Relationships     {summary.relationships:>5}")
    print(f"  Evidence          {summary.evidence:>5}")
    print(f"  Duration       {summary.duration_seconds:>8.2f}s")
    print(f"  Database       {summary.database_path}")
    print()
    print("  Scan complete.")
    print()


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        summary = asyncio.run(run_scan(args.target, args.config))
        render_summary(summary)
        sys.exit(0 if summary.scope_allowed else 1)


if __name__ == "__main__":
    main()
