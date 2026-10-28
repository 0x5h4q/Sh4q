"""Offline tests for pre-scan stage disclosure and dry-run planning.

No network requests are made. Tool availability is whatever happens to be
on PATH in the test environment; assertions about missing tools use an
empty PATH so tools are deterministically absent.
"""

import os
from pathlib import Path

from sh4q.application.stat_report import (
    plan_scan,
    resolve_stage_flags,
    render_dry_run,
    render_missing_tools,
    render_scan_plan,
    render_stage_table,
    StagePlan,
)
from sh4q.scope import ScopeDecision, ScopeStatus


def test_plan_scan_default_stages():
    """A plain scan runs the three native stages with no external tools."""
    plan = plan_scan(target="example.com")
    assert plan.target == "example.com"
    assert plan.dry_run is False
    assert plan.missing_tools == ()
    names = [s.name for s in plan.stages]
    assert "dns" in names
    assert "http" in names
    assert "ct" in names
    # All native stages report tool_on_path True (no tool required).
    for s in plan.stages:
        if s.required_tool is None:
            assert s.tool_on_path is True


def test_plan_scan_with_sub_flag():
    """--sub adds subfinder + discovered-dns + discovered-http."""
    plan = plan_scan(target="example.com", sub=True)
    names = [s.name for s in plan.stages]
    assert "subfinder" in names
    assert "discovered-dns" in names
    assert "discovered-http" in names
    subfinder = next(s for s in plan.stages if s.name == "subfinder")
    assert subfinder.required_tool == "subfinder"
    assert subfinder.risk_level == "external-controlled"
    assert subfinder.passive is False


def test_plan_scan_with_resolve_flag():
    """resolve stage adds discovered-dns + discovered-http but not subfinder."""
    plan = plan_scan(target="example.com", resolve=True)
    names = [s.name for s in plan.stages]
    assert "discovered-dns" in names
    assert "discovered-http" in names
    assert "subfinder" not in names


def test_plan_scan_web_profile():
    """--profile web implies resolve + js + js-bundles."""
    plan = plan_scan(target="example.com", profile="web")
    names = [s.name for s in plan.stages]
    assert "discovered-dns" in names
    assert "javascript-extraction" in names
    assert "javascript-bundles" in names
    assert "subfinder" not in names


def test_plan_scan_full_profile():
    """--profile full implies subfinder + httpx + url-history + web stages."""
    plan = plan_scan(target="example.com", profile="full")
    names = [s.name for s in plan.stages]
    assert "subfinder" in names
    assert "httpx-fingerprint" in names
    assert "url-history" in names
    assert "discovered-dns" in names
    assert "javascript-extraction" in names


def test_plan_scan_template_stages():
    """Template stages resolve to their internal plugin stages."""
    plan = plan_scan(target="example.com", sub=True, httpx=True, vhosts=True)
    names = [s.name for s in plan.stages]
    assert "subfinder" in names
    assert "httpx-fingerprint" in names
    assert "vhost-discovery" in names
    assert "discovered-dns" in names  # sub expands to it


def test_missing_tools_with_empty_path():
    """With PATH emptied, external tools are reported as missing."""
    old_path = os.environ.get("PATH")
    os.environ["PATH"] = ""
    try:
        plan = plan_scan(target="example.com", sub=True, httpx=True)
        assert "subfinder" in plan.missing_tools
        assert "httpx" in plan.missing_tools
    finally:
        if old_path is not None:
            os.environ["PATH"] = old_path
        else:
            os.environ.pop("PATH", None)


def test_missing_tools_empty_when_all_present():
    """If all required tools are on PATH, missing_tools is empty."""
    plan = plan_scan(target="example.com")  # native stages only
    assert plan.missing_tools == ()


def test_resolve_stage_flags_template_precedence():
    """Template stages set flags even when explicit flags differ."""
    flags = resolve_stage_flags(
        template_stages=("sub", "httpx"),
        sub=False,
        httpx=False,
    )
    assert flags["sub"] is True
    assert flags["httpx"] is True


def test_resolve_stage_flags_web_profile():
    flags = resolve_stage_flags(profile="web")
    assert flags["resolve"] is True
    assert flags["js"] is True
    assert flags["js_bundles"] is True
    assert flags["sub"] is False


def test_resolve_stage_flags_full_profile():
    flags = resolve_stage_flags(profile="full")
    assert flags["sub"] is True
    assert flags["httpx"] is True
    assert flags["url_history"] is True
    assert flags["resolve"] is True
    assert flags["js"] is True


def test_render_stage_table_headers():
    plans = (
        StagePlan("dns", "passive", None, True, "5s timeout", True),
        StagePlan("subfinder", "external-controlled", "subfinder", False, "enum", False),
    )
    output = render_stage_table(plans)
    assert "STAGE" in output
    assert "RISK" in output
    assert "TOOL" in output
    assert "PATH" in output
    assert "BOUND" in output
    assert "dns" in output
    assert "subfinder" in output
    assert "MISSING" in output  # subfinder tool not on path


def test_render_stage_table_passive_vs_active():
    plans = (
        StagePlan("dns", "passive", None, True, "b", True),
        StagePlan("http", "active-low", None, True, "b", False),
    )
    output = render_stage_table(plans)
    dns_line = [l for l in output.splitlines() if "dns" in l][0]
    http_line = [l for l in output.splitlines() if "http" in l][0]
    assert "passive" in dns_line
    assert "active-low" in http_line


def test_render_missing_tools():
    output = render_missing_tools(("subfinder", "katana"))
    assert "Scan cannot start" in output
    assert "subfinder" in output
    assert "katana" in output
    assert "Install:" in output


def test_render_missing_tools_empty():
    assert render_missing_tools(()) == ""


def test_render_dry_run_allow():
    from sh4q.scope import ScopeDecision, ScopeStatus
    decision = ScopeDecision(ScopeStatus.ALLOW, "authorized")
    plan = plan_scan(target="example.com", dry_run=True)
    output = render_dry_run(plan, decision)
    assert "SH4Q DRY RUN" in output
    assert "Gate 1   ALLOW" in output
    assert "example.com" in output
    assert "No network requests were made" in output


def test_render_dry_run_deny():
    decision = ScopeDecision(ScopeStatus.DENY, "target is not in the allowed target list")
    plan = plan_scan(target="evil.example", dry_run=True)
    output = render_dry_run(plan, decision)
    assert "DENY" in output
    assert "Dry run aborted" in output
    assert "No network requests were made" not in output


def test_render_scan_plan_includes_budget():
    plan = plan_scan(target="example.com")
    output = render_scan_plan(plan)
    assert "Request budget" in output
    assert "1000" in output


def test_plan_scan_request_budget():
    plan = plan_scan(target="example.com")
    assert plan.request_budget == 1000


if __name__ == "__main__":
    import sys

    tests = [
        test_plan_scan_default_stages,
        test_plan_scan_with_sub_flag,
        test_plan_scan_with_resolve_flag,
        test_plan_scan_web_profile,
        test_plan_scan_full_profile,
        test_plan_scan_template_stages,
        test_missing_tools_with_empty_path,
        test_missing_tools_empty_when_all_present,
        test_resolve_stage_flags_template_precedence,
        test_resolve_stage_flags_web_profile,
        test_resolve_stage_flags_full_profile,
        test_render_stage_table_headers,
        test_render_stage_table_passive_vs_active,
        test_render_missing_tools,
        test_render_missing_tools_empty,
        test_render_dry_run_allow,
        test_render_dry_run_deny,
        test_render_scan_plan_includes_budget,
        test_plan_scan_request_budget,
    ]
    failed = 0
    for test in tests:
        try:
            test()
            print(f"PASS  {test.__name__}")
        except Exception as error:  # noqa: BLE001
            failed += 1
            print(f"FAIL  {test.__name__}: {error}")
    print()
    if failed:
        print(f"{failed} test(s) failed")
        sys.exit(1)
    print(f"stat report test passed ({len(tests)} checks)")
