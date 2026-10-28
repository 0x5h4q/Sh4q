"""Pre-scan stage disclosure and dry-run planning.

Answers "what will this run do before it does it" by resolving the stage
set, reporting per-stage risk level, required external tools (and whether
they are on PATH), and effective bounds. A dry-run performs Gate 1 and
prints the resolved scope, stage list, request budget, and planned
third-party disclosures without making a single network request.

The stage bounds below mirror the defaults in ``sh4q/config/schema.py``
so the disclosure matches what the scan will actually enforce.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sh4q.application.disclosure import planned_disclosures
from sh4q.config.schema import (
    DEFAULT_CT_SOURCES,
    EnrichmentConfig,
    HttpxAdapterConfig,
    RateLimitConfig,
    TimeoutConfig,
)
from sh4q.dependencies import dependency_reports, required_dependencies


# ---------------------------------------------------------------------------
# Defaults, pulled from the config schema so disclosure matches enforcement.
# ---------------------------------------------------------------------------

_DEFAULT_RATE = RateLimitConfig()
_DEFAULT_ENRICHMENT = EnrichmentConfig()
_DEFAULT_HTTPS = HttpxAdapterConfig()
_DEFAULT_TIMEOUT = TimeoutConfig()


def _tool_on_path(executable: str) -> bool:
    """Whether an external tool executable is present on PATH."""
    for report in dependency_reports():
        if report.dependency.name == executable:
            return report.path is not None
    return False


# ---------------------------------------------------------------------------
# Stage registry: one entry per plugin stage that can run in a scan.
#
# ``bound`` describes the effective limit the stage operates under.
# ``passive`` is True for passive stages (no traffic beyond authorised
# observation) and False for active-low / external-controlled stages.
# ---------------------------------------------------------------------------

_STAGE_REGISTRY: dict[str, dict] = {
    "dns": {
        "name": "dns",
        "risk_level": "passive",
        "required_tool": None,
        "bound": (
            f"certificate transparency + resolution, "
            f"{_DEFAULT_TIMEOUT.dns_seconds}s timeout"
        ),
        "passive": True,
    },
    "http": {
        "name": "http",
        "risk_level": "active-low",
        "required_tool": None,
        "bound": (
            f"HTTP probe on authorised ports, "
            f"{_DEFAULT_TIMEOUT.http_seconds}s timeout"
        ),
        "passive": False,
    },
    "ct": {
        "name": "ct",
        "risk_level": "passive",
        "required_tool": None,
        "bound": (
            f"certificate transparency query, "
            f"{_DEFAULT_TIMEOUT.dns_seconds}s timeout"
        ),
        "passive": True,
    },
    "subfinder": {
        "name": "subfinder",
        "risk_level": "external-controlled",
        "required_tool": "subfinder",
        "bound": (
            f"subdomain enumeration, up to "
            f"{_DEFAULT_ENRICHMENT.max_names_resolved} names resolved"
        ),
        "passive": False,
    },
    "discovered-dns": {
        "name": "discovered-dns",
        "risk_level": "passive",
        "required_tool": None,
        "bound": (
            f"resolve up to {_DEFAULT_ENRICHMENT.max_names_resolved} "
            f"discovered names"
        ),
        "passive": True,
    },
    "discovered-http": {
        "name": "discovered-http",
        "risk_level": "active-low",
        "required_tool": None,
        "bound": (
            f"probe up to {_DEFAULT_ENRICHMENT.max_hosts_probed} hosts "
            f"at {_DEFAULT_RATE.requests_per_second:g} req/s"
        ),
        "passive": False,
    },
    "httpx-fingerprint": {
        "name": "httpx-fingerprint",
        "risk_level": "external-controlled",
        "required_tool": "httpx",
        "bound": (
            f"fingerprint up to {_DEFAULT_HTTPS.max_endpoints} endpoints"
        ),
        "passive": False,
    },
    "url-history": {
        "name": "url-history",
        "risk_level": "external-controlled",
        "required_tool": "waybackurls",
        "bound": (
            f"retain up to {_DEFAULT_ENRICHMENT.max_historical_urls} "
            f"historical URLs"
        ),
        "passive": False,
    },
    "javascript-extraction": {
        "name": "javascript-extraction",
        "risk_level": "passive",
        "required_tool": None,
        "bound": (
            "extract from HTTP response samples, bounded script count"
        ),
        "passive": True,
    },
    "javascript-bundles": {
        "name": "javascript-bundles",
        "risk_level": "active-low",
        "required_tool": None,
        "bound": "bounded JavaScript bundle fetch",
        "passive": False,
    },
    "katana": {
        "name": "katana",
        "risk_level": "external-controlled",
        "required_tool": "katana",
        "bound": "bounded crawl, depth 1, 30s duration",
        "passive": False,
    },
    "vhost-discovery": {
        "name": "vhost-discovery",
        "risk_level": "active-low",
        "required_tool": None,
        "bound": "up to 500 candidates, 1 req/s, shared budget",
        "passive": False,
    },
    "directory-discovery": {
        "name": "directory-discovery",
        "risk_level": "active-low",
        "required_tool": None,
        "bound": (
            f"up to 200 paths, request budget "
            f"{_DEFAULT_ENRICHMENT.max_hosts_probed}"
        ),
        "passive": False,
    },
}

# Template stage name -> internal plugin stage names it expands to.
_TEMPLATE_STAGE_EXPANSION: dict[str, list[str]] = {
    "sub": ["subfinder", "discovered-dns", "discovered-http"],
    "resolve": ["discovered-dns", "discovered-http"],
    "httpx": ["httpx-fingerprint"],
    "url-history": ["url-history"],
    "js": ["javascript-extraction"],
    "js-bundles": ["javascript-bundles"],
    "katana": ["katana"],
    "vhosts": ["vhost-discovery"],
    "directories": ["directory-discovery"],
}

# Always-running native stages (independent of flags/template).
_ALWAYS_STAGES: list[str] = ["dns", "http", "ct"]


@dataclass(frozen=True)
class StagePlan:
    """One stage that a scan will run, with its disclosure details."""

    name: str
    risk_level: str
    required_tool: str | None
    tool_on_path: bool
    bound: str
    passive: bool


@dataclass(frozen=True)
class ScanPlan:
    """Complete pre-scan plan: scope, stages, tools, budget, disclosures."""

    target: str
    stages: tuple[StagePlan, ...]
    missing_tools: tuple[str, ...]
    planned_disclosures: tuple
    request_budget: int
    dry_run: bool


def _tool_availability() -> dict[str, bool]:
    """Return whether each known external tool is on PATH."""
    availability: dict[str, bool] = {}
    for report in dependency_reports():
        availability[report.dependency.name] = report.path is not None
    return availability


def _resolve_internal_stages(
    *,
    sub: bool = False,
    resolve: bool = False,
    httpx: bool = False,
    url_history: bool = False,
    js: bool = False,
    js_bundles: bool = False,
    katana: bool = False,
    vhosts: bool = False,
    directories: bool = False,
) -> list[str]:
    """Map CLI stage flags to the internal plugin stages that will run."""
    internal: list[str] = []
    internal.extend(_ALWAYS_STAGES)

    if sub:
        internal.extend(_TEMPLATE_STAGE_EXPANSION["sub"])
    if resolve:
        internal.extend(_TEMPLATE_STAGE_EXPANSION["resolve"])
    if httpx:
        internal.extend(_TEMPLATE_STAGE_EXPANSION["httpx"])
    if url_history:
        internal.extend(_TEMPLATE_STAGE_EXPANSION["url-history"])
    if js:
        internal.extend(_TEMPLATE_STAGE_EXPANSION["js"])
    if js_bundles:
        internal.extend(_TEMPLATE_STAGE_EXPANSION["js-bundles"])
    if katana:
        internal.extend(_TEMPLATE_STAGE_EXPANSION["katana"])
    if vhosts:
        internal.extend(_TEMPLATE_STAGE_EXPANSION["vhosts"])
    if directories:
        internal.extend(_TEMPLATE_STAGE_EXPANSION["directories"])

    # De-duplicate while preserving order: native stages first, then
    # configured stages in flag order.
    seen: set[str] = set()
    ordered: list[str] = []
    for name in internal:
        if name not in seen:
            seen.add(name)
            ordered.append(name)
    return ordered


def resolve_stage_flags(
    *,
    template_stages: tuple[str, ...] | None = None,
    profile: str | None = None,
    sub: bool = False,
    resolve: bool = False,
    httpx: bool = False,
    url_history: bool = False,
    js: bool = False,
    js_bundles: bool = False,
    katana: bool = False,
    vhosts: bool = False,
    directories: bool = False,
) -> dict[str, bool]:
    """Resolve CLI stage flags from template, profile, and explicit flags.

    Template stages take precedence and set the corresponding flags.
    Profiles add their stages on top. Returns the resolved boolean flags
    used to build the internal stage list.
    """
    flags = {
        "sub": sub,
        "resolve": resolve,
        "httpx": httpx,
        "url_history": url_history,
        "js": js,
        "js_bundles": js_bundles,
        "katana": katana,
        "vhosts": vhosts,
        "directories": directories,
    }

    if template_stages is not None:
        for stage in template_stages:
            if stage == "sub":
                flags["sub"] = True
            elif stage == "resolve":
                flags["resolve"] = True
            elif stage == "httpx":
                flags["httpx"] = True
            elif stage == "url-history":
                flags["url_history"] = True
            elif stage == "js":
                flags["js"] = True
            elif stage == "js-bundles":
                flags["js_bundles"] = True
            elif stage == "katana":
                flags["katana"] = True
            elif stage == "vhosts":
                flags["vhosts"] = True
            elif stage == "directories":
                flags["directories"] = True

    if profile in {"web", "full"}:
        flags["resolve"] = True
        flags["js"] = True
        flags["js_bundles"] = True
    if profile == "full":
        flags["sub"] = True
        flags["httpx"] = True
        flags["url_history"] = True

    return flags


def plan_scan(
    *,
    target: str,
    sub: bool = False,
    resolve: bool = False,
    httpx: bool = False,
    url_history: bool = False,
    js: bool = False,
    js_bundles: bool = False,
    katana: bool = False,
    vhosts: bool = False,
    directories: bool = False,
    profile: str | None = None,
    ct_sources: tuple[str, ...] = DEFAULT_CT_SOURCES,
    dry_run: bool = False,
) -> ScanPlan:
    """Build a complete pre-scan plan for disclosure or dry-run.

    Does not contact the network. Resolves stages, checks tool availability,
    and gathers planned third-party disclosures.
    """
    flags = resolve_stage_flags(
        template_stages=None,
        profile=profile,
        sub=sub,
        resolve=resolve,
        httpx=httpx,
        url_history=url_history,
        js=js,
        js_bundles=js_bundles,
        katana=katana,
        vhosts=vhosts,
        directories=directories,
    )

    internal_stages = _resolve_internal_stages(**flags)

    availability = _tool_availability()
    stage_plans: list[StagePlan] = []
    for name in internal_stages:
        spec = _STAGE_REGISTRY[name]
        tool = spec["required_tool"]
        stage_plans.append(
            StagePlan(
                name=spec["name"],
                risk_level=spec["risk_level"],
                required_tool=tool,
                tool_on_path=availability.get(tool, False) if tool else True,
                bound=spec["bound"],
                passive=spec["passive"],
            )
        )

    # Determine which external tools are required and which are missing.
    requested_tools = {
        sp.required_tool for sp in stage_plans if sp.required_tool is not None
    }
    missing_tools = tuple(
        sorted(t for t in requested_tools if not availability.get(t, False))
    )

    planned = planned_disclosures(
        ct_sources=ct_sources,
        adapters=tuple(
            sp.required_tool
            for sp in stage_plans
            if sp.required_tool is not None
        ),
        resolves_names=flags["resolve"] or flags["sub"],
    )

    return ScanPlan(
        target=target,
        stages=tuple(stage_plans),
        missing_tools=missing_tools,
        planned_disclosures=planned,
        request_budget=_DEFAULT_RATE.budget,
        dry_run=dry_run,
    )


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_RISK_STYLE = {
    "passive": "passive",
    "active-low": "active-low",
    "external-controlled": "external",
}


def _risk_label(plan: StagePlan) -> str:
    """Return a short, visually distinct risk label for a stage."""
    if plan.passive:
        return "passive"
    if plan.required_tool is not None:
        return "external"
    return "active-low"


def render_stage_table(plans: tuple[StagePlan, ...], narrow: bool = False) -> str:
    """Render the per-stage disclosure table as a string."""
    if not plans:
        return "  (no stages)"

    name_w = max(len(p.name) for p in plans)
    risk_w = max(len(_risk_label(p)) for p in plans)
    tool_w = max((len(p.required_tool or "-") for p in plans), default=1)

    lines: list[str] = []
    header = (
        f"  {'STAGE':<{name_w}}  "
        f"{'RISK':<{risk_w}}  "
        f"{'TOOL':<{tool_w}}  "
        f"{'PATH':<4}  BOUND"
    )
    lines.append(header)
    lines.append(
        f"  {'-' * name_w}  "
        f"{'-' * risk_w}  "
        f"{'-' * tool_w}  "
        f"{'-' * 4}  {'-' * 40}"
    )
    for p in plans:
        tool = p.required_tool or "-"
        path = "yes" if p.tool_on_path else "no"
        if p.required_tool is not None and not p.tool_on_path:
            path = "MISSING"
        lines.append(
            f"  {p.name:<{name_w}}  "
            f"{_risk_label(p):<{risk_w}}  "
            f"{tool:<{tool_w}}  "
            f"{path:<4}  {p.bound}"
        )
    return "\n".join(lines)


def render_missing_tools(missing_tools: tuple[str, ...]) -> str:
    """Render a combined missing-tool failure message.

    Returns an empty string when no tools are missing.
    """
    if not missing_tools:
        return ""
    lines = [
        "Scan cannot start because requested optional tools are missing.",
        "",
        "Missing:",
    ]
    for tool in missing_tools:
        lines.append(f"  {tool}  required by a selected scan stage")
    lines.extend(["", "Install:"])
    for report in dependency_reports():
        if report.dependency.name in missing_tools:
            lines.append(f"  {report.dependency.install_hint}")
    lines.extend(["", "Run `sh4q doctor` to check all optional dependencies."])
    return "\n".join(lines)


def render_disclosures(disclosures: tuple) -> str:
    """Render planned third-party disclosures as a string."""
    if not disclosures:
        return "  No third parties will be contacted."

    services = list(dict.fromkeys(d.service for d in disclosures))
    lines = [f"  {len(services)} third part(ies) will learn this target:"]
    for service in services:
        lines.append(f"    {service}")
    return "\n".join(lines)


def render_scan_plan(plan: ScanPlan, narrow: bool = False) -> str:
    """Render the complete scan plan (stages + disclosures) as a string."""
    lines: list[str] = []
    lines.append("\n  SH4Q SCAN PLAN")
    lines.append("  ==============")
    lines.append(f"  Target   {plan.target}")
    lines.append(f"  Stages   {len(plan.stages)} stage(s) will run")
    lines.append("")
    lines.append(render_stage_table(plan.stages, narrow=narrow))
    lines.append("")
    lines.append(render_disclosures(plan.planned_disclosures))
    lines.append("")
    lines.append(
        f"  Request budget: {plan.request_budget} "
        f"request(s) shared across all stages"
    )
    if plan.dry_run:
        lines.append("  Dry run: no network requests will be made.")
    else:
        if plan.missing_tools:
            lines.append("")
            lines.append(render_missing_tools(plan.missing_tools))
    return "\n".join(lines)


def render_dry_run(plan: ScanPlan, gate_decision, narrow: bool = False) -> str:
    """Render the complete dry-run output: Gate 1, scope, plan."""
    lines: list[str] = []
    lines.append("\n  SH4Q DRY RUN")
    lines.append("  ============")
    lines.append(f"  Target   {plan.target}")
    lines.append(
        f"  Gate 1   {'ALLOW' if gate_decision.allowed else 'DENY'} "
        f"({gate_decision.reason})"
    )
    if not gate_decision.allowed:
        lines.append("  Dry run aborted: target not authorised.")
        return "\n".join(lines)

    lines.append("")
    lines.append("  SCOPE")
    lines.append("  -----")
    lines.append(f"    Target   {plan.target}")
    lines.append(f"    Ports    80, 443 (default narrow scope)")
    lines.append("")

    lines.append(render_scan_plan(plan, narrow=narrow))
    lines.append("")
    lines.append("  Dry run complete. No network requests were made.")
    return "\n".join(lines)
