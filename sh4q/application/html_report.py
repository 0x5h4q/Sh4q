from __future__ import annotations

import html
import json
import base64
from pathlib import Path
from urllib.parse import urlsplit

from sh4q.storage.db import open_sync_database
from sh4q.storage.scan_runs import ScanRun
from sh4q.application.redaction import Redactor


def _safe_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=True).replace("<", "\\u003c")


def _banner_data_uri() -> str | None:
    candidates = (
        Path(__file__).resolve().parents[1] / "assets" / "banner.png",
        Path(__file__).resolve().parents[2] / "banner.png",
    )
    path = next((candidate for candidate in candidates if candidate.is_file()), None)
    if path is None:
        return None
    return "data:image/png;base64," + base64.b64encode(path.read_bytes()).decode("ascii")


def _owned_rows(database: str, run: ScanRun, *, redactor: Redactor | None = None) -> list[dict]:
    with open_sync_database(database) as db:
        rows = db.execute(
            """SELECT n.type, n.value, n.attributes,
            group_concat(DISTINCT sa.source_plugin),
            MAX(CASE WHEN r.type = 'HISTORICAL_URL' THEN 1 ELSE 0 END),
            MAX(CASE WHEN r.type = 'SERVES' THEN 1 ELSE 0 END)
            FROM scan_assets sa JOIN nodes n ON n.id = sa.asset_id
            LEFT JOIN relationships r ON r.id = sa.relationship_id
            WHERE sa.scan_run_id = ?
            GROUP BY n.id, n.type, n.value, n.attributes
            ORDER BY n.type, n.value""",
            (run.id,),
        ).fetchall()
        endpoint_rows = db.execute(
            """SELECT DISTINCT technology.id, endpoint.value, endpoint.attributes
            FROM scan_assets sa
            JOIN relationships r ON r.id = sa.relationship_id
            JOIN nodes technology ON technology.id = r.to_id
            JOIN nodes endpoint ON endpoint.id = r.from_id
            WHERE sa.scan_run_id = ? AND r.type = 'DETECTED_TECHNOLOGY'
              AND technology.type = 'technology' AND endpoint.type = 'url'
            ORDER BY endpoint.value""",
            (run.id,),
        ).fetchall()
    tech_endpoints = {}
    for technology_id, endpoint, raw_attributes in endpoint_rows:
        tech_endpoints.setdefault(technology_id, []).append({
            "endpoint": endpoint,
            "host": urlsplit(endpoint).hostname or endpoint,
            "status": json.loads(raw_attributes).get("status", ""),
        })
    assets = []
    for asset_type, value, raw_attributes, raw_sources, has_history, has_live in rows:
        attributes = json.loads(raw_attributes)
        host = value
        status = attributes.get("status", "")
        if asset_type == "url":
            host = urlsplit(value).hostname or value
        elif asset_type == "technology":
            endpoints = tech_endpoints.get(f"technology:{value}", [])
            if endpoints:
                host = ", ".join(sorted({item["host"] for item in endpoints}))
                status = ", ".join(sorted({str(item["status"]) for item in endpoints if item["status"]}))
        display_type = "historical-url" if asset_type == "url" and has_history and not has_live else asset_type
        display_value = (
            redactor.url(value)
            if redactor is not None and display_type in {"url", "historical-url"}
            else value
        )
        assets.append({
            "type": display_type,
            "value": display_value,
            "host": host,
            "status": status,
            "technology": value if asset_type == "technology" else "",
            "category": attributes.get("category", ""),
            "version": attributes.get("version", ""),
            "confidence": attributes.get("confidence", ""),
            "sources": sorted(source for source in (raw_sources or "").split(",") if source),
        })
    return assets


def _report_metadata(database: str, run: ScanRun, *, redactor: Redactor | None = None) -> dict:
    evidence = []
    failures = []
    stages = []
    request_metrics = {}
    historical_urls_truncated = 0
    historical_urls_rejected = 0
    javascript = []
    vhosts = []
    vhost_rejections = []
    directories = []
    directory_rejections = []

    def clean(value):
        """Redact a URL-bearing evidence field, if redaction is on.

        Redaction previously reached only the asset table, so a report
        exported with --redact still carried the unredacted URL in its
        JavaScript observations, its vhost and directory rows, and the JSON
        the page embeds for its own filtering.
        """
        return value if redactor is None else redactor.url(value)

    with open_sync_database(database) as db:
        table = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='evidence'"
        ).fetchone()
        if table:
            rows = db.execute(
                "SELECT plugin, kind, content, captured_at FROM evidence "
                "WHERE scan_run_id = ? ORDER BY captured_at", (run.id,)
            ).fetchall()
            for plugin, kind, raw_content, captured_at in rows:
                content = json.loads(raw_content)
                record = {"plugin": plugin, "kind": kind, "captured_at": captured_at}
                if kind == "request_metrics":
                    request_metrics = content
                elif kind == "stage_metrics":
                    stages = content.get("stages", [])
                elif kind == "url_history_truncated":
                    historical_urls_truncated += max(0, content.get("available", 0) - content.get("retained", 0))
                elif kind == "url_history_rejected":
                    historical_urls_rejected += 1
                elif kind.startswith("javascript_") and kind != "javascript_bundle_error":
                    javascript.append(record | {
                        "value": clean(content.get("value", "")),
                        "source_endpoint": clean(content.get("source_endpoint", "")),
                        "pattern": content.get("pattern", ""),
                    })
                elif kind in {"vhost_baseline", "vhost_observation"}:
                    vhosts.append(record | {
                        "candidate": content.get("candidate", ""),
                        "endpoint": clean(content.get("endpoint", "")),
                        "status": content.get("status", ""),
                        "classification": content.get("classification", "baseline" if kind == "vhost_baseline" else "candidate_observation"),
                        "location": clean(content.get("location", "")),
                    })
                elif kind == "vhost_rejected":
                    vhost_rejections.append(record | {
                        "candidate": content.get("candidate", ""),
                        "reason": content.get("reason", "unknown reason"),
                    })
                elif kind in {"http_error", "dns_error", "discovered_dns_error", "ct_error"}:
                    # Without the subject a failure says "no A answer" and
                    # nothing else, which is the same row a thousand times.
                    failures.append(record | {
                        "subject": clean(_failure_subject(content)),
                        "detail": content.get("error") or content.get("reason") or "unknown error",
                    })
                elif kind == "vhost_error":
                    failures.append(record | {
                        "subject": clean(_failure_subject(content)),
                        "detail": content.get("error") or "unknown error",
                    })
                elif kind in {"directory_baseline", "directory_observation"}:
                    directories.append(record | {
                        "path": content.get("path", "baseline" if kind == "directory_baseline" else ""),
                        "url": clean(content.get("url", content.get("endpoint", ""))),
                        "status": content.get("status", ""),
                        "classification": content.get("classification", "baseline" if kind == "directory_baseline" else "candidate_observation"),
                        "location": clean(content.get("location", "")),
                    })
                elif kind in {"directory_rejected", "directory_budget_denied"}:
                    directory_rejections.append(record | {
                        "path": content.get("path", ""),
                        "reason": content.get("reason", "unknown reason"),
                    })
                elif kind == "directory_error":
                    failures.append(record | {"detail": content.get("error") or "unknown error"})
                evidence.append(record)
    javascript.sort(key=lambda item: (item["source_endpoint"], item["kind"], item["value"]))
    return {"evidence": evidence, "failures": failures, "javascript": javascript, "vhosts": vhosts,
            "vhost_rejections": vhost_rejections, "stages": stages, "request_metrics": request_metrics,
            "directories": directories, "directory_rejections": directory_rejections,
            "historical_urls_rejected": historical_urls_rejected,
            "historical_urls_truncated": historical_urls_truncated}


def _failure_subject(content: dict) -> str:
    """What the failure was about: the host, URL, or candidate that failed."""
    for key in ("domain", "url", "hostname", "candidate", "endpoint", "path", "source"):
        value = content.get(key)
        if value:
            return str(value)
    return "-"


def _grouped_failures(failures: list[dict]) -> list[dict]:
    """Collapse identical failures into one row with a count and examples.

    A scan of a large estate produced 1025 DNS failures that rendered as
    1025 rows reading "no A answer". The reason repeats; the subjects do
    not, and they are what an operator needs.
    """
    groups: dict[tuple[str, str, str], list[str]] = {}
    for item in failures:
        key = (item.get("plugin", ""), item.get("kind", ""), item.get("detail", ""))
        groups.setdefault(key, []).append(item.get("subject") or "-")
    rows = [
        {
            "plugin": plugin,
            "kind": kind,
            "detail": detail,
            "count": len(subjects),
            "examples": sorted(set(subjects))[:4],
            "more": max(0, len(set(subjects)) - 4),
        }
        for (plugin, kind, detail), subjects in groups.items()
    ]
    return sorted(rows, key=lambda row: (-row["count"], row["plugin"], row["detail"]))


def render_html_report(database: str, run: ScanRun, *, redactor: Redactor | None = None) -> str:
    assets = _owned_rows(database, run, redactor=redactor)
    metadata = _report_metadata(database, run, redactor=redactor)
    banner_uri = _banner_data_uri()
    grouped_failures = _grouped_failures(metadata["failures"])
    payload = {
        "scan": {
            "id": run.id,
            "target": run.target,
            "status": run.status,
            "started_at": run.started_at,
            "completed_at": run.completed_at,
        },
        "assets": assets,
        **metadata,
    }
    title = html.escape(f"Sh4q report: {run.target}")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
/* Design tokens. Every colour is declared once here and referenced by name,
   so dark mode redefines eight values rather than duplicating every rule. */
:root {{
  --bg: #eff2f5;           --surface: #ffffff;      --surface-2: #f6f8fa;
  --border: #d9e0e7;       --border-soft: #e9eef2;
  --text: #16202b;         --muted: #5b6b7a;
  --accent: #157f78;       --accent-soft: #d9f2ef;  --accent-line: #2c9c94;
  --shadow: 0 1px 2px rgba(16,32,48,.05), 0 4px 14px rgba(16,32,48,.05);
  --radius: 10px;          --radius-sm: 6px;
  --ok-fg: #0f6b41; --ok-bg: #d7f2e3;
  --warn-fg: #7a5200; --warn-bg: #ffeebc;
  --alert-fg: #8a3b12; --alert-bg: #ffe2ca;
  --bad-fg: #961f1f; --bad-bg: #ffd8d8;
  color-scheme: light;
  font: 15px/1.55 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}}
/* Follow the reader's system setting unless they have chosen otherwise. The
   previous report defaulted to light regardless, so a dark-mode reader got a
   full-page flash before finding the toggle. */
@media (prefers-color-scheme: dark) {{
  body:not(.light) {{
    --bg: #0f151b;         --surface: #18212a;      --surface-2: #1e2932;
    --border: #2d3c49;     --border-soft: #26333e;
    --text: #dde7ef;       --muted: #93a6b5;
    --accent: #5ed3c7;     --accent-soft: #1b3f3e;  --accent-line: #2c9c94;
    --shadow: 0 1px 2px rgba(0,0,0,.3), 0 4px 16px rgba(0,0,0,.25);
    --ok-fg: #7ee0aa; --ok-bg: #123a28;
    --warn-fg: #ffd66b; --warn-bg: #3d3113;
    --alert-fg: #ffb987; --alert-bg: #422516;
    --bad-fg: #ff9d9d; --bad-bg: #431c1c;
    color-scheme: dark;
  }}
}}
body.dark {{
  --bg: #0f151b;           --surface: #18212a;      --surface-2: #1e2932;
  --border: #2d3c49;       --border-soft: #26333e;
  --text: #dde7ef;         --muted: #93a6b5;
  --accent: #5ed3c7;       --accent-soft: #1b3f3e;  --accent-line: #2c9c94;
  --shadow: 0 1px 2px rgba(0,0,0,.3), 0 4px 16px rgba(0,0,0,.25);
  --ok-fg: #7ee0aa; --ok-bg: #123a28;
  --warn-fg: #ffd66b; --warn-bg: #3d3113;
  --alert-fg: #ffb987; --alert-bg: #422516;
  --bad-fg: #ff9d9d; --bad-bg: #431c1c;
  color-scheme: dark;
}}

* {{ box-sizing: border-box; }}
body {{ margin: 0; color: var(--text); background: var(--bg); -webkit-font-smoothing: antialiased; }}
code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .92em; }}

header {{ position: relative; padding: 22px 5vw 20px; background: var(--surface);
  border-bottom: 3px solid var(--accent-line); }}
.brand {{ display: flex; align-items: center; gap: 20px; max-width: 1400px; margin: 0 auto; }}
/* The banner previously ran to 340px tall and pushed the actual report below
   the fold. It is identification, not content. */
.brand img {{ flex: 0 0 auto; width: min(220px, 40vw); max-height: 96px; object-fit: contain; }}
.brand-copy {{ min-width: 0; }}
header strong {{ display: block; color: var(--accent); font-size: 1.1rem; letter-spacing: .14em; }}
header .subject {{ margin-top: 2px; font-size: 1.3rem; font-weight: 650; overflow-wrap: anywhere; }}
header small {{ display: block; margin-top: 6px; color: var(--muted); overflow-wrap: anywhere; }}

main {{ max-width: 1400px; margin: 0 auto; padding: 26px 5vw 56px; }}

.stats {{ display: grid; grid-template-columns: repeat(auto-fit,minmax(150px,1fr)); gap: 12px; margin-bottom: 24px; }}
.stat {{ padding: 14px 16px; background: var(--surface); border: 1px solid var(--border);
  border-radius: var(--radius); box-shadow: var(--shadow); color: var(--muted); font-size: 12.5px;
  transition: transform .14s ease, box-shadow .14s ease; }}
.stat:hover {{ transform: translateY(-1px); box-shadow: 0 2px 4px rgba(16,32,48,.07), 0 8px 22px rgba(16,32,48,.08); }}
.stat strong {{ display: block; margin-bottom: 2px; color: var(--text);
  font-size: 1.7rem; font-weight: 640; line-height: 1.15; font-variant-numeric: tabular-nums; }}

.filters {{ position: relative; display: grid; grid-template-columns: repeat(auto-fit,minmax(180px,1fr));
  gap: 12px; align-items: end; padding: 16px; margin-bottom: 14px; background: var(--surface);
  border: 1px solid var(--border); border-radius: var(--radius); box-shadow: var(--shadow); }}
label {{ display: grid; min-width: 0; gap: 5px; color: var(--muted);
  font-size: 11.5px; font-weight: 700; letter-spacing: .04em; text-transform: uppercase; }}
input, select {{ width: 100%; min-width: 0; min-height: 38px; padding: 7px 10px; color: var(--text);
  background: var(--surface-2); border: 1px solid var(--border); border-radius: var(--radius-sm);
  font: inherit; transition: border-color .14s ease, box-shadow .14s ease; }}
input:focus, select:focus {{ outline: none; border-color: var(--accent-line);
  box-shadow: 0 0 0 3px var(--accent-soft); }}
.filter-actions {{ display: flex; align-items: end; }}

button {{ min-height: 38px; padding: 7px 13px; color: var(--text); background: var(--surface-2);
  border: 1px solid var(--border); border-radius: var(--radius-sm); font: inherit; font-weight: 600;
  cursor: pointer; transition: background .14s ease, border-color .14s ease, transform .1s ease; }}
button:hover {{ background: var(--accent-soft); border-color: var(--accent-line); }}
button:active {{ transform: translateY(1px); }}
button:focus-visible {{ outline: 2px solid var(--accent-line); outline-offset: 2px; }}
.theme-toggle {{ position: absolute; top: 18px; right: 5vw; }}

.chips {{ display: flex; flex-wrap: wrap; gap: 6px; grid-column: 1 / -1; }}
.chip {{ min-height: auto; padding: 3px 10px; border-radius: 999px; color: var(--accent);
  background: var(--accent-soft); border-color: transparent; font-size: 12px; font-weight: 600; }}

.count {{ margin: 12px 0; color: var(--muted); font-weight: 600; font-size: 13px; }}

.table-wrap {{ overflow-x: auto; background: var(--surface); border: 1px solid var(--border);
  border-radius: var(--radius); box-shadow: var(--shadow); }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ padding: 10px 13px; border-bottom: 1px solid var(--border-soft); text-align: left; vertical-align: top; }}
th {{ position: sticky; top: 0; z-index: 1; color: var(--muted); background: var(--surface-2);
  border-bottom: 1px solid var(--border); font-size: 11.5px; font-weight: 700;
  letter-spacing: .04em; text-transform: uppercase; }}
tbody tr {{ transition: background .1s ease; }}
tbody tr:hover {{ background: var(--accent-soft); }}
tbody tr:last-child td {{ border-bottom: 0; }}
td code {{ white-space: nowrap; }}
.sort {{ min-height: auto; padding: 2px 5px; border: 0; background: transparent; color: inherit;
  font: inherit; letter-spacing: inherit; text-transform: inherit; }}
.sort:hover {{ background: var(--accent-soft); }}

.status {{ display: inline-block; min-width: 2.7em; padding: 2px 7px; border-radius: 999px;
  text-align: center; font-size: 11.5px; font-weight: 700; font-variant-numeric: tabular-nums; }}
.status-2 {{ color: var(--ok-fg); background: var(--ok-bg); }}
.status-3 {{ color: var(--warn-fg); background: var(--warn-bg); }}
.status-4 {{ color: var(--alert-fg); background: var(--alert-bg); }}
.status-5 {{ color: var(--bad-fg); background: var(--bad-bg); }}
.copy {{ min-height: auto; padding: 1px 7px; margin-left: 6px; font-size: 11.5px; }}

.pagination {{ display: flex; align-items: center; justify-content: flex-end; gap: 10px; margin: 12px 0; }}
.pagination button:disabled {{ cursor: not-allowed; opacity: .4; }}
.pagination button:disabled:hover {{ background: var(--surface-2); border-color: var(--border); }}
#page {{ color: var(--muted); font-size: 13px; font-variant-numeric: tabular-nums; }}

details {{ margin-top: 16px; background: var(--surface); border: 1px solid var(--border);
  border-radius: var(--radius); box-shadow: var(--shadow); overflow: hidden; }}
summary {{ padding: 13px 16px; font-weight: 650; cursor: pointer; list-style: none;
  transition: background .12s ease; }}
summary::-webkit-details-marker {{ display: none; }}
summary::before {{ display: inline-block; width: 1.1em; content: "\25B8";
  color: var(--muted); transition: transform .15s ease; }}
details[open] > summary::before {{ transform: rotate(90deg); }}
summary:hover {{ background: var(--surface-2); }}
details > section {{ margin: 0; padding: 0 16px 16px; }}
details .table-wrap {{ box-shadow: none; }}
details h3 {{ margin: 18px 0 8px; color: var(--muted); font-size: 12px;
  letter-spacing: .04em; text-transform: uppercase; }}
details ul {{ margin: 0; padding-left: 20px; color: var(--muted); font-size: 13.5px; }}
details p {{ color: var(--muted); font-size: 13px; }}

section {{ margin-top: 24px; }}
section h2 {{ margin: 0 0 10px; font-size: 1.05rem; }}
pre {{ overflow-x: auto; margin: 0; padding: 14px; background: var(--surface-2);
  border: 1px solid var(--border); border-radius: var(--radius-sm); color: var(--text); font-size: 13px; }}

@media (prefers-reduced-motion: reduce) {{ * {{ transition: none !important; }} }}
@media (max-width: 760px) {{
  header, main {{ padding-left: 16px; padding-right: 16px; }}
  .theme-toggle {{ right: 16px; }}
  .brand {{ flex-direction: column; align-items: flex-start; gap: 12px; }}
  .brand img {{ width: min(180px, 48vw); max-height: 72px; }}
  header .subject {{ font-size: 1.1rem; }}
  .stats {{ grid-template-columns: repeat(2,minmax(0,1fr)); }}
  th, td {{ padding: 8px 10px; }}
}}
</style></head><body>
<header><button id="theme" class="theme-toggle" type="button" title="Switch between light and dark">Theme</button><div class="brand">{f'<img src="{banner_uri}" alt="Sh4q" />' if banner_uri else ''}<div class="brand-copy">{'' if banner_uri else '<strong>SH4Q</strong>'}<div class="subject">{html.escape(run.target)}</div><small>scan {html.escape(run.id)} · {html.escape(run.status)}</small></div></div></header>
<main><div class="stats">
<div class="stat"><strong>{len(assets)}</strong>scan-owned assets</div>
<div class="stat"><strong>{len(metadata["evidence"])}</strong>evidence records</div>
<div class="stat"><strong>{len(metadata["failures"])}</strong>failures</div>
<div class="stat"><strong>{len(metadata["stages"])}</strong>stages</div>
<div class="stat"><strong>{metadata["historical_urls_truncated"]}</strong>history truncated</div>
<div class="stat"><strong>{metadata["historical_urls_rejected"]}</strong>history rejected</div>
<div class="stat"><strong>{len(metadata["javascript"])}</strong>JavaScript observations</div>
<div class="stat"><strong>{len(metadata["vhosts"])}</strong>vhost observations</div>
<div class="stat"><strong>{len(metadata["directories"])}</strong>directory observations</div>
</div><section class="filters" aria-label="Report filters">
<label>Search<input id="search" type="search" placeholder="hostname, URL, technology"></label>
<label>Asset type<select id="type"><option value="">All</option></select></label>
<label>Target / host<select id="host"><option value="">All</option></select></label>
<label>HTTP status<select id="status"><option value="">All</option></select></label>
<label>Technology / category<select id="technology"><option value="">All</option></select></label>
<label>Source<select id="source"><option value="">All</option></select></label>
<div class="filter-actions"><button id="reset" type="button">Reset filters</button></div>
</section><div class="chips" id="chips" aria-live="polite"></div><div class="count" id="count"></div>
<div class="table-wrap"><table><thead><tr><th><button class="sort" data-sort="type" type="button">Type</button></th><th><button class="sort" data-sort="value" type="button">Value</button></th><th><button class="sort" data-sort="host" type="button">Host / target</button></th><th><button class="sort" data-sort="status" type="button">Status</button></th><th><button class="sort" data-sort="technology" type="button">Technology</button></th><th><button class="sort" data-sort="category" type="button">Category</button></th><th><button class="sort" data-sort="source" type="button">Source</button></th></tr></thead>
<tbody id="rows"></tbody></table></div>
<div class="pagination"><button id="prev" type="button">Previous</button><span id="page"></span><button id="next" type="button">Next</button></div>
<details open><summary>Failures</summary><section><div class="table-wrap"><table><thead><tr><th>Count</th><th>Stage</th><th>Reason</th><th>Affected</th></tr></thead><tbody>{''.join(f'<tr><td><strong>{item["count"]}</strong></td><td>{html.escape(item["plugin"])}<br><small>{html.escape(item["kind"])}</small></td><td>{html.escape(item["detail"])}</td><td>{"<br>".join(f"<code>{html.escape(example)}</code>" for example in item["examples"])}{f"<br><small>and {item[chr(34)+chr(34)] if False else item["more"]} more</small>" if item["more"] else ""}</td></tr>' for item in grouped_failures) or '<tr><td colspan="4">No recorded failures.</td></tr>'}</tbody></table></div><p>Identical failures are grouped. Every individual record is retained in evidence.</p></section></details>
<details open><summary>JavaScript observations</summary><section><div class="table-wrap"><table><thead><tr><th>Type</th><th>Reference or pattern</th><th>Source endpoint</th><th>Captured</th></tr></thead><tbody>{''.join(f'<tr><td>{html.escape(item["kind"].removeprefix("javascript_"))}</td><td><code>{html.escape(str(item["value"]))}</code></td><td><code>{html.escape(str(item["source_endpoint"] or "-"))}</code></td><td>{html.escape(item["captured_at"])}</td></tr>' for item in metadata["javascript"]) or '<tr><td colspan="4">No JavaScript observations.</td></tr>'}</tbody></table></div><p>These are passive, unverified observations. They are not automatically requested or treated as confirmed secrets.</p></section></details>
<details open><summary>Virtual-host observations</summary><section><div class="table-wrap"><table><thead><tr><th>Candidate</th><th>Endpoint</th><th>Status</th><th>Classification</th><th>Redirect</th><th>Captured</th></tr></thead><tbody>{''.join(f'<tr><td><code>{html.escape(str(item["candidate"] or "baseline"))}</code></td><td><code>{html.escape(str(item["endpoint"] or "-"))}</code></td><td>{html.escape(str(item["status"] or "-"))}</td><td>{html.escape(str(item["classification"]))}</td><td>{html.escape(str(item["location"] or "-"))}</td><td>{html.escape(item["captured_at"])}</td></tr>' for item in metadata["vhosts"]) or '<tr><td colspan="6">No virtual-host observations.</td></tr>'}</tbody></table></div><h3>Rejected candidates</h3><ul>{''.join(f'<li><code>{html.escape(str(item["candidate"]))}</code>: {html.escape(str(item["reason"]))}</li>' for item in metadata["vhost_rejections"]) or '<li>No rejected candidates.</li>'}</ul><p>Virtual-host observations are bounded, scope-checked candidates and are not security findings.</p></section></details>
<details open><summary>Directory observations</summary><section><div class="table-wrap"><table><thead><tr><th>Path</th><th>URL</th><th>Status</th><th>Classification</th><th>Redirect</th><th>Captured</th></tr></thead><tbody>{''.join(f'<tr><td><code>{html.escape(str(item["path"] or "baseline"))}</code></td><td><code>{html.escape(str(item["url"] or "-"))}</code></td><td>{html.escape(str(item["status"] or "-"))}</td><td>{html.escape(str(item["classification"]))}</td><td>{html.escape(str(item["location"] or "-"))}</td><td>{html.escape(item["captured_at"])}</td></tr>' for item in metadata["directories"]) or '<tr><td colspan="6">No directory observations.</td></tr>'}</tbody></table></div><h3>Rejected or budget-denied paths</h3><ul>{''.join(f'<li><code>{html.escape(str(item["path"]))}</code>: {html.escape(str(item["reason"]))}</li>' for item in metadata["directory_rejections"]) or '<li>No rejected paths.</li>'}</ul><p>Directory observations are bounded, scope-checked responses and are not security findings.</p></section></details>
<details><summary>Stage timings</summary><section><div class="table-wrap"><table><thead><tr><th>Stage</th><th>Status</th><th>Attempts</th><th>Findings</th><th>Duration</th></tr></thead><tbody>{''.join(f'<tr><td>{html.escape(str(item.get("name", "")))}</td><td>{html.escape(str(item.get("status", "")))}</td><td>{item.get("attempts", 0)}</td><td>{item.get("discoveries", 0)}</td><td>{item.get("duration_seconds", 0)}s</td></tr>' for item in metadata["stages"]) or '<tr><td colspan="5">No persisted stage metrics.</td></tr>'}</tbody></table></div></section></details>
<details><summary>Request metrics</summary><section><pre>{html.escape(json.dumps(metadata["request_metrics"], indent=2, sort_keys=True))}</pre></section></details>
<details><summary>Evidence index</summary><section><div class="count">{len(metadata["evidence"])} records retained for this scan.</div></section></details></main>
<script>
const report = {_safe_json(payload)};
const fields = {{type: document.querySelector('#type'), host: document.querySelector('#host'), status: document.querySelector('#status'), technology: document.querySelector('#technology'), source: document.querySelector('#source'), search: document.querySelector('#search')}};
let sortKey = 'value', sortDirection = 1, pageNumber = 1;
const pageSize = 50;
const values = (key) => {{
 const raw = report.assets.flatMap(a => key === 'source' ? a.sources : [a[key]]).filter(Boolean);
 if (key === 'status') return [...new Set(raw.flatMap(value => String(value).split(',').map(item => item.trim()).filter(Boolean)))].sort((a, b) => Number(a) - Number(b) || a.localeCompare(b));
 return [...new Set(raw)].sort();
}};
for (const [key, select] of Object.entries(fields)) if (select.tagName === 'SELECT') for (const value of values(key)) select.add(new Option(value, value));
function render() {{
 const query = fields.search.value.toLowerCase();
 const filtered = report.assets.filter(a => (!fields.type.value || a.type === fields.type.value) && (!fields.host.value || a.host === fields.host.value) && (!fields.status.value || String(a.status).split(',').map(item => item.trim()).includes(fields.status.value)) && (!fields.technology.value || a.technology === fields.technology.value || a.category === fields.technology.value) && (!fields.source.value || a.sources.includes(fields.source.value)) && (!query || JSON.stringify(a).toLowerCase().includes(query)));
 filtered.sort((left, right) => String(left[sortKey] ?? '').localeCompare(String(right[sortKey] ?? ''), undefined, {{numeric: true}}) * sortDirection);
 const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize)); pageNumber = Math.min(pageNumber, pageCount);
 const visible = filtered.slice((pageNumber - 1) * pageSize, pageNumber * pageSize);
 const esc = value => String(value ?? '').replace(/[&<>\"']/g, char => ({{'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',"'":'&#39;'}}[char]));
 document.querySelector('#count').textContent = `${{filtered.length}} of ${{report.assets.length}} scan-owned assets`;
 document.querySelector('#page').textContent = `Page ${{pageNumber}} of ${{pageCount}}`;
 document.querySelector('#prev').disabled = pageNumber <= 1; document.querySelector('#next').disabled = pageNumber >= pageCount;
 document.querySelector('#chips').innerHTML = Object.entries(fields).filter(([key, input]) => input.value && key !== 'search').map(([key, input]) => `<button class="chip" data-clear="${{key}}" type="button">${{esc(key)}}: ${{esc(input.value)}} x</button>`).join('');
 const shown = value => value === '' || value == null ? '-' : value;
 const statusBadge = value => {{ const code = String(value ?? ''); const family = code.slice(0, 1); return code === '-' ? '-' : `<span class="status status-${{family}}">${{esc(code)}}</span>`; }};
 document.querySelector('#rows').innerHTML = visible.map(a => `<tr><td>${{esc(a.type)}}</td><td><code>${{esc(a.value)}}</code><button class="copy" data-copy="${{esc(a.value)}}" type="button" title="Copy value">Copy</button></td><td>${{esc(shown(a.host))}}</td><td>${{statusBadge(a.status)}}</td><td>${{esc(shown(a.technology))}}</td><td>${{esc(shown(a.category))}}</td><td>${{esc(a.sources.length ? a.sources.join(', ') : '-')}}</td></tr>`).join('') || '<tr><td colspan="7">No assets match these filters.</td></tr>';
}}
Object.values(fields).forEach(input => input.addEventListener('input', () => {{ pageNumber = 1; render(); }}));
document.querySelectorAll('.sort').forEach(button => button.addEventListener('click', () => {{ const next = button.dataset.sort; sortDirection = sortKey === next ? sortDirection * -1 : 1; sortKey = next; render(); }}));
document.querySelector('#prev').addEventListener('click', () => {{ pageNumber -= 1; render(); }}); document.querySelector('#next').addEventListener('click', () => {{ pageNumber += 1; render(); }});
document.querySelector('#chips').addEventListener('click', event => {{ const key = event.target.dataset.clear; if (key) {{ fields[key].value = ''; pageNumber = 1; render(); }} }});
document.querySelector('#rows').addEventListener('click', event => {{ const value = event.target.dataset.copy; if (value) navigator.clipboard?.writeText(value).then(() => {{ event.target.textContent = 'Copied'; setTimeout(() => event.target.textContent = 'Copy', 1000); }}); }});
const prefersDark = () => window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
const applyTheme = choice => {{ document.body.classList.toggle('dark', choice === 'dark'); document.body.classList.toggle('light', choice === 'light'); }};
const stored = localStorage.getItem('sh4q-theme');
if (stored) applyTheme(stored);
document.querySelector('#theme').addEventListener('click', () => {{
  const dark = document.body.classList.contains('dark') || (!document.body.classList.contains('light') && prefersDark());
  const next = dark ? 'light' : 'dark';
  applyTheme(next); localStorage.setItem('sh4q-theme', next);
}});
render();
document.querySelector('#reset').addEventListener('click', () => {{
 Object.values(fields).forEach(input => input.value = ''); pageNumber = 1; render();
}});
</script></body></html>\n"""
