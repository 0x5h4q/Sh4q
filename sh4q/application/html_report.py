from __future__ import annotations

import html
import json
from urllib.parse import urlsplit

from sh4q.storage.db import open_sync_database
from sh4q.storage.scan_runs import ScanRun


def _safe_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=True).replace("<", "\\u003c")


def _owned_rows(database: str, run: ScanRun) -> list[dict]:
    with open_sync_database(database) as db:
        rows = db.execute(
            """SELECT n.type, n.value, n.attributes,
            group_concat(DISTINCT sa.source_plugin)
            FROM scan_assets sa JOIN nodes n ON n.id = sa.asset_id
            WHERE sa.scan_run_id = ?
            GROUP BY n.id, n.type, n.value, n.attributes
            ORDER BY n.type, n.value""",
            (run.id,),
        ).fetchall()
    assets = []
    for asset_type, value, raw_attributes, raw_sources in rows:
        attributes = json.loads(raw_attributes)
        host = value
        if asset_type == "url":
            host = urlsplit(value).hostname or value
        assets.append({
            "type": asset_type,
            "value": value,
            "host": host,
            "status": attributes.get("status", ""),
            "technology": value if asset_type == "technology" else "",
            "category": attributes.get("category", ""),
            "version": attributes.get("version", ""),
            "confidence": attributes.get("confidence", ""),
            "sources": sorted(source for source in (raw_sources or "").split(",") if source),
        })
    return assets


def _report_metadata(database: str, run: ScanRun) -> dict:
    evidence = []
    failures = []
    stages = []
    request_metrics = {}
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
                elif kind in {"http_error", "dns_error", "discovered_dns_error", "ct_error"}:
                    failures.append(record | {"detail": content.get("error") or content.get("reason") or "unknown error"})
                evidence.append(record)
    return {"evidence": evidence, "failures": failures, "stages": stages, "request_metrics": request_metrics}


def render_html_report(database: str, run: ScanRun) -> str:
    assets = _owned_rows(database, run)
    metadata = _report_metadata(database, run)
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
:root {{ color-scheme: light; font: 15px system-ui, sans-serif; }}
body {{ margin: 0; color: #17202a; background: #f5f7f9; }}
header {{ padding: 24px 5vw; background: #17202a; color: #fff; }}
main {{ max-width: 1400px; margin: 0 auto; padding: 24px 5vw; }}
.filters {{ display: grid; grid-template-columns: repeat(auto-fit,minmax(150px,1fr)); gap: 10px; margin-bottom: 18px; }}
label {{ display: grid; gap: 4px; font-size: 12px; font-weight: 650; }}
input, select {{ min-height: 36px; border: 1px solid #c7d0d9; border-radius: 4px; padding: 6px 8px; background: #fff; }}
.count {{ margin: 10px 0; color: #52606d; }}
.stats {{ display: grid; grid-template-columns: repeat(auto-fit,minmax(130px,1fr)); gap: 10px; margin: 18px 0; }}
.stat {{ padding: 12px; background: #fff; border: 1px solid #d9e0e6; }}
.stat strong {{ display: block; font-size: 1.35rem; }}
section {{ margin-top: 24px; }}
section h2 {{ font-size: 1.1rem; }}
.table-wrap {{ overflow-x: auto; background: #fff; border: 1px solid #d9e0e6; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ padding: 9px 10px; border-bottom: 1px solid #e8edf1; text-align: left; vertical-align: top; }}
th {{ background: #eef2f5; position: sticky; top: 0; }}
code {{ overflow-wrap: anywhere; }}
@media (max-width: 600px) {{ header, main {{ padding-left: 14px; padding-right: 14px; }} th, td {{ padding: 7px; }} }}
</style></head><body>
<header><strong>SH4Q</strong><div>Scan report for <code>{html.escape(run.target)}</code></div><small>{html.escape(run.id)} · {html.escape(run.status)}</small></header>
<main><div class="stats">
<div class="stat"><strong>{len(assets)}</strong>scan-owned assets</div>
<div class="stat"><strong>{len(metadata["evidence"])}</strong>evidence records</div>
<div class="stat"><strong>{len(metadata["failures"])}</strong>failures</div>
<div class="stat"><strong>{len(metadata["stages"])}</strong>stages</div>
</div><section class="filters" aria-label="Report filters">
<label>Search<input id="search" type="search" placeholder="hostname, URL, technology"></label>
<label>Asset type<select id="type"><option value="">All</option></select></label>
<label>Target / host<select id="host"><option value="">All</option></select></label>
<label>Status<select id="status"><option value="">All</option></select></label>
<label>Technology / category<select id="technology"><option value="">All</option></select></label>
<label>Source<select id="source"><option value="">All</option></select></label>
</section><div class="count" id="count"></div>
<div class="table-wrap"><table><thead><tr><th>Type</th><th>Value</th><th>Host / target</th><th>Status</th><th>Technology</th><th>Category</th><th>Source</th></tr></thead>
<tbody id="rows"></tbody></table></div>
<section><h2>Failures</h2><div class="table-wrap"><table><thead><tr><th>Plugin</th><th>Kind</th><th>Detail</th><th>Captured</th></tr></thead><tbody>{''.join(f'<tr><td>{html.escape(item["plugin"])}</td><td>{html.escape(item["kind"])}</td><td>{html.escape(item["detail"])}</td><td>{html.escape(item["captured_at"])}</td></tr>' for item in metadata["failures"]) or '<tr><td colspan="4">No recorded failures.</td></tr>'}</tbody></table></div></section>
<section><h2>Stage timings</h2><div class="table-wrap"><table><thead><tr><th>Stage</th><th>Status</th><th>Attempts</th><th>Findings</th><th>Duration</th></tr></thead><tbody>{''.join(f'<tr><td>{html.escape(str(item.get("name", "")))}</td><td>{html.escape(str(item.get("status", "")))}</td><td>{item.get("attempts", 0)}</td><td>{item.get("discoveries", 0)}</td><td>{item.get("duration_seconds", 0)}s</td></tr>' for item in metadata["stages"]) or '<tr><td colspan="5">No persisted stage metrics.</td></tr>'}</tbody></table></div></section>
<section><h2>Request metrics</h2><pre>{html.escape(json.dumps(metadata["request_metrics"], indent=2, sort_keys=True))}</pre></section>
<section><h2>Evidence index</h2><div class="count">{len(metadata["evidence"])} records retained for this scan.</div></section></main>
<script>
const report = {_safe_json(payload)};
const fields = {{type: document.querySelector('#type'), host: document.querySelector('#host'), status: document.querySelector('#status'), technology: document.querySelector('#technology'), source: document.querySelector('#source'), search: document.querySelector('#search')}};
const values = (key) => [...new Set(report.assets.flatMap(a => key === 'source' ? a.sources : [a[key]]).filter(Boolean))].sort();
for (const [key, select] of Object.entries(fields)) if (select.tagName === 'SELECT') for (const value of values(key)) select.add(new Option(value, value));
function render() {{
 const query = fields.search.value.toLowerCase();
 const filtered = report.assets.filter(a => (!fields.type.value || a.type === fields.type.value) && (!fields.host.value || a.host === fields.host.value) && (!fields.status.value || String(a.status) === fields.status.value) && (!fields.technology.value || a.technology === fields.technology.value || a.category === fields.technology.value) && (!fields.source.value || a.sources.includes(fields.source.value)) && (!query || JSON.stringify(a).toLowerCase().includes(query)));
 document.querySelector('#count').textContent = `${{filtered.length}} of ${{report.assets.length}} scan-owned assets`;
 const esc = value => String(value ?? '').replace(/[&<>\"']/g, char => ({{'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',"'":'&#39;'}}[char]));
 document.querySelector('#rows').innerHTML = filtered.map(a => `<tr><td>${{esc(a.type)}}</td><td><code>${{esc(a.value)}}</code></td><td>${{esc(a.host)}}</td><td>${{esc(a.status)}}</td><td>${{esc(a.technology)}}</td><td>${{esc(a.category)}}</td><td>${{esc(a.sources.join(', '))}}</td></tr>`).join('');
}}
Object.values(fields).forEach(input => input.addEventListener('input', render)); render();
</script></body></html>\n"""
