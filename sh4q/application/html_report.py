from __future__ import annotations

import html
import json
import base64
from pathlib import Path
from urllib.parse import urlsplit

from sh4q.storage.db import open_sync_database
from sh4q.storage.scan_runs import ScanRun


def _safe_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=True).replace("<", "\\u003c")


def _banner_data_uri() -> str | None:
    path = Path(__file__).resolve().parents[2] / "banner.png"
    if not path.is_file():
        return None
    return "data:image/png;base64," + base64.b64encode(path.read_bytes()).decode("ascii")


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
    for asset_type, value, raw_attributes, raw_sources in rows:
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
        assets.append({
            "type": asset_type,
            "value": value,
            "host": host,
            "status": status,
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
    banner_uri = _banner_data_uri()
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
body {{ margin: 0; color: #17202a; background: #eef2f5; }}
header {{ padding: 30px 5vw 32px; background: #17202a; color: #fff; border-bottom: 4px solid #2c9c94; text-align: center; }}
.brand {{ max-width: 1400px; margin: 0 auto; }}
.brand img {{ display: block; width: min(620px, 88vw); max-height: 250px; object-fit: contain; margin: 0 auto 20px; border-radius: 5px; background: #f5f7f9; }}
.brand-copy {{ min-width: 0; }}
header strong {{ display: block; color: #7de0d5; font-size: 1.35rem; letter-spacing: .12em; }}
header div {{ margin-top: 7px; font-size: 1.2rem; }}
header small {{ display: block; margin-top: 10px; color: #b9c6d1; }}
main {{ max-width: 1400px; margin: 0 auto; padding: 26px 5vw 40px; }}
.stats {{ display: grid; grid-template-columns: repeat(auto-fit,minmax(160px,1fr)); gap: 12px; margin: 0 0 22px; }}
.stat {{ padding: 16px; background: #fff; border: 1px solid #d5dee6; border-radius: 6px; box-shadow: 0 2px 8px rgba(23,32,42,.05); }}
.stat strong {{ display: block; color: #17202a; font-size: 1.55rem; line-height: 1.2; }}
.filters {{ display: grid; grid-template-columns: repeat(auto-fit,minmax(180px,1fr)); gap: 12px; align-items: end; padding: 16px; margin-bottom: 14px; background: #fff; border: 1px solid #d5dee6; border-radius: 6px; }}
label {{ display: grid; min-width: 0; gap: 5px; color: #344454; font-size: 12px; font-weight: 700; }}
input, select {{ box-sizing: border-box; width: 100%; min-width: 0; min-height: 38px; border: 1px solid #bdc9d3; border-radius: 4px; padding: 7px 9px; color: #17202a; background: #fff; font: inherit; }}
input:focus, select:focus {{ outline: 2px solid #7de0d5; outline-offset: 1px; border-color: #2c9c94; }}
.filter-actions {{ display: flex; align-items: end; }}
button {{ min-height: 38px; border: 1px solid #8797a5; border-radius: 4px; padding: 7px 12px; color: #17202a; background: #f4f7f9; font: inherit; font-weight: 650; cursor: pointer; }}
button:hover {{ background: #e6edf1; }}
.count {{ margin: 12px 0; color: #52606d; font-weight: 600; }}
section {{ margin-top: 28px; }}
section h2 {{ margin: 0 0 10px; color: #253647; font-size: 1.1rem; }}
.table-wrap {{ overflow-x: auto; background: #fff; border: 1px solid #d5dee6; border-radius: 6px; box-shadow: 0 2px 8px rgba(23,32,42,.04); }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ padding: 10px 11px; border-bottom: 1px solid #e8edf1; text-align: left; vertical-align: top; }}
th {{ color: #344454; background: #e8eef2; position: sticky; top: 0; font-size: 12px; text-transform: uppercase; }}
tbody tr:hover {{ background: #f3faf9; }}
tbody tr:last-child td {{ border-bottom: 0; }}
td code {{ white-space: nowrap; overflow-wrap: normal; }}
pre {{ overflow-x: auto; padding: 14px; border: 1px solid #d5dee6; border-radius: 6px; background: #17202a; color: #dbe7ef; }}
@media (max-width: 600px) {{ header, main {{ padding-left: 14px; padding-right: 14px; }} .brand img {{ width: min(430px, 90vw); max-height: 180px; }} header div {{ font-size: 1.05rem; }} th, td {{ padding: 8px; }} .stats {{ grid-template-columns: repeat(2,minmax(0,1fr)); }} }}
</style></head><body>
<header><div class="brand">{f'<img src="{banner_uri}" alt="SH4Q" />' if banner_uri else ''}<div class="brand-copy">{'' if banner_uri else '<strong>SH4Q</strong>'}<div>Scan report for <code>{html.escape(run.target)}</code></div><small>{html.escape(run.id)} · {html.escape(run.status)}</small></div></div></header>
<main><div class="stats">
<div class="stat"><strong>{len(assets)}</strong>scan-owned assets</div>
<div class="stat"><strong>{len(metadata["evidence"])}</strong>evidence records</div>
<div class="stat"><strong>{len(metadata["failures"])}</strong>failures</div>
<div class="stat"><strong>{len(metadata["stages"])}</strong>stages</div>
</div><section class="filters" aria-label="Report filters">
<label>Search<input id="search" type="search" placeholder="hostname, URL, technology"></label>
<label>Asset type<select id="type"><option value="">All</option></select></label>
<label>Target / host<select id="host"><option value="">All</option></select></label>
<label>HTTP status<select id="status"><option value="">All</option></select></label>
<label>Technology / category<select id="technology"><option value="">All</option></select></label>
<label>Source<select id="source"><option value="">All</option></select></label>
<div class="filter-actions"><button id="reset" type="button">Reset filters</button></div>
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
 const shown = value => value === '' || value == null ? '-' : value;
 document.querySelector('#rows').innerHTML = filtered.map(a => `<tr><td>${{esc(a.type)}}</td><td><code>${{esc(a.value)}}</code></td><td>${{esc(shown(a.host))}}</td><td>${{esc(shown(a.status))}}</td><td>${{esc(shown(a.technology))}}</td><td>${{esc(shown(a.category))}}</td><td>${{esc(a.sources.length ? a.sources.join(', ') : '-')}}</td></tr>`).join('') || '<tr><td colspan="7">No assets match these filters.</td></tr>';
}}
Object.values(fields).forEach(input => input.addEventListener('input', render)); render();
document.querySelector('#reset').addEventListener('click', () => {{
 Object.values(fields).forEach(input => input.value = ''); render();
}});
</script></body></html>\n"""
