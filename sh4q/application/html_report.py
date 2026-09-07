from __future__ import annotations

import html
import json
import base64
from pathlib import Path
from urllib.parse import urlsplit

from sh4q.storage.db import open_sync_database
from sh4q.storage.scan_runs import ScanRun
from sh4q.application.redaction import redact_url


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


def _owned_rows(database: str, run: ScanRun, *, redact: bool = False) -> list[dict]:
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
        display_value = redact_url(value) if redact and display_type in {"url", "historical-url"} else value
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


def _report_metadata(database: str, run: ScanRun) -> dict:
    evidence = []
    failures = []
    stages = []
    request_metrics = {}
    historical_urls_truncated = 0
    historical_urls_rejected = 0
    javascript = []
    vhosts = []
    vhost_rejections = []
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
                        "value": content.get("value", ""),
                        "source_endpoint": content.get("source_endpoint", ""),
                        "pattern": content.get("pattern", ""),
                    })
                elif kind in {"vhost_baseline", "vhost_observation"}:
                    vhosts.append(record | {
                        "candidate": content.get("candidate", ""),
                        "endpoint": content.get("endpoint", ""),
                        "status": content.get("status", ""),
                        "classification": content.get("classification", "baseline" if kind == "vhost_baseline" else "candidate_observation"),
                        "location": content.get("location", ""),
                    })
                elif kind == "vhost_rejected":
                    vhost_rejections.append(record | {
                        "candidate": content.get("candidate", ""),
                        "reason": content.get("reason", "unknown reason"),
                    })
                elif kind in {"http_error", "dns_error", "discovered_dns_error", "ct_error"}:
                    failures.append(record | {"detail": content.get("error") or content.get("reason") or "unknown error"})
                elif kind == "vhost_error":
                    failures.append(record | {"detail": content.get("error") or "unknown error"})
                evidence.append(record)
    javascript.sort(key=lambda item: (item["source_endpoint"], item["kind"], item["value"]))
    return {"evidence": evidence, "failures": failures, "javascript": javascript, "vhosts": vhosts,
            "vhost_rejections": vhost_rejections, "stages": stages, "request_metrics": request_metrics,
            "historical_urls_rejected": historical_urls_rejected,
            "historical_urls_truncated": historical_urls_truncated}


def render_html_report(database: str, run: ScanRun, *, redact: bool = False) -> str:
    assets = _owned_rows(database, run, redact=redact)
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
body.dark {{ color: #dbe7ef; background: #111820; }}
header {{ padding: 24px 5vw 30px; background: #f5f7f9; color: #17202a; border-bottom: 4px solid #2c9c94; text-align: center; }}
.brand {{ max-width: 1400px; margin: 0 auto; }}
.brand img {{ display: block; width: min(820px, 92vw); max-height: 340px; object-fit: contain; margin: 0 auto 18px; }}
.brand-copy {{ min-width: 0; }}
header strong {{ display: block; color: #167d76; font-size: 1.35rem; letter-spacing: .12em; }}
header div {{ margin-top: 7px; font-size: 1.2rem; }}
header small {{ display: block; margin-top: 10px; color: #52606d; }}
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
.theme-toggle {{ position: absolute; top: 16px; right: 5vw; }}
.filters {{ position: relative; }}
.chips {{ display: flex; flex-wrap: wrap; gap: 6px; grid-column: 1 / -1; }}
.chip {{ border-radius: 12px; padding: 3px 9px; color: #155e59; background: #d9f4f0; font-size: 12px; }}
.sort {{ min-height: auto; padding: 2px 4px; border: 0; background: transparent; color: inherit; font-size: inherit; text-transform: inherit; }}
.sort:hover {{ background: #d7e3e8; }}
.status {{ display: inline-block; min-width: 2.5em; padding: 2px 6px; border-radius: 10px; text-align: center; font-size: 12px; font-weight: 700; }}
.status-2 {{ color: #146c43; background: #d1f0df; }} .status-3 {{ color: #725400; background: #fff0bd; }} .status-4 {{ color: #8a3b12; background: #ffe1c7; }} .status-5 {{ color: #9a2020; background: #ffd6d6; }}
.copy {{ min-height: auto; padding: 2px 6px; margin-left: 6px; font-size: 12px; }}
.pagination {{ display: flex; align-items: center; justify-content: flex-end; gap: 8px; margin: 10px 0; }}
.pagination button:disabled {{ cursor: not-allowed; opacity: .45; }}
body.dark header, body.dark .stat, body.dark .filters, body.dark .table-wrap {{ background: #18232d; color: #dbe7ef; border-color: #344756; }}
body.dark .brand img {{ padding: 12px; border-radius: 6px; background: #f5f7f9; }}
body.dark .stat strong, body.dark section h2, body.dark label, body.dark .count {{ color: #dbe7ef; }}
body.dark header small {{ color: #9fb2bf; }} body.dark .chip {{ color: #bff4eb; background: #214b4a; }}
body.dark input, body.dark select, body.dark button {{ color: #dbe7ef; background: #202f3b; border-color: #4a6170; }}
body.dark th {{ color: #dbe7ef; background: #263845; }} body.dark td {{ border-color: #2e414e; }} body.dark tbody tr:hover {{ background: #203a3d; }}
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
@media (max-width: 600px) {{ header, main {{ padding-left: 14px; padding-right: 14px; }} .brand img {{ width: min(540px, 94vw); max-height: 220px; }} header div {{ font-size: 1.05rem; }} th, td {{ padding: 8px; }} .stats {{ grid-template-columns: repeat(2,minmax(0,1fr)); }} }}
</style></head><body>
<header><button id="theme" class="theme-toggle" type="button" title="Toggle theme">Theme</button><div class="brand">{f'<img src="{banner_uri}" alt="SH4Q" />' if banner_uri else ''}<div class="brand-copy">{'' if banner_uri else '<strong>SH4Q</strong>'}<div>Scan report for <code>{html.escape(run.target)}</code></div><small>{html.escape(run.id)} · {html.escape(run.status)}</small></div></div></header>
<main><div class="stats">
<div class="stat"><strong>{len(assets)}</strong>scan-owned assets</div>
<div class="stat"><strong>{len(metadata["evidence"])}</strong>evidence records</div>
<div class="stat"><strong>{len(metadata["failures"])}</strong>failures</div>
<div class="stat"><strong>{len(metadata["stages"])}</strong>stages</div>
<div class="stat"><strong>{metadata["historical_urls_truncated"]}</strong>history truncated</div>
<div class="stat"><strong>{metadata["historical_urls_rejected"]}</strong>history rejected</div>
<div class="stat"><strong>{len(metadata["javascript"])}</strong>JavaScript observations</div>
<div class="stat"><strong>{len(metadata["vhosts"])}</strong>vhost observations</div>
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
<details open><summary>Failures</summary><section><div class="table-wrap"><table><thead><tr><th>Plugin</th><th>Kind</th><th>Detail</th><th>Captured</th></tr></thead><tbody>{''.join(f'<tr><td>{html.escape(item["plugin"])}</td><td>{html.escape(item["kind"])}</td><td>{html.escape(item["detail"])}</td><td>{html.escape(item["captured_at"])}</td></tr>' for item in metadata["failures"]) or '<tr><td colspan="4">No recorded failures.</td></tr>'}</tbody></table></div></section></details>
<details open><summary>JavaScript observations</summary><section><div class="table-wrap"><table><thead><tr><th>Type</th><th>Reference or pattern</th><th>Source endpoint</th><th>Captured</th></tr></thead><tbody>{''.join(f'<tr><td>{html.escape(item["kind"].removeprefix("javascript_"))}</td><td><code>{html.escape(str(item["value"]))}</code></td><td><code>{html.escape(str(item["source_endpoint"] or "-"))}</code></td><td>{html.escape(item["captured_at"])}</td></tr>' for item in metadata["javascript"]) or '<tr><td colspan="4">No JavaScript observations.</td></tr>'}</tbody></table></div><p>These are passive, unverified observations. They are not automatically requested or treated as confirmed secrets.</p></section></details>
<details open><summary>Virtual-host observations</summary><section><div class="table-wrap"><table><thead><tr><th>Candidate</th><th>Endpoint</th><th>Status</th><th>Classification</th><th>Redirect</th><th>Captured</th></tr></thead><tbody>{''.join(f'<tr><td><code>{html.escape(str(item["candidate"] or "baseline"))}</code></td><td><code>{html.escape(str(item["endpoint"] or "-"))}</code></td><td>{html.escape(str(item["status"] or "-"))}</td><td>{html.escape(str(item["classification"]))}</td><td>{html.escape(str(item["location"] or "-"))}</td><td>{html.escape(item["captured_at"])}</td></tr>' for item in metadata["vhosts"]) or '<tr><td colspan="6">No virtual-host observations.</td></tr>'}</tbody></table></div><h3>Rejected candidates</h3><ul>{''.join(f'<li><code>{html.escape(str(item["candidate"]))}</code>: {html.escape(str(item["reason"]))}</li>' for item in metadata["vhost_rejections"]) or '<li>No rejected candidates.</li>'}</ul><p>Virtual-host observations are bounded, scope-checked candidates and are not security findings.</p></section></details>
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
document.querySelector('#theme').addEventListener('click', () => {{ document.body.classList.toggle('dark'); localStorage.setItem('sh4q-theme', document.body.classList.contains('dark') ? 'dark' : 'light'); }}); if (localStorage.getItem('sh4q-theme') === 'dark') document.body.classList.add('dark'); render();
document.querySelector('#reset').addEventListener('click', () => {{
 Object.values(fields).forEach(input => input.value = ''); pageNumber = 1; render();
}});
</script></body></html>\n"""
