from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "Sh4q_Architecture_Progress_Review.docx"

REPLACEMENTS = {
    "Engineering Documentation — Updated through Week 4 MVP and live-domain validation": "Engineering Documentation — Updated through private-alpha preparation",
    "Week 4 MVP milestone complete": "Private-alpha preparation milestone",
    "Scope Engine, Scheduler, DNS, HTTP, Event Bus, Discovery Handler, SQLite persistence, Evidence Store, durable replay": "Scope Engine, Scheduler, DNS, HTTP, CT, Subfinder, discovered-host enrichment, scan ownership, SQLite persistence, exports, reporting, evidence and durable replay",
    "Live scans against eight real domains plus dedicated crash-recovery tests": "Live-domain checks plus deterministic offline validation and export/reporting checks",
    "Phases 1–3; approximately 10 plugins": "Current MVP plus controlled adapter expansion",
    "The MVP has also been exercised against eight real domains—github.com, iana.org, wikipedia.org, mozilla.org, python.org, cloudflare.com, microsoft.com and nasa.gov.": "The MVP has been exercised against varied live domains and controlled fixtures, including DNS failures, HTTP blocks, redirects, provider degradation and rate limiting.",
    "Subdomain enumeration and certificate-transparency enumeration.": "Broad adapter coverage beyond the current Subfinder, CT and native discovery paths.",
    "Technology fingerprinting.": "Deep technology fingerprinting beyond conservative response-header observations.",
    "Phase 2": "Phase 2",
    "DNS, HTTP, port scanning, technology detection, subdomain enumeration, reporting": "DNS, HTTP, CT, Subfinder, discovered-host enrichment, technology observations and reporting",
    "Active roadmap": "Implemented MVP surface",
    "Subdomain enumeration — highest current capability gap and the first major test of the event/evidence/graph architecture at higher discovery volume.": "Presentation polish, clean-install verification, private-alpha feedback, and repeated performance measurement.",
    "Certificate-transparency discovery and passive hostname intelligence.": "Add the next passive adapter only after the current controlled contract is reviewed.",
    "Technology detection and/or port/service discovery based on plugin-contract fit.": "Expand technology signatures conservatively and keep observations distinct from verified software inventory.",
    "Reporting improvements that expose normalized relationships without requiring direct SQLite inspection.": "HTML reporting and richer filtering remain the next user-facing reporting step.",
    "Technology results are displayed per endpoint with status, category, confidence, version, and supporting signal.": "Technology results are displayed per endpoint with status, category, confidence, version, and supporting signal.",
    "The Week 4 milestone changes Sh4q's status from an architecture prototype into a functioning MVP engine.": "The current milestone changes Sh4q's status from an architecture prototype into a functioning, auditable MVP prepared for limited private-alpha testing.",
    "Weeks 5–6: subdomain enumeration first, followed by additional discovery modules and reporting, while preserving the frozen engine contracts unless real plugin behavior demonstrates concrete schema pressure.": "Private alpha: presentation polish, clean-install verification, controlled feedback, repeated benchmarks, and one carefully selected next adapter.",
    "Weeks 5–6: subdomain enumeration first, followed by additional discovery modules and reporting, while preserving the frozen engine contracts unless real plugin behavior demonstrates a concrete need to change them.": "Private alpha: presentation polish, clean-install verification, controlled feedback, repeated benchmarks, and one carefully selected next adapter.",
    "JavaScript analysis, cloud enumeration, certificate transparency, passive intelligence, screenshots, secret discovery": "JavaScript analysis, cloud enumeration, deeper passive intelligence, screenshots and secret discovery",
    "The validated implementation had a clean working tree and HEAD at commit 9f1b73b (Fix scan pipeline, scope handling, and relationship counting) before the later Week 4 documentation update.": "The review is maintained alongside the implementation history; the current repository state is recorded by Git commits and the authoritative architecture.md record.",
    "│   ├── events/": "│   ├── adapters/ (controlled runner, Subfinder, fingerprinting)",
    "│   │   ├── dns_plugin.py": "│   ├── events/ and handlers.py",
    "│   │   ├── http_plugin.py": "│   ├── plugins/ and scheduler.py",
    "│   │   └── interface.py": "│   ├── scope/ and storage/",
    "│   ├── handlers.py": "│   ├── config/ and network services",
    "│   ├── scheduler.py": "│   ├── docs/ and tools/",
    "│   ├── scope/": "│   ├── tests/ and .github/workflows/",
    "│   └── storage/": "│   └── README.md",
    "└── venv/": "└── pyproject.toml",
    "The Application/Scan Runner and CLI layers are additive orchestration layers. Proven scheduler, handler, storage and plugin boundaries are not being reshuffled merely for aesthetic reasons.": "The application, CLI, adapter, scheduler, handler, scope, and storage layers remain separate ownership boundaries. A tester distribution should omit local virtual environments, scan databases, generated exports, and private academic records.",
    "Document Maintenance Note": "Document Maintenance Note",
}


def main():
    temp = PATH.with_suffix(".tmp.docx")
    with ZipFile(PATH) as source:
        files = {name: source.read(name) for name in source.namelist()}
    data = files["word/document.xml"].decode("utf-8")
    for old, new in REPLACEMENTS.items():
        data = data.replace(old, new)
    files["word/document.xml"] = data.encode("utf-8")
    with ZipFile(temp, "w", ZIP_DEFLATED) as target:
        for name, content in files.items():
            target.writestr(name, content)
    temp.replace(PATH)
    print(f"Updated {PATH}")


if __name__ == "__main__":
    main()
