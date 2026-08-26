# Research and Source Collection Workflow

## Purpose

This workflow automates source discovery and organisation without treating automatically generated metadata or AI summaries as authoritative. The researcher remains responsible for opening, verifying, and citing the original publication.

## Recommended Tool Chain

1. **OpenAlex and Crossref** discover papers and return DOI, title, author, year, venue, abstract, and links through public scholarly metadata APIs.
2. **Google Scholar, IEEE Xplore, ACM Digital Library, SpringerLink, ScienceDirect, Scopus, Web of Science, and the university library** are used to confirm relevance and obtain the authoritative full text.
3. **Zotero** is the source of record. Store the PDF, DOI, publisher URL, tags, notes, and page-specific quotations there. Use the Zotero Word plugin to insert APA 7 citations.
4. **NotebookLM** may compare verified PDFs and identify themes, disagreements, and research gaps. It must never be cited as a source.

## Search and Verification Process

Create a search manifest with one row per research concept:

```text
concept,query,source_database,date_searched,results_reviewed,selected_count
scope safety,"DNS rebinding prevention SSRF",OpenAlex,YYYY-MM-DD,50,8
```

For each candidate source:

- deduplicate by DOI, then by normalised title;
- verify the title, authors, year, venue, DOI, and publication type against the publisher or library record;
- download the full text only through legitimate access;
- record why the paper is relevant and which chapter it supports;
- mark peer-reviewed, standard, technical report, or tool documentation separately.

Start with 15-20 strong sources, then expand to the supervisor-approved target (usually 35-50 or more). Do not inflate the bibliography with papers that are never discussed.

## Automated Metadata Helper

The repository may contain a small collector that queries OpenAlex for candidate metadata and writes CSV/JSON. It should be used for discovery only, respect API limits, cache responses, and never overwrite the Zotero library. A human must verify every selected record before citation.

Suggested command shape:

```bash
python tools/collect_sources.py \
  --query "DNS rebinding prevention SSRF" \
  --output docs/research/openalex-dns-rebinding.csv
```

Store manifests and review notes in `docs/research/`; do not commit downloaded copyrighted PDFs unless permitted.

## Literature Matrix Fields

Track: citation key, research problem, method, sample/data, findings, limitation, relevance to Sh4q, chapter, evidence location, verification status, and whether the source is peer-reviewed.

## Academic Integrity Controls

Never copy AI-generated prose without checking the cited paper. Every important claim in Chapters One and Two must have a source and page/section note. Keep a source audit trail showing search date, database, query, inclusion decision, and verification status.

## Outputs for the Thesis

The workflow produces a verified APA 7 bibliography, a literature matrix for Chapter Two, a search-method appendix, and an audit trail demonstrating how sources were selected. This makes the literature review reproducible without claiming that automation replaces scholarly judgement.
