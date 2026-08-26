"""Collect candidate scholarly metadata from OpenAlex for human verification."""

import argparse
import csv
import json
import urllib.parse
import urllib.request
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--query", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--per-page", type=int, default=25)
    args = parser.parse_args()

    params = urllib.parse.urlencode({"search": args.query, "per-page": min(args.per_page, 100)})
    request = urllib.request.Request(
        f"https://api.openalex.org/works?{params}",
        headers={"User-Agent": "sh4q-research-helper/1.0"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        payload = json.load(response)

    rows = []
    for work in payload.get("results", []):
        primary = work.get("primary_location") or {}
        source = primary.get("source") or {}
        rows.append(
            {
                "title": work.get("title", ""),
                "year": work.get("publication_year", ""),
                "doi": work.get("doi", ""),
                "type": work.get("type", ""),
                "cited_by_count": work.get("cited_by_count", 0),
                "venue": source.get("display_name", ""),
                "landing_page": primary.get("landing_page_url", ""),
                "open_access": bool((work.get("open_access") or {}).get("is_oa")),
                "authors": "; ".join(
                    (author.get("author") or {}).get("display_name", "")
                    for author in work.get("authorships", [])
                ),
            }
        )

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=rows[0].keys() if rows else ["title"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {len(rows)} candidate records to {output}")


if __name__ == "__main__":
    main()
