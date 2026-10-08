"""Relevance triage over already-persisted JavaScript and history observations.

Pure presentation: the classifiers never authorize, persist, or reclassify
inventory. Cases below are shaped like the globe.gov run that motivated them
(Liferay theme assets, OAuth endpoints, license boilerplate inside bundles,
Wayback admin paths) without depending on any of those hosts.
"""

from sh4q.application.triage import (
    HISTORY_BUCKETS,
    JS_BUCKETS,
    classify_historical_url,
    classify_javascript_reference,
)


def check(bucket, reasons, expected):
    assert bucket == expected, f"{bucket} != {expected} ({reasons})"
    assert isinstance(reasons, tuple) and reasons, "reasons must explain the bucket"


# --- JavaScript reference buckets -------------------------------------------

# API routes rank first among same-host findings.
check(*classify_javascript_reference("https://example.com/api/me"), "api-route")
check(*classify_javascript_reference("https://example.com/o/auth/login"), "auth-flow")
check(*classify_javascript_reference("https://example.com/o/oauth2/token"), "auth-flow")

# Static assets sink below routes.
check(*classify_javascript_reference("https://example.com/o/theme/js/app.js"), "static-asset")
check(*classify_javascript_reference(
    "https://example.com/combo?browserId=other&minifierType=js&/o/x.js",
), "static-asset")

# Anything else same-host is a page route.
check(*classify_javascript_reference("https://example.com/home"), "page-route")
check(*classify_javascript_reference("https://example.com/"), "page-route")

# A different host than the linking page is third-party evidence, not inventory.
check(
    *classify_javascript_reference(
        "https://cdn.example.net/lib.js", "https://example.com/"
    ),
    "third-party",
)
# No source endpoint means no host comparison is possible: judge the path.
check(*classify_javascript_reference("https://cdn.example.net/api/x"), "api-route")

# Library-embedded boilerplate is recognizable by shape, not by domain.
check(*classify_javascript_reference("https://example.com/node_modules/x/LICENSE.txt"), "boilerplate")
check(*classify_javascript_reference("https://example.com/AUTHORS.txt"), "boilerplate")
check(*classify_javascript_reference("http://a"), "boilerplate")
check(*classify_javascript_reference("http://x"), "boilerplate")

# Auth beats api when both match: /api/oauth/token is an auth finding.
check(*classify_javascript_reference("https://example.com/api/oauth/token"), "auth-flow")

# Buckets are the documented set, and triage never raises.
assert JS_BUCKETS == (
    "boilerplate", "third-party", "auth-flow",
    "api-route", "static-asset", "page-route",
)
check(*classify_javascript_reference("not a url at all"), "unparseable")
check(*classify_javascript_reference(""), "unparseable")


# --- historical URL buckets ---------------------------------------------------

check(*classify_historical_url("https://example.com/admin/"), "admin-console")
check(*classify_historical_url("https://example.com/wp-admin/upload.php"), "admin-console")
check(*classify_historical_url("https://example.com/api/users"), "api-surface")
check(*classify_historical_url("https://example.com/o/oauth2/authorize"), "auth-flow")
check(*classify_historical_url("https://example.com/static/app.js?v=2"), "static-asset")
check(*classify_historical_url("https://example.com/search?q=x"), "parameterized")
check(*classify_historical_url("https://example.com/about"), "page")

# Admin beats api when both match: /api/admin/users is an admin finding.
check(*classify_historical_url("https://example.com/api/admin/users"), "admin-console")
# A static asset with a query is still a static asset, not a parameter to test.
check(*classify_historical_url("https://example.com/app.js?v=2"), "static-asset")

assert HISTORY_BUCKETS == (
    "admin-console", "api-surface", "auth-flow",
    "static-asset", "parameterized", "page",
)
check(*classify_historical_url(":::bad:::"), "unparseable")


print("triage test passed")


# --- wiring: relevance reaches the results view ------------------------------
# The classifier alone helps nobody; the listing must carry the bucket.
import asyncio
import os
import tempfile

from sh4q.application.results import list_javascript_observations
from sh4q.storage.evidence import Evidence, SQLiteEvidenceStore
from sh4q.storage import SQLiteStorage


async def _wiring_main() -> None:
    handle, db_path = tempfile.mkstemp(prefix="sh4q_triage_", suffix=".db")
    os.close(handle)
    os.remove(db_path)
    try:
        storage = SQLiteStorage(db_path)
        await storage.init()
        evidence = SQLiteEvidenceStore(db_path)
        await evidence.init()
        await evidence.append(Evidence(
            id="t0", target="example.com", plugin="javascript-extraction",
            kind="javascript_endpoint_reference",
            content={
                "value": "https://example.com/api/me",
                "source_endpoint": "https://example.com/",
            },
            scan_run_id="scan-t",
        ))
        await evidence.append(Evidence(
            id="t1", target="example.com", plugin="javascript-extraction",
            kind="javascript_script_url",
            content={
                "value": "https://example.com/vendor/LICENSE.txt",
                "source_endpoint": "https://example.com/",
            },
            scan_run_id="scan-t",
        ))
        rows = list_javascript_observations(db_path, scan_id="scan-t")
        by_value = {row.value: row for row in rows}
        assert by_value["https://example.com/api/me"].relevance == "api-route", by_value
        assert by_value["https://example.com/vendor/LICENSE.txt"].relevance == "boilerplate", by_value
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


asyncio.run(_wiring_main())

print("triage wiring test passed")
