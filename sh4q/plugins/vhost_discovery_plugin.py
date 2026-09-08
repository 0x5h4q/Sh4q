from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
from collections.abc import Iterable
from urllib.parse import urlsplit

import httpx

from sh4q.network import ScopedHTTPClient, ScopedHTTPError
from sh4q.scope import ScopeEngine

from .discovery import Discovery
from .interface import Plugin, PluginMetadata


class VhostDiscoveryPlugin(Plugin):
    """Probe an operator-supplied, bounded list of virtual-host candidates."""

    metadata = PluginMetadata(
        name="vhost-discovery",
        dependencies=["http"],
        timeout=120.0,
        risk_level="active-low",
        retry_on_timeout=False,
    )

    def __init__(
        self,
        scope: ScopeEngine,
        candidates_file: str | Path | None = None,
        candidates: Iterable[str] | None = None,
        *,
        max_candidates: int = 500,
        client_factory=None,
        endpoint_scheme: str = "https",
        endpoint_port: int = 443,
        request_interval: float = 1.0,
    ):
        if max_candidates < 1:
            raise ValueError("max_candidates must be positive")
        if endpoint_scheme not in {"http", "https"}:
            raise ValueError("endpoint_scheme must be http or https")
        if request_interval < 0:
            raise ValueError("request_interval must not be negative")
        self._scope = scope
        self._file = Path(candidates_file) if candidates_file is not None else Path("")
        self._provided_candidates = list(candidates) if candidates is not None else None
        self._discovered_candidates: list[str] = []
        self._max_candidates = max_candidates
        self._client_factory = client_factory or (
            lambda: ScopedHTTPClient(scope, timeout=15.0)
        )
        self._scheme = endpoint_scheme
        self._port = endpoint_port
        self._request_interval = request_interval
        # The scheduler must allow the configured bounded workload to finish.
        # A fixed timeout silently discards every observation on larger lists.
        self.metadata = PluginMetadata(
            name="vhost-discovery",
            dependencies=["http"],
            timeout=max(120.0, (max_candidates + 1) * request_interval + 30.0),
            risk_level="active-low",
            retry_on_timeout=False,
        )

    def _candidates(self, target: str) -> list[tuple[str, int]]:
        if self._provided_candidates is not None:
            lines = list(enumerate(self._provided_candidates, 1))
        elif self._file != Path("") and self._file.is_file():
            lines = list(enumerate(self._file.read_text(encoding="utf-8").splitlines(), 1))
        elif self._discovered_candidates:
            lines = list(enumerate(self._discovered_candidates, 1))
        elif self._file != Path(""):
            raise ValueError(f"vhost candidate file not found: {self._file}")
        else:
            lines = []
        root = self._scope.normalize_target(target)
        seen: set[str] = set()
        result: list[tuple[str, int]] = []
        for line_number, raw in lines:
            value = raw.split("#", 1)[0].strip().rstrip(".")
            if not value:
                continue
            if "://" in value:
                parsed = urlsplit(value)
                value = parsed.hostname or ""
            value = self._scope.normalize_target(value)
            if "." not in value:
                value = f"{value}.{root}"
            if not value or value in seen:
                continue
            seen.add(value)
            if len(result) >= self._max_candidates:
                break
            if not self._scope.authorize(value, self._port).allowed:
                result.append((value, line_number))
            else:
                result.append((value, line_number))
        return result

    def accept_discoveries(self, discoveries: list[Discovery], source_plugin: str | None = None) -> None:
        if self._provided_candidates is not None or self._file != Path(""):
            return
        if source_plugin not in {"ct", "subfinder", "amass-passive"}:
            return
        self._discovered_candidates.extend(
            item.data.get("hostname", "") for item in discoveries
            if item.kind == "subdomain_found" and item.data.get("hostname")
        )

    async def execute(self, target: str) -> list[Discovery]:
        candidates = self._candidates(target)
        endpoint = f"{self._scheme}://{self._scope.normalize_target(target)}/"
        discoveries: list[Discovery] = []
        try:
            async with self._client_factory() as client:
                baseline = await self._probe(client, endpoint, target, target, None)
                baseline_fp = baseline.data.get("fingerprint") if baseline.kind == "vhost_observation" else None
                discoveries.append(Discovery(kind="vhost_baseline", data={"endpoint": endpoint, "fingerprint": baseline_fp}))
                for candidate, line_number in candidates:
                    decision = self._scope.authorize(candidate, self._port)
                    if not decision.allowed:
                        discoveries.append(Discovery(kind="vhost_rejected", data={"candidate": candidate, "line": line_number, "reason": decision.reason}))
                        continue
                    if self._request_interval:
                        await asyncio.sleep(self._request_interval)
                    result = await self._probe(client, endpoint, target, candidate, line_number)
                    if result.kind == "vhost_observation" and result.data.get("fingerprint") == baseline_fp:
                        result.data["classification"] = "default_vhost_match"
                    discoveries.append(result)
        except asyncio.CancelledError:
            # Return observations captured before cancellation so the event
            # bus can persist a useful partial stage instead of losing all data.
            discoveries.append(Discovery(kind="vhost_partial", data={
                "endpoint": endpoint, "captured": len(discoveries),
            }))
            return discoveries
        return discoveries

    async def _probe(self, client, endpoint: str, target: str, candidate: str, line_number: int | None) -> Discovery:
        try:
            response, body, truncated = await client.get_text_bounded(
                endpoint, 65536, headers={"Host": candidate}, follow_redirects=False
            )
            body_bytes = body.encode("utf-8", errors="replace")
            declared_length = response.headers.get("content-length")
            content_length = int(declared_length) if declared_length and declared_length.isdigit() else len(body_bytes)
            fingerprint = hashlib.sha256(
                f"{response.status_code}|{response.headers.get('content-type', '')}|{content_length}|".encode() + body_bytes
            ).hexdigest()
            return Discovery(kind="vhost_observation", data={
                "candidate": candidate, "endpoint": endpoint, "status": response.status_code,
                "location": response.headers.get("location", ""), "content_length": content_length,
                "body_truncated": truncated, "fingerprint": fingerprint, "line": line_number,
            })
        except asyncio.CancelledError:
            raise
        except (httpx.HTTPError, ScopedHTTPError, OSError) as error:
            return Discovery(kind="vhost_error", data={
                "candidate": candidate, "endpoint": endpoint, "line": line_number,
                "error": str(error).strip() or f"{type(error).__name__} without detail",
            })
