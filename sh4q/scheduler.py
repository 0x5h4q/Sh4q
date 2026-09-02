import asyncio
import random
import time
from typing import Any

from sh4q.events import Event, EventBus
from sh4q.plugins import Plugin
from sh4q.scope import ScopeEngine
from sh4q.cli.branding import status_line


class Scheduler:
    def __init__(
        self,
        plugins: list[Plugin],
        scope: ScopeEngine,
        bus: EventBus,
        *,
        max_retries: int = 2,
        retry_base_delay: float = 0.5,
        retry_max_delay: float = 8.0,
        retry_jitter: float = 0.25,
        scan_run_id: str | None = None,
    ):
        self._plugins = plugins
        self._scope = scope
        self._bus = bus

        self._max_retries = max(0, max_retries)
        self._retry_base_delay = max(0.0, retry_base_delay)
        self._retry_max_delay = max(
            self._retry_base_delay,
            retry_max_delay,
        )
        self._retry_jitter = max(0.0, retry_jitter)
        self.stage_durations: dict[str, float] = {}
        self.stage_outcomes: dict[str, dict] = {}
        self._scan_run_id = scan_run_id

    def _ordered_plugins(self) -> list[Plugin]:
        ordered: list[Plugin] = []
        remaining = list(self._plugins)
        done_names: set[str] = set()

        while remaining:
            progressed = False

            for plugin in list(remaining):
                if all(
                    dependency in done_names
                    for dependency in plugin.metadata.dependencies
                ):
                    ordered.append(plugin)
                    done_names.add(plugin.metadata.name)
                    remaining.remove(plugin)
                    progressed = True

            if not progressed:
                names = [
                    plugin.metadata.name
                    for plugin in remaining
                ]

                raise RuntimeError(
                    "Circular or unmet plugin dependency "
                    f"among: {names}"
                )

        return ordered

    def _retryable_discovery(
        self,
        discoveries: list[Any],
    ) -> bool:
        """
        Plugins can mark a discovery as retryable when the failure
        is transient and worth trying again.

        The Scheduler owns the retry mechanism itself:
        attempt counting, backoff, jitter, and exhaustion.
        """
        for discovery in discoveries:
            data = getattr(discovery, "data", {})

            if not isinstance(data, dict):
                continue

            if data.get("retryable") is True:
                return True

        return False

    def _backoff_delay(self, retry_number: int) -> float:
        """
        Exponential backoff with optional positive jitter.

        retry_number=1:
            base delay

        retry_number=2:
            base * 2

        retry_number=3:
            base * 4

        Capped at retry_max_delay.
        """
        exponential = self._retry_base_delay * (
            2 ** (retry_number - 1)
        )

        delay = min(
            exponential,
            self._retry_max_delay,
        )

        if self._retry_jitter:
            jitter = random.uniform(
                0.0,
                delay * self._retry_jitter,
            )
            delay += jitter

        return delay

    async def _execute_plugin(
        self,
        plugin: Plugin,
        target: str,
    ) -> list[Any]:

        total_attempts = self._max_retries + 1
        stage_name = plugin.metadata.name

        for attempt in range(1, total_attempts + 1):

            print(status_line(
                f"EXECUTE {plugin.metadata.name} "
                f"on {target} "
                f"(attempt {attempt}/{total_attempts})"
            ))

            try:
                discoveries = await asyncio.wait_for(
                    plugin.execute(target),
                    timeout=plugin.metadata.timeout,
                )

            except asyncio.TimeoutError:
                print(status_line(
                    f"TIMEOUT {plugin.metadata.name} "
                    f"on {target} "
                    f"(attempt {attempt}/{total_attempts})"
                , "error"))

                # Timeout is treated as a transient execution failure.
                # Retry it using the Scheduler's generic retry policy.
                if attempt >= total_attempts or not plugin.metadata.retry_on_timeout:
                    message = (
                        f"RETRY EXHAUSTED {plugin.metadata.name} on {target} "
                        f"after {attempt} attempts"
                        if plugin.metadata.retry_on_timeout
                        else f"TIMEOUT {plugin.metadata.name} on {target}; retries disabled"
                    )
                    print(status_line(message, "error"))
                    self.stage_outcomes[stage_name] = {
                        "status": "timeout_exhausted" if plugin.metadata.retry_on_timeout else "timeout",
                        "attempts": attempt, "discoveries": 0
                    }
                    return []

                delay = self._backoff_delay(attempt)

                print(status_line(
                    f"RETRY {plugin.metadata.name} "
                    f"on {target}: "
                    f"attempt {attempt + 1}/{total_attempts} "
                    f"in {delay:.2f}s"
                ))

                await asyncio.sleep(delay)
                continue

            except Exception as e:
                print(status_line(
                    f"ERROR {plugin.metadata.name} "
                    f"on {target}: {e}"
                , "error"))

                # Generic unexpected exceptions are NOT automatically
                # retried. Plugins should explicitly report retryable
                # domain-specific failures through discoveries.
                self.stage_outcomes[stage_name] = {
                    "status": "error", "attempts": attempt, "discoveries": 0,
                    "error": f"{type(e).__name__}: {e}",
                }
                return []

            # ---------------------------------------------------------
            # Plugin completed successfully.
            #
            # The plugin may still have discovered a transient failure,
            # e.g. HTTP 503, and explicitly mark it retryable=True.
            # ---------------------------------------------------------

            if not self._retryable_discovery(discoveries):
                self.stage_outcomes[stage_name] = {
                    "status": "completed", "attempts": attempt, "discoveries": len(discoveries)
                }
                return discoveries

            if attempt >= total_attempts:
                print(status_line(
                    f"RETRY EXHAUSTED {plugin.metadata.name} "
                    f"on {target} "
                    f"after {attempt} attempts"
                , "error"))
                self.stage_outcomes[stage_name] = {
                    "status": "retry_exhausted", "attempts": attempt,
                    "discoveries": len(discoveries),
                }
                return discoveries

            delay = self._backoff_delay(attempt)

            print(status_line(
                f"RETRY {plugin.metadata.name} "
                f"on {target}: "
                f"attempt {attempt + 1}/{total_attempts} "
                f"in {delay:.2f}s"
            ))

            await asyncio.sleep(delay)

        return []

    async def run(self, target: str):
        # ---------------------------------------------------------
        #                           Gate 1
        # ---------------------------------------------------------

        decision = self._scope.authorize(target)

        print(status_line(
            f"GATE 1: {target} -> "
            f"{'ALLOW' if decision.allowed else 'DENY'} "
            f"({decision.reason})"
        , "ok" if decision.allowed else "error"))

        if not decision.allowed:
            return decision

        # ---------------------------------------------------------
        #                        Plugin execution
        # ---------------------------------------------------------

        for plugin in self._ordered_plugins():
            stage_started = time.monotonic()

            # -----------------------------------------------------
            # Plugin-specific preflight
            # -----------------------------------------------------

            if not await plugin.preflight():
                print(
                    f"SKIP {plugin.metadata.name}: "
                    "preflight failed"
                )
                self.stage_durations[plugin.metadata.name] = round(
                    time.monotonic() - stage_started, 3
                )
                self.stage_outcomes[plugin.metadata.name] = {
                    "status": "skipped", "attempts": 0, "discoveries": 0
                }
                continue

            try:
                discoveries = await self._execute_plugin(
                    plugin,
                    target,
                )
            except BaseException:
                self.stage_durations[plugin.metadata.name] = round(
                    time.monotonic() - stage_started, 3
                )
                self.stage_outcomes[plugin.metadata.name] = {
                    "status": "interrupted", "attempts": 0, "discoveries": 0
                }
                raise
            finally:
                try:
                    await plugin.cleanup()
                except Exception as error:
                    outcome = self.stage_outcomes.setdefault(
                        plugin.metadata.name,
                        {"status": "cleanup_error", "attempts": 0, "discoveries": 0},
                    )
                    outcome["cleanup_error"] = f"{type(error).__name__}: {error}"
                    print(
                        f"CLEANUP ERROR {plugin.metadata.name} "
                        f"on {target}: {error}"
                    )

            # -----------------------------------------------------
            #                   Publish discoveries
            # -----------------------------------------------------

            for candidate in self._plugins:
                accept = getattr(candidate, "accept_discoveries", None)
                if accept is not None:
                    accept(discoveries, plugin.metadata.name)

            for discovery in discoveries:
                await self._bus.publish(
                    Event(
                        type="discovery",
                        payload={
                            "kind": discovery.kind,
                            "data": discovery.data,
                            "source_plugin": plugin.metadata.name,
                            "scan_target": target,
                            "scan_run_id": self._scan_run_id,
                        },
                    )
                )

            # Keep terminal output and stage state ordered while preserving
            # asynchronous handler execution within the stage.
            await self._bus.drain()
            self.stage_durations[plugin.metadata.name] = round(
                time.monotonic() - stage_started, 3
            )
            print("\n" + status_line(f"STAGE COMPLETE {plugin.metadata.name}", "ok"))

        return decision
