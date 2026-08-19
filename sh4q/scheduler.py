import asyncio
import random
from typing import Any

from sh4q.events import Event, EventBus
from sh4q.plugins import Plugin
from sh4q.scope import ScopeEngine


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

        for attempt in range(1, total_attempts + 1):

            print(
                f"EXECUTE {plugin.metadata.name} "
                f"on {target} "
                f"(attempt {attempt}/{total_attempts})"
            )

            try:
                discoveries = await asyncio.wait_for(
                    plugin.execute(target),
                    timeout=plugin.metadata.timeout,
                )

            except asyncio.TimeoutError:
                print(
                    f"TIMEOUT {plugin.metadata.name} "
                    f"on {target} "
                    f"(attempt {attempt}/{total_attempts})"
                )

                # Timeout is treated as a transient execution failure.
                # Retry it using the Scheduler's generic retry policy.
                if attempt >= total_attempts:
                    print(
                        f"RETRY EXHAUSTED {plugin.metadata.name} "
                        f"on {target} "
                        f"after {attempt} attempts"
                    )
                    return []

                delay = self._backoff_delay(attempt)

                print(
                    f"RETRY {plugin.metadata.name} "
                    f"on {target}: "
                    f"attempt {attempt + 1}/{total_attempts} "
                    f"in {delay:.2f}s"
                )

                await asyncio.sleep(delay)
                continue

            except Exception as e:
                print(
                    f"ERROR {plugin.metadata.name} "
                    f"on {target}: {e}"
                )

                # Generic unexpected exceptions are NOT automatically
                # retried. Plugins should explicitly report retryable
                # domain-specific failures through discoveries.
                return []

            # ---------------------------------------------------------
            # Plugin completed successfully.
            #
            # The plugin may still have discovered a transient failure,
            # e.g. HTTP 503, and explicitly mark it retryable=True.
            # ---------------------------------------------------------

            if not self._retryable_discovery(discoveries):
                return discoveries

            if attempt >= total_attempts:
                print(
                    f"RETRY EXHAUSTED {plugin.metadata.name} "
                    f"on {target} "
                    f"after {attempt} attempts"
                )
                return discoveries

            delay = self._backoff_delay(attempt)

            print(
                f"RETRY {plugin.metadata.name} "
                f"on {target}: "
                f"attempt {attempt + 1}/{total_attempts} "
                f"in {delay:.2f}s"
            )

            await asyncio.sleep(delay)

        return []

    async def run(self, target: str):
        # ---------------------------------------------------------
        #                           Gate 1
        # ---------------------------------------------------------

        decision = self._scope.authorize(target)

        print(
            f"GATE 1: {target} -> "
            f"{'ALLOW' if decision.allowed else 'DENY'} "
            f"({decision.reason})"
        )

        if not decision.allowed:
            return decision

        # ---------------------------------------------------------
        #                        Plugin execution
        # ---------------------------------------------------------

        for plugin in self._ordered_plugins():

            # -----------------------------------------------------
            # Plugin-specific preflight
            # -----------------------------------------------------

            if not await plugin.preflight():
                print(
                    f"SKIP {plugin.metadata.name}: "
                    "preflight failed"
                )
                continue

            try:
                discoveries = await self._execute_plugin(
                    plugin,
                    target,
                )

            finally:
                await plugin.cleanup()

            # -----------------------------------------------------
            #                   Publish discoveries
            # -----------------------------------------------------

            for discovery in discoveries:
                await self._bus.publish(
                    Event(
                        type="discovery",
                        payload={
                            "kind": discovery.kind,
                            "data": discovery.data,
                            "source_plugin": plugin.metadata.name,
                            "scan_target": target,
                        },
                    )
                )

        return decision