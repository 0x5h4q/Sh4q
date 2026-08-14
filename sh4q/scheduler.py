import asyncio

from sh4q.events import Event, EventBus
from sh4q.plugins import Plugin
from sh4q.scope import ScopeEngine


class Scheduler:
    def __init__(
        self,
        plugins: list[Plugin],
        scope: ScopeEngine,
        bus: EventBus,
    ):
        self._plugins = plugins
        self._scope = scope
        self._bus = bus

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
                names = [plugin.metadata.name for plugin in remaining]
                raise RuntimeError(
                    f"Circular or unmet plugin dependency among: {names}"
                )

        return ordered

    async def run(self, target: str):
        # Gate 1: the original target must be authorized
        decision = self._scope.authorize(target)

        print(
            f"GATE 1: {target} -> "
            f"{'ALLOW' if decision.allowed else 'DENY'} "
            f"({decision.reason})"
        )

        if not decision.allowed:
            return decision

        for plugin in self._ordered_plugins():

            # Plugin-specific preflight
            if not await plugin.preflight():
                print(
                    f"SKIP {plugin.metadata.name}: "
                    "preflight failed"
                )
                continue

            try:
                discoveries = await asyncio.wait_for(
                    plugin.execute(target),
                    timeout=plugin.metadata.timeout,
                )

            except asyncio.TimeoutError:
                print(
                    f"TIMEOUT {plugin.metadata.name} on {target}"
                )
                discoveries = []

            except Exception as exc:
                print(
                    f"ERROR {plugin.metadata.name} on {target}: "
                    f"{exc}"
                )
                discoveries = []

            finally:
                await plugin.cleanup()

            # Scheduler owns event publication.
            # Plugins never interact directly with the EventBus.
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