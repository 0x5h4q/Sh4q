
"""
sh4q/scheduler.py

The Scheduler — orchestrates running plugins against a target. This is
where Config, Scope, Storage, Events, and the Plugin contract finally
meet. Deliberately simple dependency ordering (explicit depends_on lists)
per the decision to defer capability-based typing until real plugins
justify it.
"""

import asyncio

from sh4q.events import Event, EventBus
from sh4q.plugins import Plugin
from sh4q.scope import ScopeEngine


class Scheduler:
    def __init__(self, plugins: list[Plugin], scope: ScopeEngine, bus: EventBus):
        self._plugins = plugins
        self._scope = scope
        self._bus = bus

    def _ordered_plugins(self) -> list[Plugin]:
        """Simple dependency-respecting order: a plugin only runs once every
        plugin it depends on (by name) has already been placed."""
        ordered: list[Plugin] = []
        remaining = list(self._plugins)
        done_names: set[str] = set()

        while remaining:
            progressed = False
            for plugin in list(remaining):
                if all(dep in done_names for dep in plugin.metadata.dependencies):
                    ordered.append(plugin)
                    done_names.add(plugin.metadata.name)
                    remaining.remove(plugin)
                    progressed = True
            if not progressed:
                names = [p.metadata.name for p in remaining]
                raise RuntimeError(f"Circular or unmet plugin dependency among: {names}")
        return ordered

    async def run(self, target: str) -> None:
        # Gate 1: is the ORIGINAL target allowed to be scanned at all?
        decision = self._scope.authorize(target)
        print(f"GATE 1: {target} -> {'ALLOW' if decision.allowed else 'DENY'} ({decision.reason})")
        if not decision.allowed:
            return

        for plugin in self._ordered_plugins():
            if not await plugin.preflight():
                print(f"SKIP {plugin.metadata.name}: preflight failed")
                continue

            try:
                discoveries = await asyncio.wait_for(
                    plugin.execute(target), timeout=plugin.metadata.timeout
                )
            except asyncio.TimeoutError:
                print(f"TIMEOUT {plugin.metadata.name} on {target}")
                discoveries = []
            except Exception as e:
                print(f"ERROR {plugin.metadata.name} on {target}: {e}")
                discoveries = []
            finally:
                await plugin.cleanup()

            # The Scheduler publishes on the plugin's behalf — the plugin
            # itself never touches the Event bus.
            for d in discoveries:
                await self._bus.publish(
                    Event(
                        type="discovery",
                        payload={"kind": d.kind, "data": d.data, "source_plugin": plugin.metadata.name},
                    )
                )