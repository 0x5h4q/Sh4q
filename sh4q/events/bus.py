
"""
sh4q/events/bus.py

The Event Bus — in-process, asyncio.Queue-based pub/sub. This is the
"EVENT BUS" box from the mental model: publishers only ever talk to the
queue; subscribers only ever get called by the dispatcher loop. Neither
side knows the other exists.
"""

import asyncio
from collections import defaultdict
from typing import Awaitable, Callable

from .event import Event

Handler = Callable[[Event], Awaitable[None]]


class EventBus:
    def __init__(self):
        self._queue: asyncio.Queue[Event] = asyncio.Queue()
        self._subscribers: dict[str, list[Handler]] = defaultdict(list)
        self._dispatcher_task: asyncio.Task | None = None

    def subscribe(self, event_type: str, handler: Handler) -> None:
        """Register a handler to be called whenever an event of this type
        is dispatched. Multiple handlers can subscribe to the same type."""
        self._subscribers[event_type].append(handler)

    async def publish(self, event: Event) -> None:
        """Announce that something happened. Returns almost immediately —
        does NOT wait for subscribers to react. That's the whole point."""
        await self._queue.put(event)

    async def _dispatch_loop(self) -> None:
        while True:
            event = await self._queue.get()
            handlers = self._subscribers.get(event.type, [])
            # Run all subscribers for this event concurrently, not one
            # after another — a slow subscriber shouldn't delay the others.
            await asyncio.gather(*(handler(event) for handler in handlers))
            self._queue.task_done()

    def start(self) -> None:
        """Start the background dispatcher. Call once, at engine startup."""
        self._dispatcher_task = asyncio.create_task(self._dispatch_loop())

    async def drain(self) -> None:
        """Wait until every published event so far has been fully
        dispatched. Useful for tests and for clean shutdown."""
        await self._queue.join()

    def stop(self) -> None:
        """Stop the dispatcher. Call after drain(), at shutdown."""
        if self._dispatcher_task:
            self._dispatcher_task.cancel()