

import asyncio
from collections import defaultdict
from typing import Awaitable, Callable

from .event import Event
from .event_log import DurableEventLog

Handler = Callable[[Event], Awaitable[None]]


class EventBus:
    def __init__(self, event_log: DurableEventLog | None = None):
        self._queue: asyncio.Queue[Event] = asyncio.Queue()
        self._subscribers: dict[str, list[Handler]] = defaultdict(list)
        self._dispatcher_task: asyncio.Task | None = None
        self._event_log = event_log   # None = old in-process-only behavior, no durability

    def subscribe(self, event_type: str, handler: Handler) -> None:
        self._subscribers[event_type].append(handler)

    async def publish(self, event: Event) -> None:
        if self._event_log:
            await self._event_log.record_pending(event)
        await self._queue.put(event)

    async def recover(self) -> int:
        if not self._event_log:
            return 0
        unfinished = await self._event_log.recover_unfinished()
        for event in unfinished:
            await self._queue.put(event)
        return len(unfinished)

    async def _dispatch_loop(self) -> None:
        while True:
            event = await self._queue.get()
            if self._event_log:
                await self._event_log.mark_processing(event.id)
            handlers = self._subscribers.get(event.type, [])
            await asyncio.gather(*(handler(event) for handler in handlers))
            if self._event_log:
                await self._event_log.mark_completed(event.id)
            self._queue.task_done()

    def start(self) -> None:
        "Start the background dispatcher. Call once, at engine startup."
        self._dispatcher_task = asyncio.create_task(self._dispatch_loop())

    async def drain(self) -> None:
        await self._queue.join()

    def stop(self) -> None:
        if self._dispatcher_task:
            self._dispatcher_task.cancel()