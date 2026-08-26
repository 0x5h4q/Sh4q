

import asyncio
from collections import defaultdict
from typing import Awaitable, Callable

from .event import Event
from .event_log import DurableEventLog

Handler = Callable[[Event], Awaitable[None]]


class EventBus:
    def __init__(self, event_log: DurableEventLog | None = None, *, max_event_attempts: int = 3, retry_delay: float = 0.0):
        self._queue: asyncio.Queue[Event] = asyncio.Queue()
        self._subscribers: dict[str, list[Handler]] = defaultdict(list)
        self._dispatcher_task: asyncio.Task | None = None
        self._event_log = event_log   # None = old in-process-only behavior, no durability
        self._max_event_attempts = max(1, max_event_attempts)
        self._retry_delay = max(0.0, retry_delay)

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
            try:
                if self._event_log:
                    await self._event_log.mark_processing(event.id)
                handlers = self._subscribers.get(event.type, [])
                await asyncio.gather(*(handler(event) for handler in handlers))
                if self._event_log:
                    await self._event_log.mark_completed(event.id)
            except asyncio.CancelledError:
                raise
            except Exception as error:
                if self._event_log:
                    await self._event_log.mark_failed(
                        event.id,
                        f"{type(error).__name__}: {error}",
                        max_attempts=self._max_event_attempts,
                        retry_delay=self._retry_delay,
                    )
                else:
                    print(f"EVENT FAILED {event.id}: {error}")
            finally:
                self._queue.task_done()

    def start(self) -> None:
        "Start the background dispatcher. Call once, at engine startup."
        self._dispatcher_task = asyncio.create_task(self._dispatch_loop())

    async def drain(self) -> None:
        await self._queue.join()

    def stop(self) -> None:
        if self._dispatcher_task:
            self._dispatcher_task.cancel()

    async def shutdown(self) -> None:
        """Cancel the dispatcher and wait for it to finish cleanly."""
        task = self._dispatcher_task
        self._dispatcher_task = None
        if task is None:
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
