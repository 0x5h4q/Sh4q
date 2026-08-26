from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

@dataclass(frozen=True)
class LimiterMetrics:
    admitted: int
    denied: int
    completed: int
    failed: int
    active: int
    peak_concurrency: int

class RequestLimiter:
    def __init__(self, max_concurrent: int, requests_per_second: float, budget: int):
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._interval = 1.0 / requests_per_second
        self._budget = budget
        self._lock = asyncio.Lock()
        self._next_slot = 0.0
        self._admitted = self._denied = self._completed = self._failed = self._active = self._peak = 0

    async def acquire(self):
        async with self._lock:
            if self._budget <= 0:
                self._denied += 1
                return None
            self._budget -= 1
            self._admitted += 1
            slot = max(time.monotonic(), self._next_slot)
            self._next_slot = slot + self._interval
        try:
            await asyncio.sleep(max(0.0, slot - time.monotonic()))
            await self._semaphore.acquire()
        except asyncio.CancelledError:
            async with self._lock:
                self._budget += 1
                self._admitted -= 1
            raise
        async with self._lock:
            self._active += 1
            self._peak = max(self._peak, self._active)
        return RequestPermit(self)

    async def _release(self, success):
        self._semaphore.release()
        async with self._lock:
            self._active -= 1
            self._completed += bool(success)
            self._failed += not success

    async def metrics(self):
        async with self._lock:
            return LimiterMetrics(self._admitted, self._denied, self._completed, self._failed, self._active, self._peak)

class RequestPermit:
    def __init__(self, limiter):
        self._limiter = limiter
        self._success = False
    def succeeded(self):
        self._success = True
    async def __aenter__(self):
        return self
    async def __aexit__(self, exc_type, exc, tb):
        await self._limiter._release(self._success and exc_type is None)
