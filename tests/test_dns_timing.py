import asyncio
import time


async def timed_resolve(target, n):
    loop = asyncio.get_running_loop()
    for i in range(n):
        start = time.monotonic()
        try:
            results = await loop.getaddrinfo(target, None)
            elapsed = time.monotonic() - start
            print(f"  run {i+1}: {elapsed:.3f}s ({len(results)} results)")
        except Exception as e:
            elapsed = time.monotonic() - start
            print(f"  run {i+1}: {elapsed:.3f}s FAILED ({e})")


asyncio.run(timed_resolve("example.com", 8))