import asyncio
import time
from sh4q.events import Event, EventBus


async def main():
    bus = EventBus()

    async def storage_writer(event: Event):
        print(f"  [storage] saving {event.payload}")

    async def slow_subscriber(event: Event):
        print(f"  [slow_sub] starting work on {event.payload['host']}...")
        await asyncio.sleep(1)  # simulate slow work, e.g. a screenshot capture
        print(f"  [slow_sub] finished {event.payload['host']}")

    bus.subscribe("dns_found", storage_writer)
    bus.subscribe("dns_found", slow_subscriber)

    bus.start()

    start = time.monotonic()
    print("publishing event 1...")
    await bus.publish(Event(type="dns_found", payload={"host": "example.com"}))
    print(f"publish() returned after {time.monotonic() - start:.3f}s (should be near-instant)")

    print("publishing event 2...")
    await bus.publish(Event(type="dns_found", payload={"host": "api.example.com"}))
    print(f"publish() #2 returned after {time.monotonic() - start:.3f}s (still fast)")

    await bus.drain()
    print(f"drain() confirms everything is actually done after {time.monotonic() - start:.3f}s total")
    bus.stop()


asyncio.run(main())