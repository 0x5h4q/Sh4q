import asyncio

from sh4q.events import Event, EventBus


async def main() -> None:
    bus = EventBus()
    processed: list[str] = []

    async def broken(event: Event) -> None:
        raise RuntimeError("expected failure")

    async def healthy(event: Event) -> None:
        processed.append(event.id)

    bus.subscribe("broken", broken)
    bus.subscribe("healthy", healthy)
    bus.start()
    await bus.publish(Event(type="broken"))
    healthy_event = Event(type="healthy")
    await bus.publish(healthy_event)
    await asyncio.wait_for(bus.drain(), timeout=1)
    assert processed == [healthy_event.id]
    await bus.shutdown()
    assert bus._dispatcher_task is None
    print("event lifecycle test passed")


asyncio.run(main())
