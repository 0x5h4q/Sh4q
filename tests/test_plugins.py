import asyncio
from sh4q.plugins import Plugin, PluginMetadata, Discovery


class FakePlugin(Plugin):
    metadata = PluginMetadata(name="fake", risk_level="passive", dependencies=[])

    async def execute(self, target: str) -> list[Discovery]:
        return [Discovery(kind="fake_finding", data={"target": target, "note": "hello"})]


async def main():
    print("-- a well-formed plugin works end to end --")
    plugin = FakePlugin()
    print(f"  metadata: name={plugin.metadata.name} risk_level={plugin.metadata.risk_level}")
    ready = await plugin.preflight()
    print(f"  preflight: {ready}")
    discoveries = await plugin.execute("example.com")
    print(f"  execute returned: {discoveries}")
    await plugin.cleanup()
    print(f"  cleanup: ran without error")
    print(f"  discovery is a Discovery, not a Node: {type(discoveries[0]).__name__}")


asyncio.run(main())

print()
print("-- deliberately BREAK the contract: a plugin missing execute() --")
try:
    class BrokenPlugin(Plugin):
        metadata = PluginMetadata(name="broken")
        # no execute() defined at all

    broken = BrokenPlugin()  # should fail before this even runs
    print("  ERROR: this should never print — instantiation should have failed")
except TypeError as e:
    print(f"  correctly rejected: {e}")