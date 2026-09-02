from pathlib import Path

from sh4q.adapters import AdapterContext, AmassPassiveAdapter
from sh4q.config import Sh4qConfig
from sh4q.scope import ScopeEngine
from sh4q.plugins.discovered_dns_plugin import DiscoveredDNSPlugin
import asyncio


config = Sh4qConfig(**{"scope": {"targets": ["example.com"]}})
adapter = AmassPassiveAdapter(executable="/opt/tools/amass")
context = AdapterContext(ScopeEngine(config), Path("out"))
argv = adapter.build_argv("example.com", context)
assert argv == (
    "/opt/tools/amass",
    "enum",
    "-passive",
    "-nocolor",
    "-d",
    "example.com",
)
assert adapter.evidence_argv(argv) == [
    "/opt/tools/amass", "enum", "-passive", "-nocolor", "-d", "<target>"
]

discoveries = adapter.parse_stdout(
    "example.com",
    "api.example.com\nAPI.EXAMPLE.COM.\nexample.com\nevil.test\n"
    "example.com (FQDN) --> a_record --> 192.0.2.1 (IPAddress)\n"
    "example.com (FQDN) --> mx_record --> mail.example.com (FQDN)\n",
)
assert [item.data["hostname"] for item in discoveries] == [
    "api.example.com",
    "evil.test",
    "mail.example.com",
]
assert all(item.data["source"] == "amass-passive" for item in discoveries)

async def verify_enrichment():
    async def resolve(name):
        return ["192.0.2.10"]
    plugin = DiscoveredDNSPlugin(resolver=resolve, scope=ScopeEngine(config))
    plugin.accept_discoveries(discoveries, "amass-passive")
    results = await plugin.execute("example.com")
    assert any(item.data["domain"] == "api.example.com" for item in results)

asyncio.run(verify_enrichment())
print("Amass passive adapter test passed")
