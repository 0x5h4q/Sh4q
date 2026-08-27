from pathlib import Path

from sh4q.adapters import AdapterContext, ExternalToolAdapter
from sh4q.config import Sh4qConfig
from sh4q.scope import ScopeEngine


class ExampleAdapter(ExternalToolAdapter):
    name = "example"

    def build_argv(self, target, context):
        return ("example-tool", "--target", target, "--output", str(context.output_directory))


config = Sh4qConfig(**{"scope": {"targets": ["example.com"]}})
context = AdapterContext(ScopeEngine(config), Path("out"))
argv = ExampleAdapter().build_argv("example.com", context)
assert isinstance(argv, tuple)
assert argv[0] == "example-tool"
assert all(isinstance(part, str) for part in argv)
assert ";" not in argv and "&&" not in argv
print("adapter contract test passed")
