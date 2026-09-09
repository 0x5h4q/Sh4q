from pathlib import Path


pyproject = Path("pyproject.toml").read_text()
lockfile = Path("requirements.lock").read_text()

for requirement in (
    '"pydantic>=2.10,<3"',
    '"pyyaml>=6.0.2,<7"',
    '"aiosqlite>=0.21,<1"',
    '"httpx>=0.28,<1"',
    '"dnspython>=2.7,<3"',
):
    assert requirement in pyproject

for pinned in (
    "pydantic==",
    "PyYAML==",
    "aiosqlite==",
    "httpx==",
    "dnspython==",
):
    assert pinned in lockfile

print("dependency bounds test passed")
