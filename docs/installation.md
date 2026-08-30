# Installation

## Requirements

- Linux 64-bit.
- Python 3.11 or newer.
- Git.
- Internet access during dependency installation.
- Subfinder only if `--sub` will be used.

Sh4q is tested in CI on Python 3.11, 3.12, and 3.13.

## Install from the Repository

```bash
git clone <repository-url>
cd sh4q
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

Confirm the CLI is available:

```bash
sh4q --help
```

Run the offline checks:

```bash
python tools/run_offline_tests.py
```

The default suite does not require Subfinder or access to public scan targets.

## Optional Subfinder Support

`--sub` requires ProjectDiscovery Subfinder to be installed separately and available on `PATH`.

Confirm it is visible:

```bash
subfinder -version
command -v subfinder
```

Sh4q deliberately uses a fixed passive Subfinder command. It does not claim that its native request counter includes Subfinder's provider traffic.

If Subfinder is absent, use Sh4q without `--sub`:

```bash
sh4q scan your-domain.example
```

## Output Location

The default output directory is:

```text
./sh4q-output/
```

The primary database is:

```text
./sh4q-output/sh4q.db
```

Treat it as sensitive. It can contain hostnames, addresses, URLs, HTTP metadata, technology observations, failures, adapter output, and scan history.

## Updating a Development Checkout

After pulling a newer revision:

```bash
source venv/bin/activate
python -m pip install -e .
python tools/run_offline_tests.py
```

Sh4q records a database schema version and rejects newer unsupported schemas. Back up important output before testing a development revision.

## Clean Installation Check

For release testing, use a new temporary virtual environment rather than relying on an old development environment:

```bash
python3 -m venv /tmp/sh4q-alpha-venv
source /tmp/sh4q-alpha-venv/bin/activate
python -m pip install -e .
python tools/run_offline_tests.py
```
