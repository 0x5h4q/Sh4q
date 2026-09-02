# Troubleshooting

## `sh4q: command not found`

Activate the virtual environment and reinstall the editable package:

```bash
source venv/bin/activate
python -m pip install -e .
sh4q --help
```

You can also call the environment entry point directly:

```bash
venv/bin/sh4q --help
```

## `Subfinder is not installed or is not available on PATH`

Either install Subfinder and verify `command -v subfinder`, or omit `--sub`:

```bash
sh4q scan your-domain.example
```

## CT Timeouts, 502 Responses, or Rate Limits

These are common external-provider conditions. Sh4q retries retryable CT failures and retains partial names when a provider supplied them.

Review the exact scan rather than assuming it failed entirely:

```bash
sh4q show --scan <scan-id>
sh4q results --scan <scan-id> --failures --limit 50
```

Do not repeatedly rerun a rate-limited provider immediately. Respect `Retry-After` when shown.

## Many DNS Failures

Check the reason breakdown in the scan summary or `sh4q show`:

- `nxdomain`: the name did not exist at scan time;
- `no_answer`: no A or AAAA record was returned;
- `timeout`: the resolver did not answer in time;
- `servfail`: the nameserver could not provide a usable answer.

Passive sources often return historical names, so a large NXDOMAIN count is possible. A large timeout count points more strongly to resolver or network conditions.

## Few HTTP-Alive Domains

Sh4q only probes discovered names that first resolve successfully. A passive discovery is not automatically considered alive.

Check:

```bash
sh4q show --scan <scan-id>
sh4q results --scan <scan-id> --type url
```

HTTP failures are retained as evidence. A blocked out-of-scope redirect is expected policy behavior.

## `403` Responses

A `403` means the server responded but refused the request. It still counts as HTTP-alive. It does not mean the application content was accessible.

## Empty Technology Results

Technology observations require an HTTP response containing a supported explicit signal. Empty results do not mean the endpoint has no technology; the visible response may simply reveal nothing recognized by the conservative signature set.

## Export Refuses an Older Scan

Some scans created before per-scan asset ownership cannot be exported exactly. Sh4q refuses to guess their contents. Run a new scan with the current version.

## Output File Already Exists

Choose a new file or explicitly overwrite it:

```bash
sh4q export --scan <scan-id> --format csv \
  --output results.csv --force
```

## `Ctrl+C`

Press it once and wait for the clean interruption message. The scan is marked interrupted and durable events can be recovered later. Avoid repeatedly sending termination signals unless the process is genuinely stuck.

## Database Schema Error

Do not edit `schema_metadata` manually. Confirm the Sh4q version and database path. Back up the database before changing versions. A database produced by a newer unsupported Sh4q revision is rejected intentionally.

## Reporting a Problem

Follow [feedback.md](feedback.md). Include the scan ID and command, but redact sensitive hostnames, evidence, credentials, and client data.
## SQLite initialization hangs

Sh4q requires CPython 3.11 through 3.13. The current `aiosqlite` release can
stall while opening a connection under CPython 3.14, before any Sh4q schema or
scan work begins. Recreate the virtual environment with Python 3.13 (or an
older supported interpreter) and reinstall the package:

```text
python3.13 -m venv venv
source venv/bin/activate
python -m pip install -e .
```
