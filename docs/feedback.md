# Private-Alpha Feedback

Good feedback includes enough detail to reproduce the problem without exposing sensitive scan data.

## Before Reporting

1. Confirm the target was authorised.
2. Record the exact Sh4q commit:

   ```bash
   git rev-parse HEAD
   ```

3. Record the Python and operating-system versions:

   ```bash
   python --version
   uname -a
   ```

4. Run the offline suite:

   ```bash
   python tools/run_offline_tests.py
   ```

5. Reproduce with the narrowest safe command possible.

## Feedback Template

```text
Summary:

Environment:
- Operating system:
- Python version:
- Sh4q commit:
- Subfinder version, if used:

Authorisation:
- Target owned/authorised: yes/no
- Sensitive details redacted: yes/no

Command:

Scan ID:

Expected behaviour:

Actual behaviour:

Relevant output:

Ctrl+C used: yes/no

Offline test result:

Suggested improvement:
```

## Do Not Attach Publicly

- `sh4q.db` from a real engagement;
- raw adapter output containing private targets;
- credentials, tokens, cookies, or private URLs;
- client names or internal infrastructure details;
- unredacted screenshots from confidential work.

Use a controlled fixture where possible. If a database is necessary, create a sanitized reproduction database rather than sharing the original.

## Useful Types of Feedback

- unclear installation or command behavior;
- misleading counts or labels;
- scope decisions that differ from the documented policy;
- crashes or Python tracebacks;
- poor narrow-terminal formatting;
- missing export fields;
- excessive runtime or repeated work;
- provider failures that are not explained clearly;
- fingerprint signals that appear incorrect;
- documentation that assumes knowledge a new tester does not have.
