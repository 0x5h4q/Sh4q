# Authorised Use

Sh4q is for domains and systems you own or have explicit permission to assess.
If you are learning, use a lab, a local test domain, or a bug-bounty program
whose scope clearly includes the target.

Start with the default scan. Optional flags can contact additional public
providers or run external tools, so read their program rules and local terms
before enabling them. `--url-history` is passive archive lookup; it does not
make historical pages live. `--sub`, `--amass`, and `--httpx` are optional
external-tool stages and may take considerably longer than a basic scan.

Sh4q is not a permission system. The operator is responsible for confirming
authorization, respecting rate limits, and reviewing output before sharing it.

Use Sh4q only where you have permission.

Acceptable targets include:

- infrastructure you own;
- a lab created for your testing;
- a client system covered by written authorisation;
- a bug-bounty target, only within the program's published scope and rules.

Do not use Sh4q against a university, employer, company, public service, or individual merely because the domain is publicly reachable.

## Technical Scope Is Not Legal Permission

Sh4q's scope engine answers a technical question: is this target allowed by the current configuration?

It cannot determine whether you have legal or contractual permission. A Gate 1 `ALLOW` message is not an authorisation document.

The user is responsible for confirming:

- who owns the target;
- which domains, subdomains, addresses, ports, and techniques are permitted;
- the permitted testing dates and rate limits;
- data handling and reporting requirements;
- whether third-party services and redirects are included.

## Before Every Live Test

1. Confirm the exact target and written permission.
2. Read the program or client rules again.
3. Use the narrowest practical scope.
4. Start without optional adapters if unsure.
5. Keep the scan ID, command, configuration, date, and Git commit.
6. Stop if the target behaves unexpectedly or the rules are unclear.

## Sensitive Data

Scan databases and exports may reveal internal naming conventions, services, addresses, error details, and technology observations.

Do not:

- commit `sh4q-output/`;
- post raw databases publicly;
- attach unredacted evidence to public issues;
- include credentials or private client data in feedback;
- share another organisation's results without permission.

## External Tools

Subfinder contacts its own providers. Sh4q validates discovered output before trusting it, but Sh4q's native request limiter does not govern every packet generated inside Subfinder. Follow the target rules and the external tool's configuration requirements.
