# Authorised Use

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
