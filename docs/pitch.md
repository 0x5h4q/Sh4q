# Sh4q: Outreach Pitch

## One Sentence

Sh4q is a policy-controlled reconnaissance control plane that turns noisy
multi-tool discovery into a scope-checked, evidence-backed, reviewable asset
inventory.

## Short Pitch

Bug hunters already build powerful workflows around tools like Subfinder,
Amass, HTTPX, `grep`, and `jq`. Sh4q keeps that flexibility, but adds a control
plane around it: every finding has a source, every accepted asset is rechecked
against scope, and the raw observation remains available for review. It is
designed for authorised attack-surface discovery, not exploitation.

## Why It Is Different

- **Policy before persistence:** a tool can emit anything, but out-of-scope or
  unsafe results do not become trusted graph assets.
- **Evidence with provenance:** source plugin, command context, tool version,
  event state, scan identity, and raw observations remain connected.
- **Discovery is not liveness:** CT names and passive findings are not labelled
  alive until bounded DNS/HTTP evidence supports that claim.
- **Resumable and reviewable:** durable events, retries, scan ownership, and
  exports make interrupted or repeated scans auditable.
- **Composable instead of monolithic:** existing specialist tools remain useful
  through controlled adapters rather than being hidden behind an opaque script.

## Sh4q vs. ReconFTW-Style Pipelines

ReconFTW-style workflows are valuable breadth-first automation pipelines. Sh4q
focuses on a different layer: policy, evidence, provenance, and durable state
around discovery tools. It is not claiming the same scanner breadth or speed.
The practical pitch is: use specialist tools for collection, and use Sh4q when
you need to explain what happened, keep scope boundaries visible, and hand a
repeatable inventory to someone else.

## Honest Early-Tester Ask

> I’m building Sh4q, a scope-aware recon control plane inspired by the way bug
> hunters combine Subfinder/Amass/HTTPX with `grep` and `jq`. It keeps the useful
> tool flexibility, but records provenance and evidence and refuses to treat
> out-of-scope or unverified findings as trusted assets. I’d value feedback on
> whether the reports and workflow are useful on an authorised test target.

## Claims To Avoid

Do not describe Sh4q as a vulnerability scanner, exploit framework, complete
attack-surface inventory, reconFTW replacement, or guarantee of safe use without
authorisation. Say “policy-controlled,” “evidence-backed,” “scope-aware,” and
“reviewable” only in the documented sense defined by the threat model.
