# alex-workers-public

Generic parallel compute workers (GitHub Actions, `workflow_dispatch`).

This repository intentionally contains ONLY generic, reusable worker code:
hash-grinding miners and helper scripts that take all project-specific
parameters (seeds, targets, ranges) as command-line arguments at dispatch
time. No credentials, no wallet addresses, no personal data, no secrets —
anything project-specific lives elsewhere and is passed in as a command.

## Usage

Dispatch the `alex-worker` workflow with a `command` input; the command runs
on a fresh Ubuntu runner (2 CPU, ~8 GB RAM, ~72 GB disk, max 350 minutes).
Findings are harvested from the run log.

## Workers

- `pearl/pearlminer.c` — Keccak-256 nonce grinder: finds nonces with
  `keccak256(seed || nonce) <= target` in a sharded nonce space, with
  checkpoint/resume and a built-in self-test vector check.
