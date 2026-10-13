# Changelog

## 2.0.0 — unreleased (branch `finish/canonical-verifier-20261013`)

WatchTower rebuilt as the Constellation registry defines it: deterministic verifier and telemetry
receipt authority. The v1 scripts are unchanged and outside the v2 gate.

### Added

- `src/WatchTower` module for Windows PowerShell 5.1 and PowerShell 7, dependent only on OpenSSH.
- PCv1 Option A verifier and builder that agree with CPR check-for-check.
- NeverLost-format trust: authority principal with four namespaces, derived `allowed_signers`,
  producer enrolment restricted to producer namespaces.
- Telemetry verification of the live-state-surgeon wire contract with per-type body rules and
  recomputed posture and policy hashes.
- Ingest with replay, sequence and clock rules; hash-chained receipts and alerts; signed device
  documents; Constellation health facet; checkpoint seals; NFL receipt packets; device pledges;
  crash recovery; ledger re-verification; doctor; evidence index.
- `bin/watchtower.ps1` CLI with stable tokens and exit codes.
- 14 new JSON Schemas; the heartbeat, health report, policy attestation and alert schemas extended
  additively.
- Test gate: six offline suites (196 cases) plus interop against CPR, NeverLost and a recorded
  live-state-surgeon packet; non-mutation check; schema-validated report; CI for Ubuntu pwsh 7,
  Windows pwsh 7 and Windows PowerShell 5.1.
- Canonical docs, contracts, proposals 0001–0005, WBS and DoD v2.

### Fixed

- One hostile inbox packet could stop all ingest (surrogate-pair truncation) or hang it holding
  the lock (named pipe).
- Unverified packets could date alerts by their own header time.
- Hashing and chain verification could be steered by JSON keys named `Keys`, `Values` or `Count`.
- `scripts/_selftest_watchtower_cli_v1.ps1` tested commands the v1 CLI never had.

### Changed

- `ui/node_modules` is no longer tracked; LF line endings are enforced for source and canonical text.
