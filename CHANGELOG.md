# Changelog

## 2.1.0 — unreleased (branch `finish/canonical-verifier-20261013`)

Constellation integrations (proposal 0006). Additive: with no `settings.arbiter`, 2.0 outputs are
unchanged apart from trust bundles gaining `pubkey_path`.

### Added

- Integration receipts (`constellation.integration.receipt.v1`, Constellation proposal 0013) for
  `watchtower > arbiter`, `watchtower > neverlost` and `watchtower > nfl`; witness packets
  (`watchtower.integration_witness.v1`) in `packets/outbox` for NFL and a witness ledger;
  `integrations [-Witness]` command; verification in `ledger`, `doctor` and the evidence index.
- Optional policy gate with Arbiter (`settings.arbiter`): verified packets are evaluated by
  Arbiter's own engine, decisions re-verified, routed allow / deny / quarantine, evidence kept
  under `proofs/policy/` for `arbiter verify`; fails closed; example policy in `config/arbiter/`.
- NeverLost v1 trust bundles: `pubkey_path` + `pubkey_sha256` for every key (key files under
  `proofs/trust/neverlost/keys/`), re-verified on every read; `enroll -FromBundle` for producers
  NeverLost issued, carrying the authorising `neverlost.receipt.v1`, all-or-nothing.
- Seventh standalone suite `Integration`; Interop against Arbiter's real engine, NeverLost's v1
  verifier and live-state-surgeon's current emitter. `RUN_TIER0_GATE.cmd` for the Windows host.
- Proposals 0006 (this release) and 0007 (requests to Constellation, NFL, NeverLost,
  live-state-surgeon, Arbiter, Covenant Gate); contracts `arbiter.md`, `integration-receipts.md`.

### Changed

- Key ids must be unique across the whole trust bundle (`TRUST_DUPLICATE_KEY_ID`), as NeverLost
  requires. A 2.0 bundle that used one key id under two principals must re-enroll one of them.
- live-state-surgeon fixtures replaced by packets from its fixed emitter, accepted end to end
  (proposal 0002 done).
- The legacy NFL handoff consumer writes a `watchtower > nfl` integration receipt per run.
- Module manifest `ProjectUri` points at `github.com/Alpallyoop/WatchTower`.

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
