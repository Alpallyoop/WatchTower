# WatchTower — Current State

As of 2026-10-15, branch `finish/canonical-verifier-20261013` (module 2.1.0).

This file only says what has been shown by evidence someone can rerun. A label such as GREEN,
LOCKED or FREEZE elsewhere in the repository is not evidence by itself.

## 1. Proven by the gate

Ubuntu Linux, PowerShell 7.4.6, OpenSSH 9.6p1, with sibling checkouts of CPR (`ec7efe6`),
NeverLost (`3de2ecb`, branch `audit/constellation-readiness-2026-10-15`; also run against `main`
`1bd6d0e`), Arbiter (`a7ccac8`, branch `arbiter-v1-spec-conformance`) and live-state-surgeon
(`37e7fe2`):

```
WATCHTOWER_CPR_ROOT=… WATCHTOWER_NEVERLOST_ROOT=… WATCHTOWER_ARBITER_ROOT=… WATCHTOWER_LSS_ROOT=… \
  pwsh -File scripts/_RUN_watchtower_canonical_full_green_v2.ps1 -Scope all -ReportPath <file>
SUITE Core        OK   cases=65
SUITE Packet      OK   cases=30
SUITE Telemetry   OK   cases=45
SUITE Ingest      OK   cases=29
SUITE Cli         OK   cases=12
SUITE Schemas     OK   cases=15
SUITE Integration OK   cases=26
SUITE Interop     OK   cases=10
WATCHTOWER_TIER0_FULL_GREEN_OK suites=7 cases=222
WATCHTOWER_INTEROP_OK cases=10
```

Against NeverLost `main` the v1-verifier case is reported as skipped (that branch has no
`NL-AssertTrustBundleV1`), so the token is `WATCHTOWER_INTEROP_PARTIAL`; every other case passes.
The repository was hashed before and after the run and did not change. The report is
schema-validated before the tokens print.

| Capability | Evidence |
|---|---|
| PCv1 Option A verification agrees with CPR on every CPR golden vector, on WatchTower's receipt packet, its integration-witness packet and a tampered copy | Interop (real `verify_packet_v1.ps1`) |
| Telemetry verification: every stage and failure code, pinned trust, in-packet trust ignored | Telemetry |
| **live-state-surgeon packets accepted end to end** (heartbeat, health report, noncompliant policy attestation), from vendored packets and re-emitted live by LSS's current emitter, byte-identical | Integration, Interop |
| Replay, duplicate, sequence, clock-skew rules across runs | Ingest |
| Receipts, alerts, checkpoints, pledges re-verify from bytes; tampering and forged signatures detected | Ingest, Core |
| Byte-identical outputs on two nodes with the same state, inputs and time (with and without the policy gate) | Ingest, Integration |
| Crash recovery: unsealed receipts and a checkpoint without packet/pledge are completed | Ingest |
| **Integration receipts** (`constellation.integration.receipt.v1`) for `watchtower > arbiter`, `> neverlost`, `> nfl`: exact line format, chain, every outcome, failed exchanges recorded, tamper detection, witness packets for NFL and their re-verification, writer lock | Integration |
| **Policy gate** with Arbiter: allow / deny / quarantine routing; evaluator crash, timeout, missing engine, unreadable policy and unverifiable decisions (wrong hash, wrong time, typeless fields) all fail closed; evidence re-proved by WatchTower and by `arbiter verify` | Integration (test double), Interop (real engine) |
| **NeverLost v1 bundles**: key files with `pubkey_path`/`pubkey_sha256`, bundle-wide unique key ids, accepted by NeverLost's own fail-closed verifier; `enroll -FromBundle` with receipt binding, principal-level namespaces and all-or-nothing rollback | Integration, Interop |
| `allowed_signers` byte-identical to NeverLost's own derivation | Interop |
| Every emitted artifact and accepted inbound shape matches its schema | Schemas, Integration |
| CLI tokens and exit codes, including `enroll -FromBundle` and `integrations -Witness` | Cli, Integration |
| Hostile input cannot pass verification or stop ingest | Core, Packet, Ingest |

## 2. Not proven yet

| Item | Why | How to close |
|---|---|---|
| **Windows PowerShell 5.1 and Windows** | The gate has only run on Linux. The code avoids PS7-only syntax and APIs (reviewed again for 2.1), but that is not evidence. | Push the branch so `.github/workflows/tier0.yml` runs (Ubuntu pwsh 7, Windows pwsh 7, Windows PowerShell 5.1), or run `RUN_TIER0_GATE.cmd` on the Windows host |
| A real Windows host run of `init → enroll → ingest → ledger → doctor -Publish` | Needs the host | `RUN_TIER0_GATE.cmd`, then the commands in README |
| NFL witnessing WatchTower's outbox | CPR accepts both packet kinds; NFL's witness step commits no hash and runs only on Windows from `C:\dev` | NFL side, proposal 0007 §3 |
| Constellation oversight reading a live facet | Shape matches the reader; no live run recorded | Run oversight with a bound service |
| Registry state for the integrations | The registry still says receipts are `specified` | Constellation side, proposal 0007 §1 |
| Hosts with OpenSSH older than 8.1 | No `ssh-keygen -Y` | `doctor` check `ssh_keygen` fails clearly; install OpenSSH 8.1+ |

## 3. Known limits (by design)

- A sender that controls inbox directory names can deliver genuine packets out of order, so
  older ones are rejected as regressions. It can never get an unsigned packet accepted.
- Published documents are projections; after a crash between receipt and publication the
  document can lag until the next event for that device. The receipt ledger is the authority.
- A damaged ledger (receipt, alert or integration) stops ingest until an operator repairs it:
  WatchTower never extends a ledger past a defect. Witnessing failures do not stop ingest; they
  are recorded in `runtime/last_ingest.json` (`integration_witness_error`) and retried.
- 2.1 rejects a key id used under two principals (NeverLost rule). A 2.0 state root that did
  that must re-enroll one of the keys under a new id before upgrading.
- `nfl/ingest-receipt` is authorised for WatchTower's key but not used yet.

## 4. Legacy v1 (not part of the gate)

| Claim in the repository | Status |
|---|---|
| `docs/WATCHTOWER_CANONICAL_STATUS.md`, `docs/WATCHTOWER_NFL_HANDOFF_LOCK.md`: NFL consume boundary "GREEN / LOCKED" | Not re-verified as a v1 claim. The consumer script now writes a `watchtower > nfl` integration receipt per run (tested). NFL no longer produces handoff bundles. |
| `watchtower-tier0-green` tag and `proofs/freeze/watchtower_tier0_v1/` | Certifies the v1 scripts only; not a v2 claim. |
| `scripts/validator_scan_targeted.ps1`, `_RUN_clarity_tier1_step6_v1.ps1` | Clarity's scanner, misplaced here; the source of the registry edge `watchtower > clarity` that proposal 0007 asks to drop. |
| v1 CLI, bridge server, NFL duplication scripts, `release/watchtower_cli_v1` | Unchanged since the 2026-10-13 move (paths project-relative). |
| `docs/spec-watchtower.md`; schemas `attestation_record_v1`, `device_identity_v1`, `ledger_event_v1`, `observation_set_v1`, `watchtower.device.v1`, `watchtower.device_event.v1` | History; not emitted by v2. |

## 5. Location and local data

The project lives under the S: dev root at `Constellation/_Covenant-systems/watchtower`, with
`cpr`, `neverlost`, `nfl` and `arbiter` as sibling folders. Everything is saved inside the project;
scratch goes to `.scratch/`.

| Item | State |
|---|---|
| Constellation documents | Constellation's publish now ships read-only copies in `.constellation/` (registry 2.16.0) and the managed blocks point at them; the old `../Constellation` links are gone |
| NFL inbox registry | Still names `C:/dev/watchtower/packets/outbox` (NFL side, proposal 0007 §3) |
| Local keys | `proofs/keys/` on the host holds v1 keys, including one marked `COMPROMISED`; none is tracked by git. Delete or archive them outside the repository when no longer needed |

## 6. Open decisions

`docs/proposals/`: 0004 CPR on Linux/macOS (CPR owner), 0005 default branch, licence, legacy
scripts (owner), 0007 registry and neighbour requests (Constellation, NFL, NeverLost,
live-state-surgeon, Covenant Gate, Arbiter). 0001, 0002 and 0006 are done; 0003 is superseded by
0007.
