# WatchTower — Current State

As of 2026-10-13, branch `finish/canonical-verifier-20261013` (module 2.0.0).

This file only says what has been shown by evidence someone can rerun. A label such as GREEN,
LOCKED or FREEZE elsewhere in the repository is not evidence by itself.

## 1. Proven by the v2 gate

Command and result, Ubuntu Linux, PowerShell 7.4.6, OpenSSH 9.6p1, with a CPR checkout and NeverLost at
`1bd6d0e`:

```
WATCHTOWER_CPR_ROOT=<cpr> pwsh -File scripts/_RUN_watchtower_canonical_full_green_v2.ps1 -Scope all -ReportPath <file>
SUITE Core       OK   cases=65
SUITE Packet     OK   cases=30
SUITE Telemetry  OK   cases=45
SUITE Ingest     OK   cases=29
SUITE Cli        OK   cases=12
SUITE Schemas    OK   cases=15
SUITE Interop    OK   cases=9
WATCHTOWER_TIER0_FULL_GREEN_OK suites=6 cases=196
WATCHTOWER_INTEROP_OK cases=9
```

The repository was hashed before and after the run and did not change. The report is
schema-validated before the tokens print.

| Capability | Evidence |
|---|---|
| PCv1 Option A verification agrees with CPR on every CPR golden vector, on WatchTower's own outbox packet and on a tampered copy | Interop (real `verify_packet_v1.ps1`) |
| Telemetry verification: every stage and failure code, pinned trust, in-packet trust ignored | Telemetry |
| Replay, duplicate, sequence, clock-skew rules across runs | Ingest |
| Receipts, alerts, checkpoints, pledges re-verify from bytes; tampering and forged signatures detected | Ingest, Core |
| Byte-identical outputs on two independent nodes with the same inputs and time | Ingest (determinism) |
| Crash recovery: unsealed receipts and a checkpoint without packet/pledge are completed | Ingest (recovery) |
| Every emitted artifact and accepted inbound shape matches its schema | Schemas |
| `allowed_signers` byte-identical to NeverLost's own derivation | Interop |
| CLI tokens and exit codes | Cli |
| Hostile input: JSON smuggling (`Keys`/`Values`/`Count` keys), path tricks, surrogate truncation, named pipes cannot pass verification or stop ingest | Core, Packet, Ingest |

## 2. Not proven yet

| Item | Why | How to close |
|---|---|---|
| **Windows PowerShell 5.1 and Windows** | The gate has only run on Linux. A static review fixed the known 5.1 breaks (non-ASCII source, stdin BOM, stderr handling). | CI (`.github/workflows/tier0.yml`) runs Ubuntu pwsh 7, Windows pwsh 7 and Windows PowerShell 5.1. It has not run yet because the branch could not be pushed from the build environment. |
| live-state-surgeon packets accepted | Every packet LSS emits today is rejected (`MANIFEST_LISTS_OWN_SIGNATURE`); proposal 0002 lists the producer fixes | Re-run interop with a packet from a fixed emitter |
| NFL witnessing WatchTower's outbox end to end | CPR accepts the packet; NFL's poll-and-witness run on it has not been recorded | Run NFL against `packets/outbox` on the host and keep its receipt |
| Constellation oversight reading a live facet | Shape matches `oversight.mjs`'s reader; no run against a live WatchTower root recorded | Run oversight with a bound service |
| Private-key permissions on Windows | Win32-OpenSSH refuses keys readable by others. WatchTower now restricts every key it creates or signs with (`icacls`); this path has not executed on Windows yet. | Windows CI and a host run |
| Hosts with OpenSSH older than 8.1 (Windows 10, Server 2019 inbox 7.7) | No `ssh-keygen -Y` | `doctor` check `ssh_keygen` fails clearly; install OpenSSH 8.1+ |

## 3. Known limits (by design)

- A sender that controls inbox directory names can deliver genuine packets out of order, so
  older ones are rejected as regressions. It can never get an unsigned packet accepted.
- Published documents are projections; after a crash between receipt and publication the
  document can lag until the next event for that device. The receipt ledger is the authority.
- `nfl/ingest-receipt` is authorised for WatchTower's key but not used yet.

## 4. Legacy v1 (not part of the v2 gate)

| Claim in the repository | Status |
|---|---|
| `docs/WATCHTOWER_CANONICAL_STATUS.md`, `docs/WATCHTOWER_NFL_HANDOFF_LOCK.md`: NFL consume boundary "GREEN / LOCKED" | Not re-verified. The scripts' default paths now resolve inside the project and its sibling checkouts instead of fixed C: folders; their frozen vector remains in `test_vectors/`. |
| `watchtower-tier0-green` tag and `proofs/freeze/watchtower_tier0_v1/` | Certifies the v1 transport and synthetic state scripts only; its runner re-signs its own payload before verifying it (WBS v1 §1.1). Not a v2 claim. |
| `scripts/_RUN_watchtower_tier0_full_green_v1.ps1`, `_RUN_watchtower_live_state_full_green_v1.ps1` and the other v1 runners | Unchanged. The v1 live run mutated `proofs/state/watchtower_state.json` (August 2026 host run). |
| v1 CLI installer, bridge server, NFL duplication scripts | Repointed to project-relative defaults: install and inspector data under `local/`, scratch under `.scratch/`, NFL inbox as the sibling `nfl/packets/inbox`. The frozen `release/watchtower_cli_v1` bundle still contains the old Local AppData default until it is rebuilt with `_RUN_watchtower_cli_release_bundle_v1.ps1`. |
| Uncommitted local work from before the move | Preserved as commit `5371e93` on `wip/pre-s-drive-20261013` and merged into the v2 branch. |
| `scripts/_selftest_watchtower_cli_v1.ps1` | Repointed to commands the v1 CLI implements (quick-check, version, doctor, unknown-command fails). |
| `docs/spec-watchtower.md` | Conflicts with the registry role; superseded by `SPEC.md` pending proposal 0001. |
| Schemas `attestation_record_v1`, `device_identity_v1`, `ledger_event_v1`, `observation_set_v1`, `watchtower.device.v1`, `watchtower.device_event.v1` | Unchanged; not emitted by v2. |

## 5. Location and local data

The project lives under the S: dev root at `Constellation/_Covenant-systems/watchtower`, with
`cpr`, `neverlost` and `nfl` as sibling folders. Rules from the dev root apply: everything is saved
inside the project, scratch goes to `.scratch/`, and C: is read-only.

| Item | State |
|---|---|
| Working copy | Byte-identical to the former C: copy (690 files hashed outside `ui/`, 3,766 inside `ui/`, `ui/node_modules` listing identical); `git fsck` clean |
| Former Local AppData folders (`WatchTowerCLI`, `WatchTowerInspector`, 65 files, about 550 MB) | Copied into `local/` (git-ignored) and verified file by file; the CLI launchers in `local/WatchTowerCLI` now resolve relative to their own folder. The originals on C: are untouched. |
| `../Constellation` in `CLAUDE.md`, `AGENTS.md` and `ECOSYSTEM_INTEGRATION.md` | No longer resolves: the Constellation registry now lives at `../../Constellation-Network`. These blocks are generated by Constellation, so the fix belongs there (proposal 0005 §6). |
| NFL inbox registry | Still names an absolute C: path for `watchtower-outbox`; NFL must point it at this project's `packets/outbox` (proposal 0005 §6). |

## 6. Open decisions

See `docs/proposals/`: 0001 scope (capture moves to live-state-surgeon), 0002 live-state-surgeon
emitter fixes, 0003 registry entries, 0004 CPR on Linux/macOS, 0005 default branch, licence,
legacy scripts, local-only hygiene and follow-ups from the move to the S: dev root.
