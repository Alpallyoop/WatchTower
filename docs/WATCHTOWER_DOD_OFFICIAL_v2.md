# WatchTower — Official Definition of Done (v2)

| | |
|---|---|
| Document | `WATCHTOWER_DOD_OFFICIAL_v2` — supersedes `docs/history/WATCHTOWER_DOD_OFFICIAL_v1.md` |
| Date | 2026-10-13, statuses updated 2026-10-15 (module 2.1.0) |
| Scope | WatchTower as deterministic verifier and telemetry receipt authority |

## 0. Governing law (unchanged from v1)

> A criterion is met only when a named, reproducible artifact proves it — not when a token, tag,
> commit message or prior document says so.

- A token proves a code path ran. It counts only when the runner that prints it cannot print it
  after a failure and its scope is exactly what it claims.
- Self-referential proof does not count. Verification is proven on packets produced by a
  different key and code path than the verifier's (the reference producer, CPR's vectors, the
  recorded live-state-surgeon packet).
- Fail-closed is a deliverable: every accept path has negative cases that must reject with a
  named code.
- A skipped check is reported as skipped, never as passed.

## 1. Tier-0 (standalone verifier)

| DoD | Criterion | Status | Evidence |
|---|---|---|---|
| D1 | Strict, canonical, deterministic I/O: BOM, CR, invalid UTF-8, duplicate keys, floats and non-canonical ledger lines are rejected | ✅ | Core |
| D2 | PCv1 Option A verification agrees with CPR on every CPR vector and on WatchTower's own packets, tampered or not | ✅ | Packet, Interop |
| D3 | Trust is pinned: only enrolled producers, only their namespaces; packet-supplied trust ignored; test keys refused | ✅ | Telemetry, Ingest |
| D4 | Every telemetry stage has positive and negative cases with exact failure codes | ✅ | Telemetry (45 cases) |
| D5 | Replay, duplicate, sequence, time-regression and future-time rules hold across runs and restarts | ✅ | Ingest |
| D6 | One hash-chained receipt per packet; accepted packets move byte-identical; rejects are quarantined with a note; nothing in the inbox is modified | ✅ | Ingest |
| D7 | Evidence (device documents, health facet, alerts) only from signer-verified events; freshness is observation time | ✅ | Ingest, Schemas |
| D8 | Checkpoint, NFL packet and pledge are signed, cross-linked and re-verifiable from bytes; tamper and forgery detected | ✅ | Ingest |
| D9 | Determinism: two nodes with the same state, inbox, settings and time produce byte-identical outputs | ✅ | Ingest |
| D10 | Crash at any step is completed or detected by the next run | ✅ | Ingest (recovery) |
| D11 | No single hostile inbox packet can stop or wedge ingest | ✅ | Ingest (dos cases) |
| D12 | Every emitted artifact validates against a published schema, with a validator that refuses keywords it does not enforce | ✅ | Schemas |
| D13 | The gate cannot print success after a failure, mutates nothing, and writes a schema-valid report before its token | ✅ | Runner |
| D14 | **The gate passes on Windows PowerShell 5.1, Windows pwsh 7 and Linux pwsh 7** | 🔴 | CI workflow ready; not yet run |
| D15 | **A real Windows host runs `init → enroll → ingest → ledger → doctor -Publish` with its own keys** | 🔴 | Not yet run |

Tier-0 is done when D1–D15 are ✅.

## 2. Integration

| DoD | Criterion | Status |
|---|---|---|
| I1 | A packet emitted by live-state-surgeon's own code is accepted end to end | ✅ (Integration, Interop) |
| I2 | live-state-surgeon materializes from WatchTower's receipt ledger, after re-verifying it | 🟡 (LSS-side selftest; not re-run here) |
| I3 | NFL witnesses a WatchTower outbox packet and its receipt is recorded | 🟡 (CPR accepts; NFL commits no hash yet) |
| I4 | Constellation oversight reports a service's health from a WatchTower facet | 🟡 (shape verified) |
| I5 | Registry entries describe v2 outputs and a service-map receipt is recorded | 🔴 (proposal 0007) |
| I6 | Every exchange WatchTower consumes writes a `constellation.integration.receipt.v1`, failed ones included, handed to NFL | ✅ (Integration) |
| I7 | The policy gate routes on Arbiter's real decisions, fails closed, and every decision re-proves with `arbiter verify` | ✅ (Integration, Interop) |
| I8 | WatchTower's trust bundle passes NeverLost's fail-closed v1 verifier | ✅ (Interop, NeverLost `3de2ecb`) |

## 3. Standing quality gates (every change)

- The full gate is green on all three CI hosts; interop is OK where siblings are available, and
  PARTIAL is never reported as OK.
- New behaviour ships with a negative case; a fixed defect ships with a test that fails on the old
  code.
- PowerShell sources stay ASCII (enforced by Core).
- No keys, node state or `node_modules` in commits (`.gitignore`).
- Contract changes (identity, namespaces, schemas, receipt fields, layout, tokens) come with a
  proposal under `docs/proposals`.

## 4. Freeze and seal

1. Tier-0 D1–D15 ✅ and I1 ✅ (I1 done).
2. A freeze bundle `proofs/freeze/watchtower_v2_<timestamp>/` holding the CI reports
   (`watchtower.test_run.v1`) from all three hosts, the Windows host transcript, `sha256sums.txt`
   and the commit id.
3. Clean tree → commit → new tag (`watchtower-v2.0.0`, never reusing `watchtower-tier0-green`) →
   re-run the gate from the tag and reproduce the tokens.
4. Only then may a document say "WatchTower v2 Tier-0 sealed".
