# WatchTower — Official Work Breakdown Structure (v2)

| | |
|---|---|
| Document | `WATCHTOWER_WBS_OFFICIAL_v2` — supersedes `docs/history/WATCHTOWER_WBS_OFFICIAL_v1.md` |
| Date | 2026-10-13, statuses updated 2026-10-15 (module 2.1.0) |
| Scope | The registry role: deterministic verifier and telemetry receipt authority (owner decision 2026-10-13; `docs/proposals/0001-…`) |
| Baseline | branch `finish/canonical-verifier-20261013` on `master` @ `691f1ab` via `audit/hygiene-fixes-20260826` @ `517b925` |
| Companion | `WATCHTOWER_DOD_OFFICIAL_v2.md` (acceptance), `canonical/CURRENT_STATE.md` (evidence) |

## 0. Why v2

WBS v1 audited WatchTower as a device-custody product and found its spine (live capture → sign →
verify → attest) unbuilt. The registry assigns capture and materialization to live-state-surgeon
and the verifier role to WatchTower. v2 re-baselines on that role. Rows of v1 that belong to
capture are moved, not dropped (§3).

Status vocabulary is v1's: ✅ verified by a rerunnable artifact · 🟡 partial · 🔴 not proven ·
⬜ not built. A token or label alone never earns ✅.

## 1. Work breakdown

| WBS | Work package | Status | Evidence / gap |
|---|---|---|---|
| **1** | **Core library** (strict JSON, canonical JSON, UTF-8/LF I/O, atomic writes, SHA-256, path safety) | ✅ | `tests/Core.Tests.ps1` (65) |
| **2** | **PCv1 Option A verifier + builder**, CPR-conformant | ✅ | `tests/Packet.Tests.ps1` (30); Interop: CPR agrees on all golden vectors |
| **3** | **Trust**: authority key, NeverLost bundle, derived `allowed_signers`, producer enrolment | ✅ | Ingest trust cases; Interop: byte-identical with NeverLost |
| **4** | **Telemetry verifier** (LSS wire contract, 5 stages, per-type bodies) | ✅ | `tests/Telemetry.Tests.ps1` (45) |
| **5** | **Ingest**: stateful rules, routing, receipts, crash recovery, hostile-input resilience | ✅ | `tests/Ingest.Tests.ps1` (29) |
| **6** | **Published evidence**: device documents, Constellation health facet, alerts | ✅ | Ingest + Schemas |
| **7** | **Sealing**: checkpoint, NFL receipt packet, device pledge, ledger re-verification | ✅ | Ingest; Interop: `CPR_VERIFY_OK` on the outbox packet |
| **8** | **Schemas** for every emitted and accepted artifact, enforced by tests | ✅ | `tests/Schemas.Tests.ps1` (15), 18 schemas |
| **9** | **CLI** `bin/watchtower.ps1` with stable tokens | ✅ | `tests/Cli.Tests.ps1` (12) |
| **10** | **Gate**: isolated suites, non-mutation check, schema-validated report | ✅ on Linux | `scripts/_RUN_watchtower_canonical_full_green_v2.ps1` → `suites=7 cases=222`, `WATCHTOWER_INTEROP_OK cases=10` |
| **11** | **CI** on Ubuntu pwsh 7, Windows pwsh 7, Windows PowerShell 5.1 | 🟡 | Workflow written; runs when the branch is pushed |
| **12** | **Windows host run** of the gate and of `init → enroll → ingest → doctor` | 🔴 | Needs the Windows host or CI: `RUN_TIER0_GATE.cmd` |
| **13** | **Canonical docs and contracts** | ✅ | `docs/canonical/{IDENTITY,SPEC,CURRENT_STATE}.md`, `docs/contracts/*` |
| **14** | **Hygiene** (node_modules untracked, LF attributes, CLI selftest) | ✅ in branch | Local-only items remain on the host (proposal 0005 §4) |
| **INT-1** | live-state-surgeon emits conformant packets | ✅ | Integration (fixtures from LSS `37e7fe2`), Interop (live re-emission, byte-identical) |
| **INT-2** | live-state-surgeon materializer reads WatchTower's receipts | 🟡 | Implemented and tested on the LSS side (`selftest_lss_integration_v1.ps1`); not re-run from here |
| **INT-3** | NFL witnesses WatchTower's outbox end to end | 🟡 | CPR accepts receipt and witness packets; NFL commits no hash yet (proposal 0007 §3) |
| **INT-4** | Constellation oversight reads the health facet | 🟡 | Shape matches the reader; live read not recorded |
| **INT-5** | Global Workbench plugin panels over `evidence_index.json` | ⬜ | Plugin declares panels; not implemented |
| **INT-6** | Registry updated for v2 outputs and receipt states | 🔴 | Proposal 0007 (Constellation owner) |
| **INT-7** | CPR runs on Linux/macOS without a shim | 🔴 | Proposal 0004 (CPR owner) |
| **INT-8** | Integration receipts (Constellation 0013) for every exchange WatchTower consumes | ✅ | Integration suite; witness packets accepted by CPR (Interop) |
| **INT-9** | Policy gate with Arbiter (`watchtower > arbiter`, Constellation 0012) | ✅ | Integration (all outcomes), Interop (real engine, `arbiter verify`) |
| **INT-10** | NeverLost v1 bundles and `enroll -FromBundle` | ✅ | Integration; Interop (NeverLost fail-closed verifier) |
| **REL-1** | Default branch, licence, legacy scripts relocation | 🔴 | Owner decisions; proposal 0005 |
| **REL-2** | v2 freeze and tag | ⬜ | After WBS 11–12 and INT-1 (DoD v2 §4) |

## 2. Critical path to a v2 seal

1. Push the branch and get CI green on all three hosts (WBS 11).
2. Run the gate and a real `init → enroll → ingest → doctor` on the Windows host (WBS 12).
3. ~~live-state-surgeon fixes its emitter (INT-1)~~ done 2026-10-15.
4. NFL witnesses one WatchTower outbox packet (INT-3).
5. Freeze and tag per DoD v2 §4.

## 3. Where the v1 rows went

| v1 WBS | v1 subject | v2 |
|---|---|---|
| 1–3 | packet transport, terminal-state ingest, receipt substrate | rebuilt as WBS 2, 5, 7 |
| 4 | trust bootstrap | WBS 3 (NeverLost format) |
| 5–6 | device identity (synthetic / real host) | NeverLost (identity) + live-state-surgeon (device agent) |
| 7–11 | enumerators, signed observation emission, live observation verification | live-state-surgeon emits; WatchTower verifies (WBS 4) |
| 12 | attestation engine | policy attestation verification (WBS 4, `policy_pins`) |
| 13–14 | posture / state materialization | live-state-surgeon (materialization); WatchTower verifies posture hashes |
| 15 | alert derivation | WBS 6 |
| 16 | append-only ledger | WBS 5, 7 |
| 17 | negative vectors | WBS 1–9 (every stage and failure code) |
| 18–19 | telemetry schemas and pipeline | WBS 4, 8 |
| 20 | session export | NFL receipt packet (WBS 7) |
| 21–25 | TRIAD, NFL, Legacy Doctor, Atlas, Archive/Recall | NFL = INT-3; others remain contract-only (`contracts/`) |
| 26–27 | workbench UI, local bridge | capture UI/bridge → live-state-surgeon (proposal 0001); operator UI → INT-5 |
| 28–33 | SaaS, packaging | out of scope until REL-2 |
| 34 | Tier-0 seal | REL-2 |
| H1–H9 | hygiene | WBS 14; H9 (CLI selftest) done in branch |
