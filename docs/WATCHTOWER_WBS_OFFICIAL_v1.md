# WatchTower — Official Work Breakdown Structure (WBS)

**Document:** `WATCHTOWER_WBS_OFFICIAL_v1`
**Status:** Authoritative — supersedes status claims embedded in prior handoff narratives
**Audit date (UTC):** 2026-08-26T14:52Z
**Repository:** `C:\dev\watchtower`
**Audited commit:** `691f1ab` (`watchtower-cli-v1.0.1`), branch `master`
**Working tree:** clean of tracked changes at audit time

---

## 0. How to read this document

Every status in this WBS is derived from **evidence inspected on disk on the audit date**, not
from commit messages, tags, `*_OK` tokens, or prior handoff prose. The governing rule for this
audit was: *a thing is not done, and evidence is not proof, merely because a label says GREEN or
DONE.* Several such labels exist in this repository and did **not** survive verification — they are
called out explicitly below.

### Status vocabulary

| Symbol | Meaning |
| --- | --- |
| ✅ **VERIFIED** | Capability demonstrated by on-disk evidence I read. Named evidence path given. |
| 🟡 **PARTIAL** | Real implementation exists but is incomplete, or only exercised on synthetic inputs. |
| 🔴 **NOT PROVEN** | Scoped/claimed but no runnable evidence found that the capability works end-to-end. |
| ⬜ **NOT BUILT** | No implementation on disk. |
| ⚠️ **OVERSTATED** | A GREEN/DONE/FREEZE label exists in the repo but the underlying evidence does **not** support the claim as worded. |

### One environment caveat

The audit shell runs in a **Linux** VM over the connected folder. Windows PowerShell 5.1 is **not**
available there, so the `.ps1` runners could **not be re-executed live**. Verification was therefore
**static + artifact-based**: reading the scripts, and reading the transcripts / receipts / state /
manifests those scripts previously produced. Where a status depends on a run I could not reproduce,
it is marked and dated (the newest full-green transcript on disk is **2026-04-09**, i.e. ~4.5 months
before this audit). A live re-run on the Windows host is the single most valuable next confirmation
and is listed in the DoD.

---

## 1. Audit reconciliation — claims vs. evidence

These are the material discrepancies between what the repo *asserts* and what its evidence *shows*.
They drive the status column in the WBS table.

1. **"Tier-0 freeze" / "FULL GREEN" / `watchtower-tier0-green` tag are real artifacts but OVERSTATE
   scope.** A freeze bundle (`proofs/freeze/watchtower_tier0_v1/`) and a full-green transcript ending
   in `WATCHTOWER_LIVE_STATE_FULL_GREEN_OK` exist. But that runner (a) **re-signs its own payload
   before verifying it** (`PAYLOAD_REPLACE` → `RESIGN` → `VERIFY`), which is a self-referential
   round-trip, not independent verification, and arguably violates the project's own non-mutation
   law; and (b) exercises the state/observation chain on **synthetic `test_vectors/*.ndjson`**, not
   on live device/storage observation. The freeze therefore certifies the *transport + synthetic
   state substrate*, **not** the attested live-device plane that both handoffs define as WatchTower's
   actual job. Treat the Tier-0 seal as **NOT valid** for the domain DoD.

2. **Live device/storage/process observation is MORE complete than handoff #1 admits.** The CLI
   engine (`release/watchtower_cli_v1/scripts/watchtower_engine_v1.ps1`) genuinely enumerates real
   disks, volumes and processes via `Get-Disk`, `Get-Volume`, and `Get-CimInstance Win32_Process`
   (with serial hashing, health status, filesystem, partition style). The Node bridge serves this
   live. Handoff #1 marked "device/storage enumerator: NOT PROVEN" — that is **out of date**.

3. **…but that live observation is UNSIGNED and disconnected from the evidence chain.** The engine
   writes plain `drives.json` / process JSON runtime artifacts. Nothing signs them, binds them to a
   verified device identity, verifies them, attests them, or appends them to the ledger. The signed
   chain (device bootstrap → append → bind → verify → state) runs **only on synthetic device IDs and
   canned telemetry**. So WatchTower has a **real observer** and a **real signer**, but **they are two
   halves that do not yet meet.** This is the single biggest gap between current reality and the DoD.

4. **The handoff #1 "trust bootstrap BLOCKER" is stale — it is fixed.** `proofs/trust/trust_bundle.json`,
   `proofs/trust/allowed_signers`, and a live key pair (`proofs/keys/wt_key`, `wt_key.pub`) exist and
   are used by the transcript (`Good "watchtower/telemetry" signature … ED25519 …`). The
   `MISSING_PRIVATE_KEY` blocker no longer reproduces.

5. **Attestation engine is schema-only.** `schemas/attestation_record_v1.json` and
   `schemas/observation_set_v1.json` exist and are well-formed, but **no script references or produces
   them.** There is no runnable attestation step. NOT PROVEN.

6. **Negative-case coverage is thin.** Only **4** negative vectors exist
   (`negative_bad_packet_id`, `negative_bad_sha`, `negative_bad_sig`, `pcv1/tampered_manifest`)
   against the **~14** the DoD requires (wrong/unknown signer, bad device identity, missing
   observation field, invalid schema, replay/duplicate, out-of-order, policy-hash mismatch, stale,
   contradictory storage, tampered attestation, corrupt ledger line).

7. **Two parallel, un-reconciled schema families.** A tenant/SaaS-flavoured set (`observation_set_v1`,
   `attestation_record_v1`, `device_identity_v1`, `ledger_event_v1` — all carry `tenant_id`,
   `policy_ref`) and a telemetry-flavoured set (`watchtower.heartbeat/health_report/state/…`). The
   runner uses only the telemetry set; the SaaS set is design-only.

8. **Repository hygiene defects** (details in §4): a corrupt directory literally named
   ``k in $Map.Keys){ [void]$keys.Add([string]$k) }`` (a botched PowerShell redirect created it);
   dead duplicate UI sources; a stray empty top-level `workbench/`; a **compromised** and a
   **passphrase** authority private key still sitting in `proofs/keys/`; `node_modules` not
   git-ignored; 18 `allowed_signers.bak_*` files; the current materialized `watchtower_state.json`
   is `"broken"`/`"device-fail"` — a **leftover synthetic test artifact**, not real device state.

---

## 2. Canonical WBS

Scope tiers: **T0** = required for a *legitimate* standalone Tier-0 seal; **INT** = ecosystem
integration; **SaaS** = hosted product; **REL** = packaging/release; **HYG** = hygiene/quality gate.

| WBS | Workstream | Scope | Verified status | Evidence inspected / why |
| --- | --- | --- | --- | --- |
| **0** | Repo & runtime hygiene | HYG | 🟡 PARTIAL | Git tree clean (tracked); `.gitignore` guards keys/receipts. **But** corrupt dir name, dead dup UI files, stray `workbench/`, lingering compromised keys, `node_modules` untracked. See §4. |
| **1** | PCv1 packet transport + verification | T0-support | ✅ VERIFIED (roundtrip) | `full_green.stdout.txt`: sign + verify with real ed25519 key; `scripts/watchtower_verify_packet_v1*.ps1`, `test_vectors/pcv1/`. ⚠️ full-green path re-signs before verifying — see §1.1. |
| **2** | Terminal-state ingest (inbox→quarantine/receipt) | T0-support | ✅ VERIFIED | `scripts/watchtower_ingest_inbox_verify_pcv1_v1.ps1`, `docs/WATCHTOWER_TERMINAL_STATE_LAW_PCV1_V1.md`, `packets/{inbox,quarantine,receipts,outbox}` present. |
| **3** | Receipt / proof substrate | T0-support | ✅ VERIFIED | `proofs/receipts/*.ndjson`, freeze bundle + `freeze_manifest.json` with sha256 of transcripts. |
| **4** | Trust / identity bootstrap | T0 | ✅ VERIFIED (blocker cleared) | `proofs/trust/trust_bundle.json`, `allowed_signers`, `proofs/keys/wt_key(.pub)`; transcript shows good signature. Handoff "blocker" is stale. Key **hygiene** issues → WBS 0. |
| **5** | Device identity — synthetic | T0 | 🟡 PARTIAL | Device-binding selftest passes (`936257f4…` device id, `multi_device_rejected` case). Runs in scratch dir on synthetic IDs, **not the real host**. |
| **6** | Device identity — real host binding | T0 | 🔴 NOT PROVEN | No evidence the real machine's hardware facts (from the CIM engine) are bound into a stable, verifiable `watchtower.device.v1` identity. |
| **7** | Local device / platform enumerator | T0 | ✅ VERIFIED | `watchtower_engine_v1.ps1` uses `Get-CimInstance Win32_OperatingSystem/Win32_Processor`; bridge serves it. (Handoff said NOT PROVEN — out of date.) |
| **8** | Storage / volume / disk enumerator | T0 | ✅ VERIFIED | Engine `Get-Disk` / `Get-Volume` → disk_id, serial_hash, health_status, filesystem, size_remaining; bridge `/engine/observe-drives`. |
| **9** | Process enumerator + origin derivation | T0 | 🟡 PARTIAL | Engine `Get-CimInstance Win32_Process`; bridge `/engine/observe-processes` with process_hash, command_line_hash, origin classify. Origin logic is heuristic; unverified against negative cases. |
| **10** | **Signed** observation emission (bind live obs → identity + signature) | T0 | 🔴 NOT PROVEN | Live obs written as **plain** `drives.json` etc. No script signs live observations. The signer only runs on canned telemetry. **Core missing link.** |
| **11** | Observation verification (non-mutating, of live obs) | T0 | 🔴 NOT PROVEN | Telemetry verify exists (`watchtower_verify_telemetry_*`) but only for synthetic ndjson; no verified-observation path from real host output. |
| **12** | Attestation engine | T0 | 🔴 NOT PROVEN | `schemas/attestation_record_v1.json` exists; **no script references/produces it.** Zero runnable attestation. |
| **13** | Posture / state evaluator | T0 | 🟡 PARTIAL | State selftest deterministically maps `ok/stale/drift/failure→broken` on synthetic vectors (`test_vectors/watchtower/state/v1/`). Not driven by live evidence; enum not frozen in a spec file. |
| **14** | State materializer (deterministic reducer) | T0 | 🟡 PARTIAL | `proofs/state/watchtower_state.json` is produced by the runner, but current value is a **leftover synthetic `device-fail`/broken** record. No append-replay determinism test on disk. |
| **15** | Alert derivation | T0 | 🟡 PARTIAL | `WATCHTOWER_ALERT_DERIVE_OK`, `ALERT_COUNT` per case, `proofs/state/watchtower_alerts.ndjson`, `schemas/watchtower.alert.v1.json`. Synthetic-only; no alert-with-evidence-ref on live data. |
| **16** | Append-only device ledger | T0 | 🟡 PARTIAL | Device chain selftest: bootstrap→append→verify-good→**tamper-detected**. `schemas/ledger_event_v1.json` (tenant flavour) unused. Chain proven on synthetic events only. |
| **17** | Negative / corruption vectors | T0 | 🟡 PARTIAL | 4 of ~14 required vectors present. Fail-closed proven for packet id/sha/sig + tampered manifest only. |
| **18** | Telemetry schemas (heartbeat/health/policy_attest/alert) | T0 | ✅ VERIFIED (present) | `schemas/watchtower.{heartbeat,health_report,policy_attest,alert}.v1.json` well-formed with `required`/`const`. |
| **19** | Telemetry **verification pipeline** (validate+bind+receipt, all types, w/ negatives) | T0 | 🟡 PARTIAL | Sign/verify/bind scripts exist; state ndjson verified. Per-type schema validation + per-type negative rejection not evidenced as one pipeline. |
| **20** | Session export | T0 | 🔴 NOT PROVEN | No `*export*`/`*session*` script found in `scripts/`. Handoff #2 called it "partially implemented"; not on disk. |
| **21** | TRIAD evidence ingest | INT | 🟡 CONTRACT-ONLY | `contracts/triad_to_watchtower.md`, `contracts/watchtower_to_triad.md`. No verified run. |
| **22** | NFL duplication / witness | INT | 🟡 PARTIAL | `scripts/watchtower_consume_nfl_handoff_v1.ps1`, `test_vectors/handoff_frozen/…green_20260308`, `docs/WATCHTOWER_NFL_HANDOFF_LOCK.md`. Handoff frozen vector exists; live NFL round-trip unverified. |
| **23** | Legacy Doctor integration | INT | ⬜ CONTRACT-ONLY | `contracts/watchtower_to_legacy_doctor.md` only. |
| **24** | Atlas integration | INT | ⬜ CONTRACT-ONLY | `contracts/watchtower_to_atlas.md` only. |
| **25** | Archive/Recall + Covenant Gate contracts | INT | ⬜ CONTRACT-ONLY | `contracts/watchtower_to_archive_recall.md`; Covenant Gate referenced, no contract file. |
| **26** | Standalone workbench UI | Product | 🟡 PARTIAL | Clean rebuild real: `dist/assets/index-*.js` ≈152 KB, css ≈4.6 KB; `tsc -b` exits 0 (typecheck green). Duplicate/dead shell + api files remain; live render vs bridge not screenshot-verified. |
| **27** | Local bridge / API | Product | 🟡 PARTIAL | `ui/workbench/watchtower_bridge_server.cjs` (~1381 lines), port 43187, 127.0.0.1, real CIM calls. **CORS `*`**, no route allow-list hardening, alias cleanup pending. |
| **28** | Hosted ingest / API | SaaS | ⬜ NOT BUILT | No server code beyond local bridge. |
| **29** | Multi-tenant data plane | SaaS | ⬜ NOT BUILT | Tenant-aware schemas exist; no enforcement, no store. `docs/rbac.md` is doc-only. |
| **30** | Hosted dashboard | SaaS | ⬜ NOT BUILT | — |
| **31** | Alerts / notifications (hosted) | SaaS | ⬜ NOT BUILT | — |
| **32** | Licensing / entitlements | Commercial | ⬜ NOT BUILT | — |
| **33** | Packaging / installer / service | REL | 🟡 PARTIAL | `release/watchtower_cli_v1.zip` + CLI freeze bundle exist. Service/installer discipline unverified; UI Tauri packaging not confirmed. |
| **34** | Legitimate Tier-0 freeze / seal | T0-final | ⚠️ OVERSTATED | A freeze + `watchtower-tier0-green` tag exist but certify the wrong scope (§1.1). A domain-valid seal is **not** yet earned. |

---

## 3. Critical path to a *legitimate* Tier-0 seal

The existing green covers **infrastructure**. The unbuilt spine is **live evidence**. In dependency order:

1. **WBS 6** — bind the real host (CIM facts) into a stable, reproducible `watchtower.device.v1` identity.
2. **WBS 10** — sign live observations (`drives.json`/process sets) against that identity → real signed `observation_set_v1`.
3. **WBS 11** — verify those live signed observations non-mutatingly (independent verifier, not a re-sign).
4. **WBS 12** — produce a real `attestation_record_v1` under a pinned policy from verified live observations.
5. **WBS 13–16** — derive posture + materialize state + append to ledger from that real attestation; prove replay determinism.
6. **WBS 17** — expand negatives to the full ~14-vector set; prove every one fails closed.
7. **WBS 20** — session export bundling the above with hashes + receipt.
8. **WBS 34** — only then a new full-standalone runner emitting a *scoped, unambiguous* token
   (e.g. `WATCHTOWER_DEVICE_STATE_TIER0_FULL_GREEN_OK`), and a freeze whose transcript shows **live**
   observation, not `PAYLOAD_REPLACE`/`RESIGN` on canned vectors.

Everything in WBS 21–33 is downstream of, and blocked by, a legitimate #8.

---

## 4. Hygiene backlog (WBS 0) — concrete items

| # | Item | Location | Fix |
| --- | --- | --- | --- |
| H1 | Corrupt directory name from a botched PowerShell redirect | repo root: ``k in $Map.Keys){ [void]$keys.Add([string]$k) }`` | Inspect contents, then remove (needs delete permission on the connected folder). |
| H2 | Compromised + passphrase **private** authority keys retained | `proofs/keys/watchtower_authority_ed25519.COMPROMISED.*`, `.PASSPHRASE.*` | Move to secure offline store or destroy; never rotate back into trust. |
| H3 | Dead / duplicate UI sources | `ui/src/watchtower_ui_workbench_shell.tsx` (root), `…shell.tsx.bak_v21a_*`, `ui/src/lib/watchtower_api.ts` | `main.tsx` imports `src/workbench/…`; delete the unused root copies. |
| H4 | Stray empty top-level workbench | `./workbench/` (only `package.json` + `node_modules`) | Remove; the real one is `ui/workbench/`. |
| H5 | `node_modules` not ignored → ~10k untracked files, `git status` unusably slow | `ui/node_modules`, `workbench/node_modules` | Add to `.gitignore`. |
| H6 | 18 `allowed_signers.bak_*` + `trust_bundle.json.bak_*` accumulating | `proofs/trust/` | Prune; keep one archival copy if needed. |
| H7 | Bridge CORS wide open | `watchtower_bridge_server.cjs` (`Access-Control-Allow-Origin: *`) | Restrict to the local UI origin; add route allow-list. |
| H8 | Stale materialized state is a synthetic failure record | `proofs/state/watchtower_state.json` (`device-fail`/broken) | Re-materialize from a real host run so state reflects reality, not a test vector. |

---

## 4a. Addendum A — Live run on host `anakin`, 2026-08-26T18:59Z

The PowerShell runners were re-executed live on the Windows host via
`scripts/_AUDIT_liverun_v1.ps1` (evidence under `proofs/audit_liverun/20260826T185904Z/`).
This **supersedes the April-transcript dating** for the items below.

| Step | Exit | Result | Note |
| --- | --- | --- | --- |
| `_RUN_watchtower_tier0_full_green_v1` | 0 | ✅ token seen | Substrate green **today**, not just April. |
| `_RUN_watchtower_live_state_full_green_v1` | 0 | ✅ `WATCHTOWER_LIVE_STATE_FULL_GREEN_OK` | |
| `_selftest_watchtower_packet_verify_v1` | 0 | ✅ | positive + negatives |
| `_selftest_watchtower_state_v1` | 0 | ✅ | ok/stale/drift/broken |
| `_selftest_watchtower_device_chain_v1` | 0 | ✅ | tamper detected |
| `_selftest_watchtower_device_binding_v1` | 0 | ✅ | multi-device rejected |
| `_selftest_packet_constitution_v1` | 0 | ✅ `SELFTEST_OK` | (harness didn't know token; verified in transcript) |
| `_selftest_watchtower_ingest_move_pcv1_v1` | 0 | ✅ `PCV1_OK` | moved packet inbox→receipts |
| `_selftest_watchtower_cli_v1` | **1** | 🔴 **FAIL** | `WATCHTOWER_CLI_FAIL: UNKNOWN_COMMAND: device` → `DEVICE_LIST_EXIT_1` |

**Two firm empirical conclusions:**

1. **Non-mutation holds in practice.** Across the entire run the only working-tree change was the
   derived `proofs/state/watchtower_state.json`; **no evidence vector was left altered.** The §1.1
   critique of the full-green runner is therefore narrowed from "mutates evidence" to
   **"self-referential scope"** — it re-signs its own payload and verifies that, and it runs on
   synthetic vectors. That is still the reason the seal doesn't cover the live-device domain, but it
   is *not* a non-mutation violation. (Item 3 wording in §1 is corrected accordingly.)

2. **New defect — shipped CLI is broken against its own selftest.** `watchtower_cli_v1.ps1`'s command
   switch implements `engine observe-device` but **no top-level `device` command**, while
   `_selftest_watchtower_cli_v1.ps1` calls `watchtower device list`. The `watchtower-cli-v1.0.1`
   release therefore fails its own CLI selftest. This is a real regression in WBS 33 and is added to
   the hygiene backlog (H9).

Everything the live run proves green is exactly the **synthetic substrate**; the CLI step that is
supposed to touch a real device is the one that fails. This *confirms* the audit's central finding
rather than softening it: the domain plane (WBS 6, 10–12) is still unproven.

### Backlog addition

| # | Item | Location | Fix |
| --- | --- | --- | --- |
| H9 | CLI/selftest command mismatch: `device list` unimplemented | `scripts/watchtower_cli_v1.ps1` vs `scripts/_selftest_watchtower_cli_v1.ps1` | Implement a `device` command (or repoint the selftest at `engine observe-device`); re-run CLI selftest to green. |

---

## 5. Provenance

Audited at commit `691f1ab` on branch `master`, working tree clean (tracked). Evidence read
included: `proofs/freeze/watchtower_tier0_v1/{full_green.stdout.txt,freeze_manifest.json}`,
`proofs/state/watchtower_state.json`, `proofs/trust/{trust_bundle.json,allowed_signers}`,
`proofs/keys/`, `proofs/progress/watchtower_dod_progress_v1_*.json`,
`release/watchtower_cli_v1/scripts/watchtower_engine_v1.ps1`,
`ui/workbench/watchtower_bridge_server.cjs`, `ui/src/main.tsx`, `schemas/*.json`,
`test_vectors/**`, and the `scripts/` inventory. PowerShell runners were **not** re-executed
(no Windows PS in the audit VM); statuses depending on a run are dated to the newest transcript
on disk (2026-04-09) and flagged for live re-run in the DoD.
