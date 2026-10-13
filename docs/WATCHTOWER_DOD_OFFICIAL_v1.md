# WatchTower — Official Definition of Done (DoD)

**Document:** `WATCHTOWER_DOD_OFFICIAL_v1`
**Status:** Authoritative acceptance criteria for WatchTower Tier-0 and beyond
**Audit date (UTC):** 2026-08-26T14:52Z
**Repository:** `C:\dev\watchtower` @ `691f1ab` (`watchtower-cli-v1.0.1`)
**Companion:** `WATCHTOWER_WBS_OFFICIAL_v1.md`

---

## 0. The governing law of this DoD

> **A criterion is met only when a named, reproducible artifact proves it — not when a token,
> tag, commit message, or prior document says so.**

Consequences of that law for this project, established by the audit:

- A `*_OK` token printed by a script is **evidence of a code path executing**, never proof the
  domain requirement is satisfied. WatchTower already contains a `WATCHTOWER_LIVE_STATE_FULL_GREEN_OK`
  token and a `watchtower-tier0-green` tag that do **not** satisfy the Tier-0 DoD below.
- **Self-referential proof does not count.** A runner that replaces a payload, re-signs it with the
  local key, then verifies that same signature has proven a sign/verify round-trip — it has **not**
  proven verification of independently produced evidence. The current full-green runner does exactly
  this (`PAYLOAD_REPLACE` → `RESIGN` → `VERIFY`) and so cannot certify the verification requirement.
- **Synthetic-input proof does not count for live-domain criteria.** Passing on
  `test_vectors/*.ndjson` proves the reducer's logic; it does **not** prove WatchTower can observe,
  sign, verify, and attest the **real machine**. Every "live" criterion below must be met with data
  originating from a real host enumeration in the same run.
- **Fail-closed is a first-class deliverable.** A positive pass with missing negative vectors is
  **not** done. Each negative case must be a committed vector that demonstrably rejects.

### Acceptance evidence — required form

Every DoD line is "done" only when there exists, committed under `proofs/`:
a **transcript** (stdout+stderr), the **input artifact hash(es)**, the **output artifact(s)**, a
**receipt** line, and — for freeze-level items — a **manifest with sha256 of the transcript**. An
item whose only evidence is a source file or a schema is at most **PARTIAL**, never done.

---

## 1. Definition of Done — WatchTower **Tier-0 (standalone)**

Tier-0 is done when **all** of DoD-1 … DoD-15 below are ✅ with the evidence form above, produced in
a **single canonical standalone run on a real Windows host**, and sealed per §4.

Current audited status is shown so the gap is explicit. Legend: ✅ done · 🟡 partial · 🔴 not proven.

### DoD-1 — Trust bootstrap is reproducible 🟡
- **Done when:** from a clean state, one command regenerates authority key → public key →
  `trust_bundle.json` → `allowed_signers`, and a signature verifies against it, with a transcript.
- **Now:** trust materials exist and a good signature verifies (`proofs/trust/*`, `proofs/keys/wt_key`).
  Missing: a clean-room *regeneration* transcript, and retirement of the lingering
  `COMPROMISED`/`PASSPHRASE` private keys (WBS 0/H2). The original `ssh-keygen -N ""` failure must be
  shown fixed by a committed run, not asserted.

### DoD-2 — Real host receives a stable device identity 🔴
- **Done when:** the real machine's enumerated hardware facts (from the CIM engine) are bound into a
  `watchtower.device.v1` record; restarting WatchTower yields the **same** `device_id`; and that
  identity is independently verifiable from its evidence.
- **Now:** device identity is proven only for **synthetic** IDs in a scratch selftest. No real-host
  binding on disk.

### DoD-3 — Deterministic device/platform enumeration 🟡→✅(capability) / 🔴(evidence)
- **Done when:** a committed run captures OS/CPU/platform identity for the real host with a stable,
  hashable representation and a receipt.
- **Now:** the *capability* is real (`Get-CimInstance Win32_OperatingSystem/Win32_Processor`), but no
  committed evidence artifact ties a captured enumeration to a receipt under `proofs/`.

### DoD-4 — Deterministic storage/drive enumeration 🟡→✅(capability) / 🔴(evidence)
- **Done when:** physical disks + volumes + mounts + filesystem + health are captured for the real
  host, with canonical identifiers (not merely Windows' labels), hashed, and receipted.
- **Now:** capability real (`Get-Disk`/`Get-Volume`, serial-hashing, health_status). Missing: a
  committed, receipted evidence artifact of a real enumeration.

### DoD-5 — Signed observation emission 🔴  *(critical missing link)*
- **Done when:** a live observation (drive set / process set / health) is serialized as
  `observation_set_v1`, bound to the device+observer identity, and **cryptographically signed**, with
  transcript + receipt.
- **Now:** live observations are written **unsigned** (`drives.json`). The signer only ever runs on
  canned telemetry. This is the primary blocker between "system monitor" and "verification plane."

### DoD-6 — Non-mutating verification of live observations 🔴
- **Done when:** a **separate** verify invocation validates a signed live observation **without
  altering it** (input hash identical before/after), and fails on any tamper — proven, not re-signed.
- **Now:** only synthetic telemetry verify exists; and the full-green path re-signs rather than
  independently verifies (see §0).

### DoD-7 — Negative verification fails closed (full set) 🟡
- **Done when:** committed vectors exist and demonstrably reject for **all** of: tampered observation,
  wrong signer, unknown signer, bad device identity, bad event hash, missing observation field,
  invalid schema, replayed/duplicate event (where forbidden), out-of-order event (where invalid),
  policy-hash mismatch, stale observation, contradictory storage state, tampered attestation, corrupt
  ledger line.
- **Now:** 4 of ~14 present (`negative_bad_packet_id/sha/sig`, `tampered_manifest`). Rejection proven
  for those four only.

### DoD-8 — Attestation engine 🔴
- **Done when:** verified live observations produce a deterministic `attestation_record_v1` under a
  **pinned policy hash**, binding device identity + evidence set + result + reason codes + signature;
  re-runnable to the same record; independently re-verifiable.
- **Now:** schema exists; **no runner produces or consumes it.** Zero attestation evidence.

### DoD-9 — Posture derivation 🟡
- **Done when:** a **frozen** canonical posture enum (e.g. OK / DEGRADED / STALE / DRIFT / BROKEN /
  UNKNOWN / QUARANTINED / RETIRED) with **explicit precedence** is derived from a real attestation;
  and a critical failure never resolves to OK merely because a heartbeat exists.
- **Now:** `ok/stale/drift/broken` mapped deterministically on **synthetic** vectors; enum not frozen
  in a spec file; precedence rules not codified; not driven by a real attestation.

### DoD-10 — State materialization is replay-deterministic 🟡
- **Done when:** replaying the same accepted event sequence yields a byte-identical materialized
  state (`state_hash` stable), proven by a committed replay transcript.
- **Now:** a materializer runs, but the current `watchtower_state.json` is a **leftover synthetic
  `device-fail`/broken** record; no replay-determinism transcript on disk.

### DoD-11 — Real storage transition observed 🔴
- **Done when:** a controlled real transition (USB insert/remove or mount/unmount) is observed,
  signed, verified, and reflected in materialized state, with a transcript.
- **Now:** not present.

### DoD-12 — Alert/state transition on a negative condition 🟡
- **Done when:** a known negative condition on **real** evidence produces the expected deterministic
  alert (with evidence reference) and state transition; empty state shows clean.
- **Now:** alert derivation works on synthetic state cases (`ALERT_COUNT`, `watchtower_alerts.ndjson`,
  `watchtower.alert.v1` schema); no real-evidence alert with an evidence ref.

### DoD-13 — Append-only ledger with tamper detection 🟡
- **Done when:** accepted events + state transitions are appended to a hash-linked ledger; tamper is
  detected; proven on the **real** event stream.
- **Now:** device-chain selftest proves bootstrap→append→verify→**tamper-detected** on **synthetic**
  events; `ledger_event_v1` schema (tenant flavour) unused; not run on real events.

### DoD-14 — Evidence export via packet discipline 🔴
- **Done when:** a single command/action exports a session (identity, enumerations, observations,
  attestation, receipts, hashes, transcript) as a PCv1-disciplined packet that then **verifies**.
- **Now:** no export/session script found in `scripts/`.

### DoD-15 — One canonical standalone runner, correctly scoped 🔴 / ⚠️
- **Done when:** a single runner exercises DoD-1…14 **on live host data** end-to-end and emits a
  **scoped, unambiguous** success token (e.g. `WATCHTOWER_DEVICE_STATE_TIER0_FULL_GREEN_OK`), with a
  freeze transcript that shows **live enumeration**, not `PAYLOAD_REPLACE`/`RESIGN` on canned vectors.
- **Now:** the existing `WATCHTOWER_LIVE_STATE_FULL_GREEN_OK` runner is **misscoped** — it certifies
  transport + synthetic state. It must not be the Tier-0 gate.

---

## 2. Definition of Done — supporting substrate (already largely met)

These are **done as infrastructure** and are accepted as such, with the caveat that they are
*supporting*, not the Tier-0 domain gate.

| Item | Done criteria | Status | Evidence |
| --- | --- | --- | --- |
| PCv1 verify/sign roundtrip | valid packet verifies; sign+verify roundtrip green | ✅ | `full_green.stdout.txt` (sign+verify, real ed25519) |
| Terminal-state ingest | valid→receipt, invalid→quarantine, non-mutating, `-PacketRoot` pin | ✅ | ingest script + terminal-state law + `packets/*` dirs |
| Receipts/proof bundle | append-only receipts; freeze manifest with transcript hashes | ✅ | `proofs/receipts/*`, `freeze_manifest.json` |
| Telemetry schemas present | heartbeat/health/policy_attest/alert schemas valid | ✅ | `schemas/watchtower.*.v1.json` |
| Public-repo key hygiene | private key purged from history; `.gitignore` guards keys | 🟡 | `.gitignore` correct; **but** compromised/passphrase keys still on local disk (H2). Never re-trust a purged key. |
| UI clean rebuild | compact bundle; typecheck green | 🟡 | `dist/assets/index-*.js`≈152 KB; `tsc -b` exit 0. Dead dup files remain (H3); live render not screenshot-verified. |
| Local bridge | localhost-only; real routes; deterministic envelopes | 🟡 | bridge `127.0.0.1:43187`, real CIM; **CORS `*`** + no route allow-list (H7). |

---

## 3. Definition of Done — integration lanes (INT)

Each integration lane is done only when a **live, verified round-trip** exists — a contract markdown
file is **not** done.

- **TRIAD ingest (WBS 21):** verify signatures, trusted signer, `sha256sums.txt`, required roots
  (`artifact_id, block_root, semantic_root, transcript_root, policy_hash, identity_hash`), verifier
  threshold — on a real TRIAD packet, with receipt. *Now: contract-only.*
- **NFL duplication (WBS 22):** accepted WatchTower receipt duplicated to NFL and witnessed, proven by
  a round-trip transcript. *Now: partial — frozen handoff vector + consume script exist; live
  round-trip unverified.*
- **Legacy Doctor / Atlas / Archive-Recall / Covenant Gate (WBS 23–25):** each done only on a verified
  exchange. *Now: contract-only or absent.*

---

## 4. Definition of Done — Tier-0 **freeze / seal**

A legitimate seal requires **all** of:

1. DoD-1 … DoD-15 ✅ in one live standalone run.
2. Freeze bundle `proofs/freeze/watchtower_tier0_device_state_<timestamp>/` containing:
   `full_green_transcript.txt` (showing **live** enumeration), `sha256sums.txt`, `freeze_receipt.json`,
   expected outputs, and version/commit info.
3. Verify freeze contents → verify hashes → **clean git state** → commit → tag (a **new** tag that does
   not reuse `watchtower-tier0-green`) → push → **re-run from the tagged state** and reproduce the
   scoped token.
4. Only then may any document assert "**WatchTower Tier-0 (device-state) SEALED.**"

**The existing `watchtower-tier0-green` tag and April freeze do not satisfy this** and must be treated
as a *transport-substrate* seal, explicitly re-labelled, not as the Tier-0 device-plane seal.

---

## 5. Definition of Done — SaaS / hosted (out of Tier-0 scope)

Not started; gated behind a legitimate Tier-0 seal and a stable evidence contract. Done criteria per
lane: hosted ingest authenticates + rate-limits + verifies with the **same** verification laws as
standalone (no second, weaker verifier); multi-tenant isolation is **structural** and proven by a test
that one tenant cannot read another's devices/evidence; RBAC is enforced (not merely `docs/rbac.md`);
dashboard is a **projection** that cannot mutate history. *Now: ⬜ NOT BUILT across the board.*

---

## 5a. Addendum A — Live run on host `anakin`, 2026-08-26T18:59Z

The runners were executed live (evidence: `proofs/audit_liverun/20260826T185904Z/`). Effect on this DoD:

- **Supporting substrate (DoD §2) is confirmed green *today*,** not merely in an April transcript:
  `tier0_full_green`, `live_state_full_green`, `packet_verify`, `state`, `device_chain`,
  `device_binding`, `packet_constitution`, and `ingest_move` all exit 0 with their success tokens.
- **Non-mutation (DoD-6 spirit) held empirically:** the only working-tree change across the whole run
  was the derived `proofs/state/watchtower_state.json`; **no evidence vector was altered.** The
  earlier "re-signs evidence" concern is corrected to a **scope** concern (the full-green runner
  verifies its own re-signed output, on synthetic vectors) — it is not a mutation violation. This does
  **not** satisfy DoD-6, which still requires independent verification of a *live* signed observation.
- **New hard gate — DoD-16 (CLI integrity):** `_selftest_watchtower_cli_v1` **failed, exit 1**:
  `WATCHTOWER_CLI_FAIL: UNKNOWN_COMMAND: device`. The shipped `watchtower-cli-v1.0.1` does not
  implement the `device` command its own selftest invokes (it has `engine observe-device` instead).

### DoD-16 — CLI passes its own selftest 🔴 (new)
- **Done when:** `_selftest_watchtower_cli_v1.ps1` exits 0 — either by implementing a top-level
  `device` command (e.g. `device list`) or by repointing the selftest to the real command surface —
  and the release bundle is rebuilt so `watchtower-cli-vX` ships a CLI that passes its own selftest.
- **Now:** fails. A tagged CLI release that fails its own selftest must not be treated as done.

**Net:** the live run *confirms* the thesis — everything green is the synthetic substrate, and the one
step meant to reach a real device (`device list`) is the one that fails. Tier-0 remains IN PROGRESS.

---

## 6. Standing quality gates (apply to every change)

- `npm run build` (UI) passes; bundle stays compact; **no** false-green token after a failed step.
- No new dead/duplicate source files; no committed keys (public or private); receipts emitted for
  meaningful operations.
- Every new capability ships with its **negative** vector(s) proving fail-closed.
- Determinism law: *identical accepted evidence + identical policy + identical evaluator version →
  identical materialized conclusion.* (Live observation timestamps are exempt by design.)
- `UNKNOWN` remains a valid state; absence of evidence never renders as healthy.

---

## 7. Bottom line

WatchTower has a **proven deterministic transport/verification substrate** and a **real live
device/storage observer** — but the two are not yet joined, and the shipped Tier-0 "green"/freeze
certifies the substrate, not the attested device plane the project defines as its purpose. **Tier-0
is IN PROGRESS.** The seal is not yet earned. The shortest honest path to it is DoD-5 → DoD-6 →
DoD-8 (sign → verify → attest **live** observations), then DoD-7's full negative set, then a correctly
scoped runner and a re-labelled freeze.
