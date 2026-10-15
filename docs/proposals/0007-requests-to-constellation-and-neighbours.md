# Proposal 0007 — What WatchTower needs from Constellation and its neighbours

| | |
|---|---|
| Status | Proposed. Each item belongs to the owner of the named repository; nothing here was changed outside WatchTower |
| Date | 2026-10-15 |
| Supersedes | the open rows of proposal 0003 (registry entries), which this restates against registry 2.16.0 |

## 1. Constellation registry (`registry/services.json`, `registry/integrations.json`)

### Receipt state (proposal 0013 rule: positive and negative tests exist)

| Integration | Today | Request |
|---|---|---|
| `watchtower > arbiter` | planned, receipt `specified` | strength `strong`, confidence `high`, receipt `emitting` (tests: `Integration` suite, real engine in `Interop`) |
| `watchtower > neverlost` | receipt `specified` | receipt `emitting` |
| `watchtower > nfl` | receipt `specified` | receipt `emitting`, and mark the contract `legacy` (see below) |

`witnessed` waits for NFL (section 3).

### Edges to correct

| Row | Problem | Request |
|---|---|---|
| `neverlost > watchtower` (`watchtower.heartbeat.v1`, reverse-declared) | No such exchange: NeverLost reads nothing from WatchTower (NeverLost proposal 0003 asks the same). Since 0013 it also creates a receipt duty nobody can meet | Drop it |
| `watchtower > clarity` (`clarity.validator_scan.v1`) | Found because `scripts/validator_scan_targeted.ps1` writes a Clarity-shaped report. That script scans System32 for zero-length binaries: it is Clarity's tool living in the wrong repository, not a WatchTower exchange | Drop the edge; Clarity may adopt the script |
| `watchtower > nfl` (`nfl.tier0.selftest.v1`) | Only the legacy v1 handoff consumer reads it; NFL no longer produces handoff bundles | Keep while the script exists (it now emits receipts), marked legacy |
| `nfl > watchtower` (`watchtower.handoff.manifest.v1`) | The live exchange is NFL polling `packets/outbox` | Contracts `watchtower.receipt_packet.v1`, `watchtower.receipt_artifact.v1`, `watchtower.integration_witness.v1`; NFL emits these receipts as the consumer |
| `live-state-surgeon > watchtower` | Contract list | Add `watchtower.health_report.v1`, `watchtower.policy_attest.v1` (device documents LSS reads) |
| `global-workbench > watchtower` | Contract list | Add `watchtower.evidence_index.v1` |
| `claim-protocol > watchtower`, `soteriavault > watchtower` | Contracts WatchTower does not define (`watchtower.verify.receipt.v1`, `watchtower.contract.v1`) | `confidence: unverified` until their owners define them; no receipts are owed meanwhile |
| proposal 0003's `watchtower > cpr` | Conformance is not an exchange (CPR is never called at runtime) | Withdrawn: it would create an impossible receipt duty |

### WatchTower's service entry

| Field | Request |
|---|---|
| `upstream_services` | `neverlost`, `arbiter` (optional, planned → active) |
| `downstream_users` | add `nfl`, `constellation`, `global-workbench` |
| `contract_families` | add `checkpoint`, `pledge`, `integration-receipt`, `policy-gate` |
| `owns` | add "Integration receipts for exchanges where WatchTower is the consumer" |

Then republish the service map and record a service-map receipt.

## 2. Arbiter

- Nothing blocking. WatchTower calls `scripts/evaluate_arbiter_v1.ps1` with its documented
  arguments and exit contract and re-verifies decisions itself.
- Useful: publish `decision.schema.json` and `input.schema.json` under a real `$id` (Arbiter
  proposal 0001 §4 item 4) so WatchTower can pin them, and run `arbiter.cmd selftest` once on
  Windows PowerShell 5.1 (WatchTower runs Arbiter under the same edition it runs on).

## 3. NFL (Never Forgetting Ledger)

1. `config/inbox_registry.json` still names `C:/dev/watchtower/packets/outbox`. Point it at the
   S: dev-root path of this project's `packets/outbox`.
2. `nfl_ingest_inboxes_v1.ps1` and `nfl_witness_cpr_verify_v1.ps1` hard-code `powershell.exe` and
   `C:\dev\cpr`; they cannot run on Linux or from another dev root.
3. Witnessing: `nfl_witness_cpr_verify_v1.ps1` records the CPR verdict but commits no hash. For
   0013's `witnessed` state NFL must commit each outbox packet's `packet_id` (which binds every
   integration receipt line it carries) and expose a lookup WatchTower can cite.

## 4. NeverLost

- Merge the fail-closed verifier (`audit/constellation-readiness-2026-10-15`); WatchTower's bundle
  passes it (Interop). Decide NeverLost proposal 0004 item A (CRLF key files): WatchTower writes
  LF key files and hashes their exact bytes, so either choice works here.
- Issue producer bundles for live-state-surgeon nodes (`single-tenant/device_agent/device/<id>`)
  so `enroll -FromBundle` replaces the DEV `lss-dev` key.

## 5. live-state-surgeon

- Move production nodes from `lss-dev` (DEV ONLY key) to NeverLost-issued `device_agent`
  principals.
- Emit `constellation.integration.receipt.v1` for `live-state-surgeon > watchtower` (LSS is the
  consumer of WatchTower's receipts).

## 6. Covenant Gate

- Publish `covenantgate.effective_policy.v1`. WatchTower's policy-attestation rule recomputes the
  policy hash over the four fields LSS sends; the schema itself is still unowned.
