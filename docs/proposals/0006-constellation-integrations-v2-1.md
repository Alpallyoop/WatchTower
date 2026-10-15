# Proposal 0006 — Constellation integrations in WatchTower 2.1

| | |
|---|---|
| Status | Implemented in module 2.1.0 (additive). Records the contract additions the owner's Constellation decisions require; no existing field, code, token or layout path changed meaning |
| Date | 2026-10-15 |
| Authority | Constellation registry 2.16.0: proposal 0013 (integration receipts, shared invariant), proposal 0012 (planned edge `watchtower > arbiter`, from Arbiter proposal 0002); NeverLost v1 trust-bundle verifier (NeverLost branch `audit/constellation-readiness-2026-10-15`) |
| Evidence | `tests/Integration.Tests.ps1` (standalone gate), `tests/Interop.Tests.ps1` (real Arbiter, CPR, NeverLost, live-state-surgeon) |

## 1. Integration receipts (Constellation proposal 0013)

The shared invariants now say every registered integration writes a
`constellation.integration.receipt.v1` for every exchange, failed ones included, locally first,
and NFL witnesses its hash. WatchTower is the consumer, so the emitter, in:

| Integration | Contract | Exchange |
|---|---|---|
| `watchtower > arbiter` | `policy.decision.v1` (carries it) | one policy evaluation per verified packet, when the policy gate is on |
| `watchtower > neverlost` | `neverlost.trust_bundle.v1` (carries `neverlost.receipt.v1`) | one enrolment from a NeverLost-issued bundle |
| `watchtower > nfl` | `nfl.tier0.selftest.v1` | one run of the legacy NFL handoff consumer |

Added: `proofs/integrations/<consumer>__<provider>.ndjson` (Constellation's line format: schema
key order, compact, LF, 64-zero genesis, `receipt_sha256 = sha256(line)`), a witness packet
`watchtower.integration_witness.v1` in `packets/outbox` that NFL picks up with everything else,
and the witness ledger `proofs/integrations/watchtower.integration_witness_record.v1.ndjson`.
`ledger`, `doctor`, `index` and the new `integrations` command re-verify all of it.

The line format follows Constellation's schema as HAAI implemented it the same day (HAAI proposal
0015). If Constellation's schema text says otherwise, the serializer is one function
(`ConvertTo-WtIntegrationLine`).

## 2. Policy gate (`watchtower > arbiter`)

Optional, off unless `settings.arbiter` is present. Packets that pass every WatchTower check are
evaluated by Arbiter's own evaluator (child process, never imported); WatchTower re-verifies the
decision (canonical bytes, schema, `evaluated_at`, and all three hashes recomputed) and routes:
allow → accepted; deny / quarantine → quarantined at the new stage `policy`. An evaluator that is
missing, fails, times out or returns an unverifiable decision is a deny (fail closed).

Contract additions, all optional so v2.0 consumers are unaffected:

- receipt rows: `policy_decision` (`watchtower.policy_gate.v1`), only when the gate ran; stage
  enum gains `policy`; new failure codes `POLICY_DENY`, `POLICY_QUARANTINE`,
  `POLICY_EVALUATOR_UNAVAILABLE`, `POLICY_EVALUATOR_TIMEOUT`, `POLICY_EVALUATOR_FAILED`,
  `POLICY_DECISION_INVALID`, `POLICY_SET_INVALID`, `POLICY_EVIDENCE_CONFLICT`;
- quarantine notes: `policy_decision`, `policy_decision_hash`, `obligations`;
- settings: `arbiter {policyset, policy_root, timeout_seconds}`;
- evidence: `proofs/policy/{inputs,decisions,sets}/` (content-addressed; `arbiter verify` re-proves
  every decision from them).

Role check: Arbiter decides, WatchTower routes. WatchTower still authors no policy (IDENTITY.md);
the shipped `config/arbiter/` policy is an example the operator owns.

## 3. NeverLost v1 trust bundles

NeverLost's fail-closed verifier requires `pubkey_path` + `pubkey_sha256` over the exact key file
and bundle-wide unique key ids. WatchTower now writes both (`init` adds `pubkey_path` to a 2.0
bundle without changing any key or `allowed_signers` line), keeps producer key files under
`proofs/trust/neverlost/keys/`, re-verifies every key file whenever it reads the bundle, and
rejects a key id used twice anywhere in the bundle (`TRUST_DUPLICATE_KEY_ID`).
`enroll -FromBundle` enrolls `device_agent` producers from a NeverLost-issued bundle.

## 4. Other changes

- live-state-surgeon's fixed emitter is accepted end to end; the old non-conformant fixture is
  replaced (proposal 0002 is satisfied).
- Release gate: a seventh standalone suite (`Integration`), so the token reads
  `WATCHTOWER_TIER0_FULL_GREEN_OK suites=7 cases=<n>`; Interop adds Arbiter and a live
  live-state-surgeon emitter.
- Module 2.1.0; `ProjectUri` points at the current GitHub owner (`Alpallyoop`). Schema `$id`s keep
  the `ScrappyHub` URL (a schema identity, unchanged until Constellation picks a base URL).

## 5. Compatibility

With no `settings.arbiter`, every byte WatchTower 2.0 wrote is written the same way, except
trust bundles (new `pubkey_path`) and the new integration and witness files. All schema changes
are optional properties or added enum values; no `required` list changed.
