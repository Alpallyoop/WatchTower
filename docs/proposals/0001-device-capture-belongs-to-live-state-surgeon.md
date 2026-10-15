# Proposal 0001 — Device capture belongs to live-state-surgeon; WatchTower is the verifier

| | |
|---|---|
| Status | Implemented on the WatchTower side since v2.0.0 and reflected in the registry (live-state-surgeon owns capture and emits for WatchTower to verify, registry 2.16.0). `docs/spec-watchtower.md` is kept as history |
| Date | 2026-10-13 |
| Affects | `docs/spec-watchtower.md`, `README.md`, the v1 state engine scripts, local-only capture tooling, Constellation registry (no change needed) |

## Conflict being reported

Three sources describe WatchTower differently:

| Source | Says WatchTower is |
|---|---|
| Constellation registry (`services.json`, v2.12.0) and `project.contract.json` | "Deterministic verifier and telemetry receipt authority". Owns heartbeat, health and policy-attestation verification, verifier receipts and telemetry alert evidence. Does **not** own final live-state materialization. Downstream user: live-state-surgeon. |
| `docs/spec-watchtower.md` (v1) | "a deterministic device custody and attestation instrument": device identity and enrolment, fleet registry, observation snapshots, attestation collection, custody ledger, policy distribution |
| August 2026 handoff notes and WBS v1 | the device-custody product, with live disk, volume and process capture (CIM engine, local bridge, inspector UI) as its spine |

The registry is the ecosystem authority (`AGENTS.md`). live-state-surgeon's registry entry
already owns "captures and materializes live machine and service state, and emits signed …
packets for WatchTower to verify". Building capture into WatchTower would make two services own
the same responsibility and reverse the dependency direction.

The owner chose the registry's definition on 2026-10-13 ("canonical verifier").

## Proposal

1. WatchTower v2 is the verifier described in `docs/canonical/SPEC.md`. It does not capture,
   enumerate or materialize live state.
2. Live capture moves to live-state-surgeon, which emits it as signed telemetry
   (`docs/contracts/live-state-surgeon.md`). Specifically:
   - the CIM-based device / disk / volume / process enumerator and its local bridge and
     inspector UI, which exist only on the development host, not in this repository;
   - the v1 state engine (`scripts/_lib_watchtower_state_v1.ps1`,
     `watchtower_materialize_state_v1.ps1`, `_RUN_watchtower_state_engine_v1.ps1`), whose job,
     materialization, live-state-surgeon owns.
3. Device identity and enrolment (spec v1 "Identity Model", "Enrollment Ceremony") belong to
   NeverLost (identity issuance) and live-state-surgeon (device agent). WatchTower verifies
   signatures by enrolled producers; it does not issue device ids.
4. `docs/spec-watchtower.md` is marked superseded by `docs/canonical/SPEC.md` by its owner. Its
   ideas that still fit (checkpoint seals, receipt artifacts, policy-as-constraints, posture) are
   implemented in v2 within the verifier role: checkpoints, Receipt Artifact v1 packets,
   pinned policy hashes and verified posture hashes.
5. The v1 scripts stay in place, unchanged, until their owners retire them; the v2 gate does not
   run or depend on them.

## Compatibility

No consumer reads WatchTower's v1 state files through a registered contract. The registry entry
needs no change. live-state-surgeon gains the capture tooling; see proposal 0002 for the
emitter changes it needs first.

## Decision needed

- Owner: confirm, then mark `docs/spec-watchtower.md` superseded.
- live-state-surgeon owner: accept the capture tooling.
