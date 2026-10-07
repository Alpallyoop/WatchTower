# Ecosystem Integration — WatchTower

## Canonical service identity

| Field | Value |
|---|---|
| Service ID | `watchtower` |
| Canonical name | WatchTower |
| Ecosystem layer | `evidence.telemetry-verification` |
| Standalone-first | `true` |

## Role

Deterministic verifier and telemetry receipt authority.

## This service owns

- Heartbeat verification
- Health-report verification
- Policy-attestation verification
- Verifier receipts
- Telemetry alert evidence

## This service does not own

- Final live-state materialization
- Application workflow state
- Identity issuance

## Upstream services

- `neverlost`

## Downstream consumers or operators

- `live-state-surgeon`

## Contract families

- `telemetry.*`
- `heartbeat.*`
- `health.*`
- `policy-attestation.*`
- `alert.*`
- `receipt.*`

## Integration rules

1. This repository must remain independently understandable, testable, buildable, and releasable.
2. Ecosystem integrations extend capability but do not replace standalone correctness.
3. Integrations use explicit, versioned schemas and receipts.
4. No undocumented database sharing, hidden filesystem coupling, or implicit trust is permitted.
5. Producer claims must be independently verified by the receiving boundary where verification is required.
6. Integration failure must not silently corrupt local authoritative state.
7. Missing upstream services must produce an explicit unavailable, unknown, deferred, or failed state according to the local contract.
8. This repository's current implementation must not be treated as the complete product definition.

## Authoritative ecosystem sources

- `C:\dev\Constellation\ecosystem\SERVICE_MAP.md`
- `C:\dev\Constellation\registry\services.json`
- `C:\dev\Constellation\ecosystem\AGENT_POLICY.md`
- `C:\dev\Constellation\ecosystem\SHARED_INVARIANTS.md`

## Change governance

Changes to this service's ecosystem role, ownership boundaries, upstream dependencies, or downstream responsibilities require:

1. A proposal under `docs\proposals`.
2. A documented compatibility impact.
3. Updated service-map and registry entries.
4. Updated positive and negative integration tests.
5. A new service-map receipt.
