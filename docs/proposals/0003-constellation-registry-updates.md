# Proposal 0003 — Constellation registry entries for WatchTower v2

| | |
|---|---|
| Status | Proposed to the Constellation owner |
| Date | 2026-10-13 |
| Affects | `Constellation/registry/services.json`, `integrations.json`, `evidence_sources.json` (no change), service-map receipt |

WatchTower v2 implements what the registry declares and adds outputs other services can rely on.
The registry should describe them so its integration map matches reality. Nothing here changes
WatchTower's role, ownership or dependency direction.

## services.json — `watchtower`

| Field | Today | Proposed |
|---|---|---|
| `downstream_users` | `live-state-surgeon` | add `nfl` (polls `packets/outbox`, already configured in `nfl/config/inbox_registry.json`) and `constellation` (health facet, already in `evidence_sources.json`) |
| `contract_families` | telemetry, heartbeat, health, policy-attestation, alert, receipt | add `checkpoint`, `pledge` |
| `capabilities` | `[]` | `verify.pcv1`, `verify.telemetry`, `receipt.ledger`, `evidence.publish`, `nfl.outbox` |

## integrations.json

| Consumer | Provider | Contracts | Change |
|---|---|---|---|
| `nfl` | `watchtower` | `watchtower.receipt_packet.v1`, `watchtower.receipt_artifact.v1` | new; NFL polls the outbox (today the row lists only the legacy `watchtower.handoff.manifest.v1`) |
| `live-state-surgeon` | `watchtower` | add `watchtower.policy_attest.v1`, `watchtower.health_report.v1` | the device documents it may read |
| `global-workbench` | `watchtower` | add `watchtower.evidence_index.v1` | the plugin's discovery document |
| `watchtower` | `cpr` | `packet_constitution_v1_option_a` | new; WatchTower conforms to and is tested against CPR's verifier |

The rows for `claim-protocol` (`watchtower.verify.receipt.v1`) and `soteriavault`
(`watchtower.contract.v1`) name contracts WatchTower does not emit; they should carry
`confidence: unverified` until an owner defines them (`docs/contracts/claim-protocol.md`).

## Receipt

After the change, regenerate the service map and record a service-map receipt, as
`docs/canonical/ECOSYSTEM_INTEGRATION.md` requires for ecosystem changes.
