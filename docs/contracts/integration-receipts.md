# Contract: Constellation integration receipts (WatchTower as emitter)

| | |
|---|---|
| Authority | Constellation shared invariant, proposal 0013; schema `constellation.integration.receipt.v1` (WatchTower copy: `schemas/constellation.integration.receipt.v1.json`) |
| Witness | NFL, through `packets/outbox` |
| Status | Emitting for all three integrations where WatchTower is the consumer; witnessing waits for NFL to commit hashes (proposal 0007 §3) |

## 1. Ledgers

| File | Integration | Written by |
|---|---|---|
| `proofs/integrations/watchtower__arbiter.ndjson` | `watchtower > arbiter` | every policy evaluation during ingest |
| `proofs/integrations/watchtower__neverlost.ndjson` | `watchtower > neverlost` | `enroll -FromBundle` |
| `proofs/integrations/watchtower__nfl.ndjson` | `watchtower > nfl` | the legacy NFL handoff consumer |

One line per exchange, failed ones included, written before anything else is done with the
result. Example:

```
{"schema":"constellation.integration.receipt.v1","consumer":"watchtower","provider":"arbiter","emitted_by":"consumer","contract":"policy.decision.v1","request_sha256":"<input>","response_sha256":"<decision bytes>","carried":[{"contract":"policy.decision.v1","sha256":"<decision_hash>"}],"outcome":"ok","error_token":null,"prev_sha256":"0000…0000"}
```

Keys in the schema's order, compact, LF; `receipt_sha256 = sha256(line)`; `prev_sha256` chains.
`outcome` ∈ ok, refused, unavailable, unknown, deferred, failed; `error_token` is null exactly when
`ok`. The witness label is `constellation.integration.receipt.v1:watchtower>arbiter`.

## 2. Witness packets for NFL

`packets/outbox/<packet_id>/` with `manifest.json` = `watchtower.integration_witness.v1`:

```
manifest.json                                            ledgers[]: integration, ledger, payload, first/last index,
                                                         prev and head sha256, every receipt_sha256
packet_id.txt
payload/integration_receipts/watchtower__<provider>.ndjson   the new lines, byte-identical
signatures/manifest.sig                                  namespace packet/envelope, WatchTower's authority
sha256sums.txt
```

CPR accepts these packets (Interop). Committing the packet id commits every receipt line in it.
The witness ledger `proofs/integrations/watchtower.integration_witness_record.v1.ndjson` records
which ranges went into which packet; `ledger` re-checks ranges, heads and packet contents.

## 3. Receipts WatchTower does not write

Where WatchTower is the provider (`live-state-surgeon`, `constellation`, `global-workbench`,
`nfl`, `claim-protocol`, `soteriavault` consume WatchTower), the registry marks the receipt
"specified by consumer": those services write them.
