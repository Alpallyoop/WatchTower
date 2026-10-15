# Contract: WatchTower → Constellation (health facet)

| | |
|---|---|
| Direction | WatchTower publishes; Constellation's oversight reads |
| Registry | `registry/evidence_sources.json` → `facets.health.sources[]`: system `watchtower`, artifacts `{system}/runtime/services/{repo}/health_report*.json`, schema `watchtower.health_report.v1`, `max_age_days` 1. `integrations.json`: consumer `constellation`, contracts `watchtower.health_report.v1`, `watchtower.heartbeat.v1` (owner-declared, proposal 0008) |
| Status | Implemented and tested (`tests/Ingest.Tests.ps1`, `tests/Schemas.Tests.ps1`) |

## 1. Files

```
<watchtower root>/runtime/services/<repo>/health_report_<yyyyMMddTHHmmssZ>_<packet_id[0:12]>.json
<watchtower root>/runtime/services/<repo>/health_report_<…>.json.sig
```

`<repo>` is the Constellation `repository_dir` of the service (case preserved), configured by a
`service_bindings` entry in `config/watchtower.settings.json` that names which producer stream
reports that service's health:

```json
{"service_bindings":[{"service_id":"live-state-surgeon","producer":"single-tenant/device_agent/device/node-07","producer_instance":"lss"}]}
```

`runtime/services/watchtower/` holds WatchTower's own self-check (`doctor -Publish`).

## 2. Document

`schemas/watchtower.health_report.v1.json`. Fields oversight reads:

| Field | Value |
|---|---|
| `schema` | `watchtower.health_report.v1` |
| `observed_utc` | the producer's observation time (freshness) |
| `health_ok` | `health_status = ok` |
| `degraded` | `health_status = degraded` |
| `failure_count` | 1 when `health_status = fail`, else 0 |
| `proof_status` | `verified` (from a signer-verified receipt) or `self-check` (doctor) |

Plus `service_id`, `device_id`, `health_status`, `posture_hash` and a `verification` block naming
the receipt that authorises the document.

## 3. Freshness

Oversight takes freshness from `generated_utc`, else `observed_utc`, else `emitted_utc`.
WatchTower never writes `generated_utc` or `emitted_utc`: freshness is always the time the
producer observed the service, so a WatchTower that keeps running cannot make stale health look
fresh. Only a newer observation produces a new file, so the newest file by modification time is
also the newest observation.

## 4. Signatures

Every facet has a detached SSHSIG (`.sig`, namespace `watchtower`, principal
`single-tenant/watchtower_authority/authority/watchtower`). Oversight does not verify it today;
a consumer that needs proof can verify it with WatchTower's `allowed_signers`:

```
ssh-keygen -Y verify -f proofs/trust/neverlost/allowed_signers \
  -I single-tenant/watchtower_authority/authority/watchtower -n watchtower \
  -s health_report_….json.sig < health_report_….json
```

## 5. Integration receipts

Constellation's invariant (proposal 0013) is met for the integrations where WatchTower is the
consumer: see `integration-receipts.md`. Proposal 0007 asks the registry to record their state as
`emitting`. Where Constellation consumes WatchTower (this facet), Constellation writes the receipt.

## 6. Heartbeat

The registry also lists `watchtower.heartbeat.v1`. WatchTower publishes verified heartbeats per
device (`runtime/devices/<device>/heartbeat.json`), not per service; oversight does not read them
today. Mapping heartbeats to services would need a registry change and is not implemented.
