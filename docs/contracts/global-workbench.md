# Contract: WatchTower → Global Workbench (plugin)

| | |
|---|---|
| Direction | Global Workbench's WatchTower plugin reads WatchTower state; WatchTower provides its settings schema |
| Plugin manifest | `global-workbench/workbench-plugins/watchtower/plugin.manifest.json` (version 0.1.0): panels `alertPanel`, `devicePanel`, `receiptPanel`; capability `workbench.receipts.read`; `settings_schema` `watchtower.settings.v1` |
| Registry | `integrations.json`: consumer `global-workbench`, contract `watchtower.settings.v1` |
| Status | WatchTower provides the schema and a read-only discovery document. The plugin's panels are declared, not implemented against these files yet. |

## 1. Settings

`schemas/watchtower.settings.v1.json` is the plugin's `settings_schema`. The settings file is
`<root>/config/watchtower.settings.json`; unknown keys are rejected, so a settings editor must
offer exactly the schema's properties. `config/watchtower.settings.example.json` is a valid
example.

## 2. Discovery: `runtime/evidence_index.json`

`schemas/watchtower.evidence_index.v1.json`, rewritten by every ingest and by
`bin/watchtower.ps1 index`. One read gives each panel what it needs:

| Panel | Index fields |
|---|---|
| Alert panel | `ledgers.alerts`: `path`, verified `count`, `head`, `state` (`verified`, or `invalid` with `code`) |
| Device panel | `devices[]`: `device_id`, `folder` and `documents` (latest heartbeat / health / policy) |
| Receipt panel | `ledgers.telemetry_receipts`, `ledgers.checkpoints`, `ledgers.pledges`, `outbox` (`path`, `packet_count`), `last_ingest` |
| Service health | `services[]`: `service_id`, `latest_health_report`, `report_count` |

A broken chain appears as `state: invalid` with its failure code; it is never shown as healthy.

## 3. Commands a workbench can run

All read-only except `ingest`, `index`, `enroll`, `init`, `doctor -Publish`. With `-Json` each
prints canonical JSON followed by the result token (SPEC §13).

| Plugin command | WatchTower command |
|---|---|
| `watchtower.openAlertStream` | read `proofs/alerts/watchtower.alert.v1.ndjson` after `ledger` |
| `watchtower.openDeviceState` | read `runtime/devices/<device>/*.json` (+ `.sig`) |
| health check | `doctor -Json` |
