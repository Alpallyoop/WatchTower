# Contract: live-state-surgeon ⇄ WatchTower

| | |
|---|---|
| Direction | live-state-surgeon (producer) → WatchTower (verifier) → live-state-surgeon (consumer of receipts and alerts) |
| Registry | `integrations.json`: consumer `live-state-surgeon`, provider `watchtower`, contracts `watchtower.telemetry_event.v1`, `watchtower.telemetry.receipt.v1`, `watchtower.alert.v1`, `watchtower.heartbeat.v1` |
| Status | Implemented and proven on both sides: packets from live-state-surgeon's own emitter (commit `37e7fe2`) are accepted end to end (`tests/Integration.Tests.ps1`), and re-emitted live when an LSS checkout is present (`tests/Interop.Tests.ps1`). Proposal 0002 is done |

## 1. What live-state-surgeon sends

One directory per event, dropped into `<watchtower root>/packets/inbox/`. Write it under a name
starting with `_` and rename it when complete; WatchTower skips `_`/`.` names.

```
<packet>/
  manifest.json                 packet.manifest.v1, canonical JSON + LF
  packet_id.txt                 sha256(manifest.json bytes) + LF
  sha256sums.txt                "<hex64>  <path>" for every other file, LF, written last
  payload/telemetry_event.json  watchtower.telemetry_event.v1
  payload/telemetry_event.sig   SSHSIG over the event bytes, namespace per event type
  signatures/packet.sig         SSHSIG over manifest.json bytes, namespace watchtower/packet
  (any other files)             allowed, listed in manifest.files and sha256sums; ignored
```

### manifest.json (`schemas/packet.manifest.v1.json`)

```json
{"created_time":"2026-10-13T12:00:00Z",
 "files":[{"path":"payload/telemetry_event.json","sha256":"…"},{"path":"payload/telemetry_event.sig","sha256":"…"}],
 "packet_kind":"packet.telemetry.v1",
 "payload":{"event_hash":"…","event_schema":"watchtower.telemetry_event.v1","event_type":"watchtower.heartbeat.v1"},
 "producer":"lss-node-01","producer_instance":"instance-a","schema":"packet.manifest.v1"}
```

- `files[]` lists **every** packet file except `manifest.json`, `packet_id.txt`,
  `sha256sums.txt` and `signatures/packet.sig`, each with its SHA-256, no duplicates.
- The manifest MUST NOT list `signatures/packet.sig`: that signature is computed over the
  manifest, so the manifest cannot contain its hash (`MANIFEST_LISTS_OWN_SIGNATURE`).
- The manifest MUST NOT contain `packet_id`.
- `payload.event_hash` = SHA-256 of `payload/telemetry_event.json` bytes.

### payload/telemetry_event.json (`schemas/watchtower.telemetry_event.v1.json`)

```json
{"body":{…},"event_type":"watchtower.heartbeat.v1",
 "header":{"device_id":"…","event_id":"…","key_id":"lss-node-01-ed25519","namespace":"watchtower/telemetry-heartbeat",
           "producer":"lss-node-01","producer_instance":"instance-a","producer_time":"2026-10-13T12:00:00Z","seq":1},
 "schema":"watchtower.telemetry_event.v1"}
```

| Header field | Rule |
|---|---|
| `event_id`, `device_id` | `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`; `event_id` unique per producer forever |
| `producer`, `producer_instance` | equal to the manifest's |
| `key_id` | the enrolled key of `producer` |
| `namespace` | `watchtower/telemetry-heartbeat` · `-health` · `-policy` · `-alert`, matching `event_type` |
| `producer_time` | `YYYY-MM-DDTHH:MM:SSZ`, never decreasing per stream, at most `max_future_skew_seconds` ahead |
| `seq` | integer ≥ 0, strictly increasing per (`producer`, `producer_instance`, `device_id`) |

Body rules per event type are in `docs/canonical/SPEC.md` §6 and in the schema. Arrays MUST be
JSON arrays even with one element (`"reason_codes":["X"]`, not `"reason_codes":"X"`).

### Signing

```
ssh-keygen -Y sign -f <producer key> -n watchtower/telemetry-heartbeat payload/telemetry_event.json
ssh-keygen -Y sign -f <producer key> -n watchtower/packet              manifest.json
```

Order: write the event → sign it → write the manifest (final bytes) → sign the manifest →
`packet_id.txt` → `sha256sums.txt` last. Nothing may change after it is signed.

### Trust

The producer's public key is enrolled once on the WatchTower node:

```
pwsh -File bin/watchtower.ps1 enroll -Principal lss-node-01 -KeyId lss-node-01-ed25519 -PublicKey lss-node-01.pub
```

`allowed_signers`, trust bundles or public keys inside the packet are ignored.

## 2. What WatchTower returns

Everything below is under the WatchTower state root. live-state-surgeon reads these files; it
never writes them.

### Receipts — `proofs/receipts/watchtower.telemetry.receipt.v1.ndjson`

One canonical JSON row per processed packet (`schemas/watchtower.telemetry.receipt.v1.json`),
hash-chained (`receipt_hash` over the row without `receipt_hash` + LF; `prev_receipt_hash`
`GENESIS` first). Every field is always present; unknown strings are `""`, unknown `seq` is -1.

Fields live-state-surgeon's materializer reads today, all provided:

| Field | Meaning |
|---|---|
| `verify_result` | `ok` or `reject` |
| `device_id`, `event_type`, `producer_time`, `seq` | from the verified header |
| `health_status` | health reports: `ok` / `degraded` / `fail` |
| `compliance` | policy attestations: `compliant` / `noncompliant` |
| `policy_hash_claimed` | heartbeats and policy attestations |

Also: `packet_id`, `event_hash`, `event_id`, `producer`, `producer_instance`, `key_id`,
`namespace`, `fail_reason {code, detail}`, `stage`, `signer_verified`, `posture_hash`,
`policy_check` (`match` / `mismatch` / `unpinned` / `n/a`), `policy_hash_expected`,
`disposition`, `routed_to`, `receipt_time`, `verifier`, `verifier_key_id`, `node_id`,
`receipt_id`, `receipt_hash`, `prev_receipt_hash`.

A consumer SHOULD re-verify the chain before use (`bin/watchtower.ps1 ledger`, or recompute
the hashes) and MUST treat only `verify_result = "ok"` rows as verified telemetry. Facts in a
`reject` row are evidence of what was sent, not of what is true.

### Alerts — `proofs/alerts/watchtower.alert.v1.ndjson`

Hash-chained `watchtower.alert.v1` rows (SPEC §9), each with `evidence[]` pointing at the
receipt hash.

### Latest verified documents — `runtime/devices/<device>/`

`heartbeat.json`, `health_report.json`, `policy_attest.json`, each with a detached `.sig`
(namespace `watchtower`, principal `single-tenant/watchtower_authority/authority/watchtower`).

## 3. Reading files written by PowerShell

`ConvertFrom-Json` in PowerShell 7 turns ISO-8601 strings into `DateTime` values, which then
format in the local culture. Consumers comparing `producer_time` MUST compare the raw strings
(ordinal comparison is correct for this fixed format) or parse with `-DateKind String`.

## 4. Conformance evidence

`tests/fixtures/interop/live-state-surgeon/` holds a heartbeat, a health report and a
(noncompliant) policy attestation emitted by live-state-surgeon's own emitter
(`PROVENANCE.md`). WatchTower accepts all three, publishes the device documents and the
`live-state-surgeon` health facet, and raises `POLICY_NONCOMPLIANT` for the attestation. With an
LSS checkout present, Interop re-emits them with LSS's current code and requires byte-identical
packets. `tests/support/ReferenceProducer.ps1` remains a conformant reference emitter.

Production nodes should use NeverLost-issued `single-tenant/device_agent/device/<id>` principals
(`enroll -FromBundle`); the `lss-dev` key is DEV ONLY.
