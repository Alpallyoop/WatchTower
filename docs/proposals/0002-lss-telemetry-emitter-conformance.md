# Proposal 0002 — live-state-surgeon telemetry emitter conformance

| | |
|---|---|
| Status | Done (2026-10-15). live-state-surgeon fixed its emitter (LSS commit `37e7fe2`); WatchTower accepts its packets end to end (`tests/Integration.Tests.ps1`, and live in `tests/Interop.Tests.ps1`). The old fixture was replaced |
| Date | 2026-10-13 |
| Contract | `docs/contracts/live-state-surgeon.md` |
| Evidence | `tests/fixtures/interop/live-state-surgeon/pkt-hb-node-ok` and `tests/Interop.Tests.ps1`; live-state-surgeon source read at its current checkout |

live-state-surgeon's packets are right at the event layer: PCv1 structure, envelope, per-type
namespace and event signature all verify. WatchTower still rejects every packet it emits. The
defects below are on the producer side; each is backed by its source line.

## Defects

| # | Defect | Where | Effect |
|---|---|---|---|
| 1 | The manifest lists `signatures/packet.sig`, its own signature, and is rewritten after signing (`$manifest["files"] += packet.sig`, then written again) | `scripts/lss_emit_telemetry_packet_v1.ps1` ~l.199 | The signature covers a manifest that no longer exists. WatchTower: `MANIFEST_LISTS_OWN_SIGNATURE`. Every packet is rejected. |
| 2 | One-element arrays collapse to scalars: `To-Ordered` returns `@($list.ToArray())` from a function, which PowerShell unrolls | same file, `To-Ordered` | `"reason_codes":["X"]` becomes `"reason_codes":"X"`; alert events then fail `BODY_VALUE`. Reproduced: `{"capabilities":"emit"}` |
| 3 | `files[]` is not sorted: `Sort-Object path` on ordered dictionaries sorts nothing in PowerShell | same file, l.188 and l.199 | Non-deterministic manifest bytes across hosts and versions (the fixture's order is visibly unsorted) |
| 4 | JSON comes from `ConvertTo-Json`, whose escaping differs between PowerShell 5.1 and 7; keys of the manifest are in insertion order | `CanonJson` | The same event can hash differently on two hosts |
| 5 | Its own "WatchTower ingest" verifies against the `allowed_signers` shipped **inside** the packet and writes `watchtower.telemetry.receipt.v1` rows with `verifier = "watchtower-authority"`, a random `receipt_id`, no hash chain | `scripts/lss_watchtower_ingest_packet_v1.ps1` | Self-asserted trust, and receipts that claim to be WatchTower's but are not |
| 6 | The materializer reads receipts from **its own** repository (`$RepoRoot\proofs\receipts\…`) | `scripts/lss_materialize_live_state_v1.ps1` l.14 | It consumes defect 5's receipts instead of WatchTower's |
| 7 | `ConvertFrom-Json` turns `producer_time` into `DateTime` on PowerShell 7 before `Compare-IsoUtc` | same file | Ordering depends on host culture |
| 8 | A parse error | `scripts/_lib_lss_live_v1.ps1` line 283 (`Unexpected token '}'`) | Anything that dot-sources this library fails |
| 9 | Producer principal `lss-dev` is not in NeverLost form | dev trust | Cannot be managed by NeverLost (`docs/contracts/neverlost.md` §3) |

## Proposed changes (live-state-surgeon)

1. Build the manifest once with every file except `manifest.json`, `packet_id.txt`,
   `sha256sums.txt` and `signatures/packet.sig`; sign it; never touch it again; then
   `packet_id.txt`; `sha256sums.txt` last.
2. Return arrays with `return ,$array` (or build JSON from typed lists without a function
   boundary), and sort file entries by an explicit ordinal comparer.
3. Emit canonical JSON (sorted keys, no whitespace, `\u`-escapes only where JSON requires them)
   from one shared function, identical on 5.1 and 7.
4. Retire `lss_watchtower_ingest_packet_v1.ps1` as a verifier, or rename it a preflight that
   writes nothing named `watchtower.*`. Drop packets into WatchTower's inbox instead.
5. Give the materializer a `-WatchTowerRoot` and read
   `<WatchTowerRoot>/proofs/receipts/watchtower.telemetry.receipt.v1.ndjson`, re-verifying the
   chain first; read `producer_time` as a string.
6. Fix the parse error.
7. Enroll each node as `single-tenant/device_agent/device/<device_id>`.

## Acceptance

`tests/support/ReferenceProducer.ps1` is a conformant reference emitter. A live-state-surgeon
packet conforms when WatchTower accepts it (`bin/watchtower.ps1 verify-telemetry <packet>` →
`WATCHTOWER_VERIFY_TELEMETRY_OK`) and replacing the fixture with a newly emitted packet turns the
interop case "lss: … rejected because its manifest lists its own signature" into an accept.
