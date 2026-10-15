# Contract: WatchTower → NFL (via CPR)

| | |
|---|---|
| Direction | WatchTower publishes receipt packets; NFL polls, verifies with CPR, then witnesses |
| NFL configuration | `nfl/config/inbox_registry.json`: inbox `watchtower-outbox`, path `C:/dev/watchtower/packets/outbox` (stale: must point at this project's `packets/outbox` under the S: dev root, proposal 0007 §3), mode `packet` |
| Law | AnchorMark: finalize the packet in the outbox, write a local chained signed pledge, NFL picks it up |
| Status | WatchTower side implemented; the real CPR verifier returns `CPR_VERIFY_OK` on WatchTower's receipt packets and integration-witness packets (`tests/Interop.Tests.ps1`). NFL's witness step records CPR's verdict but commits no hash and runs only on Windows from `C:\dev` (proposal 0007 §3). |

## 1. The packet

Written when an ingest run seals new receipts (SPEC §10), at
`<root>/packets/outbox/<packet_id>/`. With the default root on the Windows host that is exactly
the path NFL polls.

```
<packet_id>/
  manifest.json                    watchtower.receipt_packet.v1, canonical JSON + LF
  packet_id.txt                    sha256(manifest.json bytes) + LF
  payload/receipt.json             Receipt Artifact v1 (watchtower.receipt_artifact.v1)
  payload/transcript_slice.ndjson  the sealed receipt rows, byte-identical to the ledger
  payload/checkpoint.json          the checkpoint row (canonical JSON + LF)
  payload/checkpoint.json.sig      its signature (namespace watchtower)
  signatures/receipt.ed25519.sig   over receipt_id + LF (namespace watchtower)
  signatures/manifest.sig          over manifest.json (namespace packet/envelope)
  sha256sums.txt                   every other file, written last
```

- PCv1 Option A exactly as CPR verifies it: `packet_id` over the raw manifest bytes, no
  `packet_id` inside the manifest, full `sha256sums.txt` coverage.
- The packet appears atomically (built in `packets/_staging`, verified, then moved). NFL never
  sees a partial packet.
- Building the same packet twice is a no-op; the directory is never rewritten.
- `manifest.producer` is WatchTower's principal and `manifest.producer_instance` its node id.

## 2. What NFL can verify independently

1. `CPR_VERIFY_OK` (structure, hashes, packet id). CPR checks no signatures.
2. `signatures/manifest.sig` against WatchTower's principal and namespace `packet/envelope`
   (NeverLost trust bundle, see `neverlost.md`).
3. `receipt_id` = SHA-256 of canonical `receipt.json` without `receipt_id`, + LF; and
   `signatures/receipt.ed25519.sig` over it (namespace `watchtower`).
4. Every `refs[].sha256` in `receipt.json` against the payload files.
5. The transcript slice is a contiguous section of WatchTower's hash chain: each row's
   `prev_receipt_hash` equals the previous row's `receipt_hash`, and the last row's hash equals
   `receipt.ledger.head_hash` and the checkpoint's `transcript_head_hash`.

## 3. The pledge

For every sealed checkpoint WatchTower appends a `watchtower.device_pledge.v1` row to
`proofs/pledges/watchtower.device_pledge.v1.ndjson`, signed under `watchtower/device-pledge`,
binding the receipt head, alert head, checkpoint hash and `outbox_packet_id`. A witness that has
the pledge can prove WatchTower committed to that packet before NFL saw it.

## 4. CPR conformance

`Test-WtPacket` mirrors CPR check-for-check with CPR's codes and is stricter in five documented
places (SPEC §5). The interop suite runs CPR's own `verify_packet_v1.ps1` (from a temporary copy,
so the CPR checkout is never written) on WatchTower's outbox packet, on a tampered copy, and on
every CPR golden vector, and requires both verifiers to agree.

On Linux and macOS, CPR's relative-path helper throws for every packet (it relies on Windows
`Uri` behaviour); the interop suite substitutes an equivalent helper there and runs every packet
rule unmodified. The fix belongs in CPR: `docs/proposals/0004-cpr-relative-path-on-non-windows.md`.

## 5. Integration-witness packets

Besides receipt packets, the outbox carries `watchtower.integration_witness.v1` packets: the
`constellation.integration.receipt.v1` lines WatchTower wrote as a consumer
(`integration-receipts.md`). Same PCv1 rules, manifest signed under `packet/envelope`.

## 6. Legacy handoff (NFL → WatchTower)

The v1 script `scripts/watchtower_consume_nfl_handoff_v1.ps1` and its frozen vector
(`test_vectors/handoff_frozen/watchtower_nfl_handoff_green_20260308`) consume an NFL handoff
bundle (`watchtower.handoff.manifest.v1` / `nfl.tier0.selftest.v1` in the registry). It is the
only code path of the registered integration `watchtower > nfl`, so since 2.1 every run writes a
`watchtower > nfl` integration receipt (ok, failed or unavailable; tested in
`tests/Integration.Tests.ps1`). NFL no longer produces handoff bundles; proposal 0007 asks the
registry to mark the edge legacy.
