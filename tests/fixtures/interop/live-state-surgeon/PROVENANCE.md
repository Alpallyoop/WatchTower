# Fixture provenance: `pkt-hb-node-ok`

| | |
|---|---|
| Source | `live-state-surgeon/test_vectors/lss_live_visibility_v1/outbox/pkt-hb-node-ok/` |
| Producer | live-state-surgeon `lss_emit_telemetry_packet_v1.ps1`, dev principal `lss-dev`, key `lss-dev-ed25519` |
| Copied | 2026-10-13, byte-for-byte (`.gitattributes` marks `tests/fixtures/**` as `-text`) |
| Packet id | `c21232b10a641c9b19733f67c68310a261799aac85af87ef1d555779c103cd31` |

This is the only telemetry packet live-state-surgeon has actually emitted. WatchTower keeps it
to prove, against real producer output, exactly where the two sides agree and where they do not:

- **Agree** — PCv1 structure (packet_id over the raw manifest bytes, full `sha256sums.txt`
  coverage), the `watchtower.telemetry_event.v1` envelope, the per-type event namespace
  `watchtower/telemetry-heartbeat`, and a valid event signature by `lss-dev`.
- **Disagree** — `manifest.files` lists `signatures/packet.sig`, the manifest's own signature.
  That makes the manifest signature impossible to verify over the manifest on disk (the emitter
  signs a pre-append copy, then appends the entry). WatchTower rejects such packets with
  `MANIFEST_LISTS_OWN_SIGNATURE`; it does not "reconstruct" an unsigned manifest to make it pass.

The required producer-side change is recorded in `docs/proposals/0002-lss-telemetry-emitter-conformance.md`.
Only public material is included here (no private keys).
