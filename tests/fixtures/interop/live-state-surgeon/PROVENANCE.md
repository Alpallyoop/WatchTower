# Fixture provenance: live-state-surgeon telemetry packets

| | |
|---|---|
| Producer | live-state-surgeon `scripts/lss_emit_telemetry_packet_v1.ps1` at commit `37e7fe2` ("Backup of the working copy on S:", 2026-10-15), after its emitter fix (LSS `docs/proposals/2026-10-13_audit_and_repair.md` item 4; WatchTower proposal 0002) |
| Signer | dev principal `lss-dev`, key `lss-dev-ed25519` (LSS `keys/lss_dev_ed25519`, DEV ONLY); `lss-dev.pub` is its public key |
| Events | LSS's own fixtures `test_vectors/lss_live_visibility_v1/fixtures/{hb-node-ok,hr-node-ok,pa-node-drift}.json` |
| Emitted | 2026-10-15, PowerShell 7.4.6 on Linux, OpenSSH 9.6p1; copied byte-for-byte (`.gitattributes` marks `tests/fixtures/**` as `-text`) |

```
pwsh -File scripts/lss_emit_telemetry_packet_v1.ps1 -RepoRoot <lss> -EventType <type> \
  -FixturePath test_vectors/lss_live_visibility_v1/fixtures/<name>.json \
  -OutRoot <out>/pkt-<name> -CreatedUtc <producer_time> -KeyPath <copy of keys/lss_dev_ed25519>
```

| Packet | Event type | packet_id |
|---|---|---|
| `pkt-hb-node-ok` | `watchtower.heartbeat.v1` | `5a672718dcd1f89e25e99f81e8fecc2faf76561633b05267472f859f06d1288e` |
| `pkt-hr-node-ok` | `watchtower.health_report.v1` | `b6686718a9bb08f38bddd7140c8b3ae45a9eb5e0091b198ca2ee8c426f93c640` |
| `pkt-pa-node-drift` | `watchtower.policy_attest.v1` (noncompliant) | `73cd20965a8b0dea22a04d79491d88480e60887ece1315506fa0b64c2c29da12` |

Ed25519 SSHSIG signatures are deterministic, so re-running the command above with the same
inputs reproduces these bytes. `tests/Interop.Tests.ps1` proves WatchTower accepts all three end
to end (DoD v2 I1), and, when a live-state-surgeon checkout is available, emits fresh packets with
its current emitter and ingests those too.

The packet these replace (`pkt-hb-node-ok` from 2026-10-13, packet id `c21232b1…`) listed its own
signature in `manifest.files` and was rejected with `MANIFEST_LISTS_OWN_SIGNATURE`; it remains in
git history. Only public material is included here (no private keys).
