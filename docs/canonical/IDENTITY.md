# WatchTower — Identity

| Field | Value |
|---|---|
| Service id | `watchtower` (Constellation registry, `repository_dir` `watchtower`) |
| Canonical name | WatchTower |
| Layer | `evidence.telemetry-verification` |
| Role | Deterministic verifier and telemetry receipt authority. |
| Standalone-first | yes: verifies, records and re-verifies with nothing but PowerShell and OpenSSH |
| Module | `src/WatchTower` (`WatchTower.psd1`), version 2.1.0 |
| Hosts | Windows PowerShell 5.1 and PowerShell 7 on Windows, Linux and macOS |
| Runtime dependency | OpenSSH `ssh-keygen` (Ed25519 SSHSIG signing and verification). Optional: an Arbiter checkout, only when the policy gate is configured |

## What WatchTower is

WatchTower receives signed telemetry packets from producers such as live-state-surgeon,
verifies them against pinned trust, and records the result as evidence that other services can
check without trusting WatchTower's word for it:

- one hash-chained receipt per packet, accepted or rejected (`watchtower.telemetry.receipt.v1`);
- signed, latest-per-device heartbeat, health and policy-attestation documents;
- signed health facets that Constellation's oversight reads per service;
- hash-chained alert evidence (`watchtower.alert.v1`);
- signed checkpoint seals, a CPR-valid receipt packet for NFL, and a chained device pledge;
- one `constellation.integration.receipt.v1` per exchange with an upstream service (Arbiter,
  NeverLost, NFL), handed to NFL for witnessing (Constellation proposal 0013).

## What WatchTower is not

From the registry (`does_not_own`) and the scope decision recorded in
`docs/proposals/0001-device-capture-belongs-to-live-state-surgeon.md`:

- It does not capture or materialize live machine state. live-state-surgeon does.
- It does not hold application workflow state.
- It does not issue identities. NeverLost does; WatchTower uses a NeverLost-format trust bundle.
- It does not decide or author policy. Expected policy hashes are pinned in settings and drift is
  reported. When the optional policy gate is on, Arbiter decides allow / deny / quarantine and
  WatchTower only routes on that decision and keeps the proof (SPEC §16).
- It does not witness its own receipts. NFL does, after CPR verification.

## Signing identity

WatchTower signs as one NeverLost principal. The key never leaves the node.

| | |
|---|---|
| Principal | `single-tenant/watchtower_authority/authority/watchtower` |
| Key id | `watchtower-authority-ed25519` |
| Key file | `<root>/proofs/keys/watchtower_authority_ed25519` (+ `.pub`) |
| Authorised namespaces | `nfl/ingest-receipt`, `packet/envelope`, `watchtower`, `watchtower/device-pledge` |
| Node id | `sha256(<canonical public key> + LF)`: stable per key, recorded in every artifact |

| Namespace | WatchTower signs |
|---|---|
| `watchtower` | checkpoint seals, published evidence documents, `receipt_id` of each receipt artifact |
| `watchtower/device-pledge` | device pledges |
| `packet/envelope` | `manifest.json` of every outbox packet |
| `nfl/ingest-receipt` | reserved for NFL ingest receipts; authorised, not used yet |

The trust bundle (`proofs/trust/neverlost/trust_bundle.json`, schema `neverlost.trust_bundle.v1`)
and the `allowed_signers` file derived from it byte-for-byte are the only trust WatchTower uses.
Keys, trust bundles or `allowed_signers` files shipped inside a packet are ignored.

## Producers WatchTower accepts

A producer is accepted only after it is enrolled in the trust bundle
(`bin/watchtower.ps1 enroll`). Enrolment grants the producer namespaces below: all five by
default; `-Namespace` can narrow the set but never add anything else
(`TRUST_NAMESPACE_NOT_PRODUCER`).

| Namespace | Signs |
|---|---|
| `watchtower/packet` | the packet `manifest.json` |
| `watchtower/telemetry-heartbeat` | `watchtower.heartbeat.v1` events |
| `watchtower/telemetry-health` | `watchtower.health_report.v1` events |
| `watchtower/telemetry-policy` | `watchtower.policy_attest.v1` events |
| `watchtower/telemetry-alert` | `watchtower.alert.v1` events |

Keys whose comment marks them as test keys (`TEST_ONLY`) are refused unless `-AllowTestKey` is
given, and a producer can never be enrolled under WatchTower's own principal.

## Ecosystem position

```
live-state-surgeon ──signed telemetry packets──▶ WatchTower ──receipts, alerts, evidence──▶ live-state-surgeon
                                                    │                                      Constellation (health facet)
NeverLost ──trust bundle format, principal,─────────┤                                      Global Workbench (index, settings)
            producer bundles (enroll -FromBundle)   │
Arbiter ◀──policy.input.v1 / policy.decision.v1─────┤  (optional policy gate)
                                                    └──receipt + integration-witness packets (packets/outbox)──▶ NFL (after CPR_VERIFY_OK)
```

Constants that define this identity live in `src/WatchTower/Private/Constants.ps1`. Changing any
of them is a contract change and needs a proposal under `docs/proposals`.
