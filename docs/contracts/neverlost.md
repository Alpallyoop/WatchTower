# Contract: NeverLost → WatchTower (trust)

| | |
|---|---|
| Direction | NeverLost defines identity format and trust bundles; WatchTower consumes them (registry: `neverlost.trust_bundle.v1`, `neverlost.receipt.v1`) |
| NeverLost reference | `docs/SPEC_NeverLost_v1.md` (identity layer, locked), `scripts/_lib_neverlost_v1.ps1` |
| Status | Implemented: NeverLost v1 bundle rules (key files, unique key ids); byte-identical `allowed_signers` and acceptance by NeverLost's fail-closed verifier proven in `tests/Interop.Tests.ps1`; enrolment from NeverLost-issued bundles carrying `neverlost.receipt.v1` (`enroll -FromBundle`). |

## 1. WatchTower's principal

NeverLost v1 principals are `<tenant>/<role>/<subject>`. WatchTower is
`single-tenant/watchtower_authority/authority/watchtower` with key id
`watchtower-authority-ed25519` and exactly four namespaces:
`nfl/ingest-receipt`, `packet/envelope`, `watchtower`, `watchtower/device-pledge`.
`Get-WtAuthority` refuses to sign if the bundle's entry for this key differs in any of these.

## 2. Trust bundle format

`<root>/proofs/trust/neverlost/trust_bundle.json`, canonical JSON:

```json
{"principals":[{"keys":[{"alg":"ssh-ed25519","key_id":"watchtower-authority-ed25519",
   "namespaces":["nfl/ingest-receipt","packet/envelope","watchtower","watchtower/device-pledge"],
   "pubkey":"ssh-ed25519 AAAA…","pubkey_path":"proofs/keys/watchtower_authority_ed25519.pub","pubkey_sha256":"…"}],
  "principal":"single-tenant/watchtower_authority/authority/watchtower"}],
 "schema":"neverlost.trust_bundle.v1"}
```

| Rule | Code on violation |
|---|---|
| `schema` is `neverlost.trust_bundle.v1` | `TRUST_BUNDLE_SCHEMA` |
| `pubkey` is `<type> <base64>` without a comment | `TRUST_PUBKEY_NOT_CANONICAL` |
| `pubkey_sha256`, when present, is 64 lowercase hex | `TRUST_PUBKEY_SHA256_FORMAT` |
| `pubkey_path` (written by WatchTower 2.1 for every key) is root-relative and comes with `pubkey_sha256`; the file exists, hashes to `pubkey_sha256` and holds exactly `pubkey` (re-verified every time the bundle is read) | `TRUST_PUBKEY_PATH`, `TRUST_PUBKEY_SHA256_MISSING`, `TRUST_PUBKEY_FILE_MISSING`, `TRUST_PUBKEY_SHA256_MISMATCH`, `TRUST_PUBKEY_FILE_MISMATCH` |
| key ids are unique across the whole bundle (NeverLost `KEY_ID_DUPLICATE`) | `TRUST_DUPLICATE_KEY_ID` |
| alg `ssh-ed25519`; namespaces non-empty, unique, well-formed | `TRUST_KEY_ALG`, `TRUST_KEY_NO_NAMESPACES`, `TRUST_DUPLICATE_NAMESPACE` |
| principals and public keys are unique in the bundle (compared case-insensitively, which only rejects more) | `TRUST_DUPLICATE_PRINCIPAL`, `TRUST_PUBKEY_REUSED` |

`allowed_signers` is derived, never edited: one line per key,
`<principal> namespaces="<sorted, comma-separated>" <pubkey>`, sorted by principal then key,
LF line endings. `bin/watchtower.ps1 trust` and the doctor check that the file on disk is exactly
the derivation (`ALLOWED_SIGNERS_NOT_DERIVED` otherwise).

## 3. Producer principals

WatchTower accepts any well-formed principal for a producer, but deployments SHOULD use the
NeverLost form so one bundle can be managed by NeverLost: a live-state-surgeon node is
`single-tenant/device_agent/device/<device_id>` (tested in `tests/Ingest.Tests.ps1`). Producers
hold only producer namespaces (`IDENTITY.md`).

## 4. Bundles are per product

NeverLost's spec keeps trust bundles separate per product ("no silent merging"). WatchTower's
bundle lives in its own state root and is created by `bin/watchtower.ps1 init`; NeverLost may
generate or audit it, but WatchTower never reads another product's bundle.

Producer key files live at `proofs/trust/neverlost/keys/<key id>.pub`, so the bundle and its key
files can be handed to NeverLost as one root.

## 5. Enrolling from a NeverLost-issued bundle

```
pwsh -File bin/watchtower.ps1 enroll -FromBundle <neverlost>/proofs/trust/trust_bundle.json   -Principal single-tenant/device_agent/device/<id> [-KeyId <id>] [-NeverLostReceipt <line.json>]
```

The source bundle must pass NeverLost v1 rules (every key with `pubkey_path` + `pubkey_sha256`,
re-verified against `-BundleRoot`, default the NeverLost root); only `device_agent` principals can
be producers; namespaces must be producer namespaces (or narrowed with `-Namespace`). A
`-NeverLostReceipt` line whose `trust_bundle_sha256` names another bundle is refused. Every call
writes a `watchtower > neverlost` integration receipt (`integration-receipts.md`), carrying the
receipt line's hash.

## 6. Not yet integrated

- Key rotation: `init` never rotates silently (`TRUST_AUTHORITY_KEY_MISMATCH`). A rotation
  procedure through NeverLost is not specified yet.
- Signed bundles: NeverLost proposal 0004 item B (a NeverLost root key signing bundles). When it
  exists, `enroll -FromBundle` should verify that signature too.
