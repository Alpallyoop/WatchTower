# Contract: NeverLost → WatchTower (trust)

| | |
|---|---|
| Direction | NeverLost defines identity format and trust bundles; WatchTower consumes them (registry: `neverlost.trust_bundle.v1`, `neverlost.receipt.v1`) |
| NeverLost reference | `docs/SPEC_NeverLost_v1.md` (identity layer, locked), `scripts/_lib_neverlost_v1.ps1` |
| Status | Trust bundle and `allowed_signers` format implemented; byte-identical `allowed_signers` with NeverLost's own library proven in `tests/Interop.Tests.ps1`. `neverlost.receipt.v1` is not consumed yet. |

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
   "pubkey":"ssh-ed25519 AAAA…","pubkey_sha256":"…"}],
  "principal":"single-tenant/watchtower_authority/authority/watchtower"}],
 "schema":"neverlost.trust_bundle.v1"}
```

| Rule | Code on violation |
|---|---|
| `schema` is `neverlost.trust_bundle.v1` | `TRUST_BUNDLE_SCHEMA` |
| `pubkey` is `<type> <base64>` without a comment | `TRUST_PUBKEY_NOT_CANONICAL` |
| `pubkey_sha256`, when present, is 64 lowercase hex (NeverLost defines it as the SHA-256 of the `.pub` file; WatchTower checks the format, since that file is not part of the bundle) | `TRUST_PUBKEY_SHA256_FORMAT` |
| alg `ssh-ed25519`; namespaces non-empty, unique, well-formed | `TRUST_KEY_ALG`, `TRUST_KEY_NO_NAMESPACES`, `TRUST_DUPLICATE_NAMESPACE` |
| principals and public keys are unique in the bundle, key ids within their principal (compared case-insensitively, which only rejects more) | `TRUST_DUPLICATE_PRINCIPAL`, `TRUST_DUPLICATE_KEY_ID`, `TRUST_PUBKEY_REUSED` |

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

## 5. Not yet integrated

- `neverlost.receipt.v1`: NeverLost's own receipts are not consumed. A future version can record
  the NeverLost receipt that authorised each enrolment.
- Key rotation: `init` never rotates silently (`TRUST_AUTHORITY_KEY_MISMATCH`). A rotation
  procedure through NeverLost is not specified yet.
