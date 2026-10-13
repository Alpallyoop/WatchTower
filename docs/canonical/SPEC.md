# WatchTower — Specification (v2)

Status: normative for module version 2.0.0. Identity and scope: `IDENTITY.md`. What is proven
today and what is not: `CURRENT_STATE.md`. Wire contracts with each neighbour: `docs/contracts/`.
Machine-readable shapes: `schemas/` (JSON Schema draft 2020-12).

The key words MUST, MUST NOT and SHOULD are used as in RFC 2119.

## 1. Invariants

These follow Constellation's shared invariants and apply to everything below.

1. **Bytes on disk are the evidence.** Hashes are SHA-256, lowercase hex, over exact bytes. Text
   WatchTower writes is UTF-8 without BOM with LF line endings; JSON is canonical (keys sorted
   ordinally, no insignificant whitespace, integers only) followed by one LF.
2. **Fail closed.** Anything that cannot be verified is rejected with a named code. A success
   token is printed only after the output it reports is durable and has been re-read.
3. **Evidence is never mutated.** Packets are moved, never edited. Ledgers are append-only.
   Verification commands never write.
4. **Deterministic.** Identical inputs, prior state, settings and verification time produce
   byte-identical outputs on any host. The verification time is explicit (`-VerificationTime`,
   default now) and recorded in every artifact.
5. **Pinned trust only.** Signatures are checked against the node's trust bundle. Trust material
   carried inside a packet is ignored.
6. **No machine paths in evidence.** Records carry root-relative paths; failure details are
   scrubbed of the state root and packet path.

## 2. Strict JSON

Every JSON document WatchTower reads is parsed by its own strict parser
(`ConvertFrom-WtJson`), not by `ConvertFrom-Json`. It rejects: a BOM or invalid UTF-8, duplicate
keys, floating-point or out-of-range numbers, lone surrogates, control characters in strings,
trailing data and nesting deeper than 64. Strings are never coerced to dates. `-Canonical`
additionally requires the input to be byte-identical to its canonical form.

Dictionary access always goes through `PSBase`, so attacker-supplied keys named `Keys`,
`Values` or `Count` cannot change what is hashed (see the regression tests in
`tests/Core.Tests.ps1` and `tests/Packet.Tests.ps1`).

## 3. State root

All runtime state lives under one root: `-Root`, defaulting to the repository root.
The layout is fixed; only behaviour is configurable.

WatchTower writes nothing to the user profile: no `%TEMP%`, no AppData, no global
configuration. Short-lived scratch directories (signing copies, test work) are created under
`<repository>/.wt-tmp/` (git-ignored) or `WATCHTOWER_TMP` when set, and removed after use.
On Windows, every private key WatchTower creates or signs with is restricted to its owner,
SYSTEM and Administrators (`icacls`), because Windows OpenSSH refuses keys that inherit broader
rights from a project folder (`KEY_ACL_FAILED` if that cannot be done).

```
<root>/
  config/watchtower.settings.json            optional, watchtower.settings.v1
  proofs/keys/watchtower_authority_ed25519   authority key (+ .pub); never committed
  proofs/trust/neverlost/trust_bundle.json   neverlost.trust_bundle.v1
  proofs/trust/neverlost/allowed_signers     derived from the bundle, byte-for-byte
  packets/inbox/<name>/                      inbound packets (names starting . or _ are skipped)
  packets/receipts/<packet_id>/              accepted packets, moved byte-identical
  packets/quarantine/<name>[__n]/            rejected packets, + <name>.rejection.json
  packets/outbox/<packet_id>/                receipt packets for NFL (PCv1 Option A)
  proofs/receipts/watchtower.telemetry.receipt.v1.ndjson   receipt ledger (hash chain)
  proofs/receipts/watchtower.checkpoint.v1.ndjson          checkpoint ledger (hash chain)
  proofs/receipts/checkpoints/<checkpoint_hash>.sig
  proofs/alerts/watchtower.alert.v1.ndjson                 alert ledger (hash chain)
  proofs/pledges/watchtower.device_pledge.v1.ndjson        pledge ledger (hash chain)
  proofs/pledges/signatures/<pledge_hash>.sig
  runtime/devices/<device>/{heartbeat,health_report,policy_attest}.json (+ .sig)
  runtime/services/<service_id>/health_report_<observed>_<packet12>.json (+ .sig)
  runtime/last_ingest.json                   watchtower.ingest_run.v1
  runtime/evidence_index.json                watchtower.evidence_index.v1
  runtime/doctor_report.json                 watchtower.doctor_report.v1 (doctor -Publish)
  runtime/ingest.lock                        present only while an ingest runs
```

`<device>` is the device id when it matches `^[a-z0-9][a-z0-9_-]{0,63}$` and is not a reserved
Windows device name; otherwise `id-` + the first 40 hex of its SHA-256. The document inside
always carries the original id.

## 4. Settings (`watchtower.settings.v1`)

| Key | Default | Meaning |
|---|---|---|
| `max_future_skew_seconds` | 300 | Producer time may lead verification time by at most this (0–86400). |
| `publish.device_evidence` | true | Publish signed latest-per-device documents. |
| `publish.service_health` | true | Publish the Constellation health facet for bound services. |
| `publish.nfl_outbox` | true | Build the receipt packet for NFL when sealing. |
| `publish.device_pledge` | true | Append a device pledge when sealing. |
| `service_bindings[]` | `[]` | `{service_id, producer, producer_instance[, device_id]}`: whose health reports describe a Constellation service. |
| `policy_pins[]` | `[]` | `{device_id or effective_group, expected_policy_hash}`: expected effective-policy hash. A device pin wins over a group pin. |

Unknown keys at any level fail with `SETTINGS_UNKNOWN_KEY`; invalid values with `SETTINGS_VALUE`.
`service_id` is a Constellation `repository_dir` (case preserved, at most 64 characters, no
trailing dot, not a reserved device name); two ids that differ only in case are rejected because
they would share one folder on Windows and macOS. `config/watchtower.settings.example.json` is a
validated example.

## 5. Packet verification (PCv1 Option A)

`Test-WtPacket` implements CPR's checks in CPR's order with CPR's failure codes, so a packet NFL
will witness is one WatchTower accepts and vice versa:

- `manifest.json`, `sha256sums.txt` and `packet_id.txt` exist;
- `packet_id` = SHA-256 of the raw `manifest.json` bytes; the manifest MUST NOT contain `packet_id`;
- `sha256sums.txt` lines are `<hex64><space><space><path>`, cover every file except itself, and
  every hash matches.

WatchTower is stricter in five places, each closing a gap: exact `packet_id.txt` format
(64 lowercase hex + LF); `sha256sums.txt` without BOM/CR, lowercase, no duplicates; strict JSON
manifest; only regular files and directories (no hidden files, symbolic links, named pipes,
sockets or devices); no `.` segments or backslashes in listed paths. Copying a packet with
Windows Explorer can add hidden `desktop.ini` / `Thumbs.db` files; such a packet is rejected
(`PACKET_HIDDEN_FILE_FORBIDDEN`), as it must be.
PCv1 carries no signatures; signatures are checked by the telemetry layer (§6).

`New-WtPacket` builds packets in CPR order (payload, manifest, packet_id, signatures,
sha256sums last) in a sibling `_staging` directory, verifies the result, then moves it into place
atomically. Building an identical packet again is a no-op; a different packet with the same id
fails `PACKET_EXISTS_DIFFERENT`.

## 6. Telemetry verification

`Test-WtTelemetryPacket` (stateless) runs these stages in order. The first failure stops
verification; the stage and code are recorded in the receipt.

| Stage | Checks | Typical codes |
|---|---|---|
| `pcv1` | §5 | `MISSING_MANIFEST`, `SHA256_MISMATCH`, `PACKET_ID_MISMATCH` |
| `manifest` | `packet.manifest.v1`, `packet_kind` `packet.telemetry.v1`, supported `event_type`, payload descriptor, `files[]` = every packet file except `manifest.json`, `packet_id.txt`, `sha256sums.txt` and `signatures/packet.sig`, each hash matches | `MANIFEST_SCHEMA`, `EVENT_TYPE_UNSUPPORTED`, `MANIFEST_LISTS_OWN_SIGNATURE`, `MANIFEST_FILES_INCOMPLETE` |
| `event` | `event_hash` = SHA-256 of `payload/telemetry_event.json` bytes; strict JSON; `watchtower.telemetry_event.v1` envelope; header identifiers well-formed; producer and instance equal the manifest's; namespace is the event type's; `seq` ≥ 0; `producer_time` is `YYYY-MM-DDTHH:MM:SSZ` | `EVENT_HASH_MISMATCH`, `EVENT_INVALID`, `PRODUCER_MISMATCH`, `NAMESPACE_MISMATCH` |
| `signature` | `signatures/packet.sig` over the raw manifest bytes (namespace `watchtower/packet`) and `payload/telemetry_event.sig` over the raw event bytes (per-type namespace), both by `header.producer` + `header.key_id` in the pinned bundle | `SIGNER_NOT_TRUSTED`, `SIGNER_NAMESPACE_NOT_AUTHORIZED`, `PACKET_SIG_INVALID`, `EVENT_SIG_INVALID` |
| `body` | per-type rules below | `BODY_VALUE`, `POSTURE_HASH_MISMATCH`, `POLICY_HASH_MISMATCH` |

Body rules (fields not listed pass through unvalidated and are never interpreted):

| Event type | Rules |
|---|---|
| `watchtower.heartbeat.v1` | `uptime_seconds` integer ≥ 0; `policy_hash_claimed`, if present, hex64 |
| `watchtower.health_report.v1` | `health_status` ∈ {ok, degraded, fail}; `posture` object with schema `watchtower.posture.v1` and `measurements`; `posture_hash` = canonical hash of `posture` |
| `watchtower.policy_attest.v1` | `effective_group` text; `policy` with schema `covenantgate.effective_policy.v1` and `policy_id`, `policy_version`, `rules_hash`; `policy_hash_claimed` = canonical hash of those four fields; `compliance` ∈ {compliant, noncompliant}; `posture_hash`, if present, hex64 |
| `watchtower.alert.v1` | `alert_type` text; `state` ∈ {unknown, stale, broken, drift, degraded, ok}; `reason_codes` array of strings |

`signer_verified` is true once both signatures verified, even if a later stage fails. Only then
is anything taken from the header or body into evidence (§8).

## 7. Ingest

`Invoke-WtIngest` (CLI `ingest`) holds `runtime/ingest.lock` (exclusive create; a leftover lock
fails `INGEST_LOCKED`), opens and fully re-verifies the receipt and alert chains, and processes
inbox entries in ordinal name order. Names starting with `.` or `_` are in-progress drops and
are skipped. For each packet:

1. Stateless verification (§6).
2. Stateful rules, derived only from `ok` receipts in the ledger (there is no separate state
   file). They compare against the last accepted event of each stream, so a sender that controls
   inbox names can reorder genuine packets and get older ones rejected; it can never get a packet
   accepted that the producer did not sign. Rules: `DUPLICATE_PACKET` (same `packet_id`), `REPLAYED_EVENT` (same producer + `event_id`),
   `SEQUENCE_REPLAYED` / `SEQUENCE_REGRESSION` / `TIME_REGRESSION` per
   (producer, producer_instance, device_id) stream, `FUTURE_TIMESTAMP` beyond the allowed skew.
3. Routing is decided before anything is written: accepted → `packets/receipts/<packet_id>`
   (`ACCEPTED_DESTINATION_EXISTS` if taken); rejected → `packets/quarantine/<name>` or the first
   free `<name>__<n>`.
4. The receipt row is appended (hash chain), **then** the directory is moved, then a quarantine
   note is written for a rejection. Untrusted strings are bounded (256 characters, surrogate-safe,
   unpaired surrogates replaced by U+FFFD). If a packet's receipt still cannot be built from what
   it claims, it is rejected as `RECEIPT_UNRECORDABLE` (stage `record`) with no packet-supplied
   field except its name: no single packet can stop the run.
5. For an accepted packet: device evidence and the service health facet are published (§8).
6. Alert evidence is appended (§9).

After the loop, sealing (§10) runs from the ledgers, then `runtime/last_ingest.json` and the
evidence index are rewritten. The lock is always released.

### Crash behaviour

Renames and replaces retry for about three seconds on a sharing violation (Windows antivirus,
indexers and readers hold files briefly), then fail. Every step is idempotent or detected on the
next run:

- Receipts appended but not sealed: the next run seals the unsealed range.
- Checkpoint written but no outbox packet or pledge: the next run builds them for that
  checkpoint (same packet id) without adding a checkpoint.
- Receipt appended but the move not done: the packet is still in the inbox; the next run records
  it again as `DUPLICATE_PACKET` (accepted case) and quarantines it. `Test-WtLedger` reports
  `ROUTED_PACKET_ABSENT` for the first receipt. Nothing is lost or silently accepted twice.
- Accepted but evidence not published: the receipt ledger is the authority; documents are
  re-published by the next accepted event for that device. Consumers that need completeness read
  receipts, not documents.

## 8. Published evidence

Published documents are projections of the receipt ledger. Each is canonical JSON with a detached
signature `<file>.sig` (namespace `watchtower`) and a `verification` block naming the verifier,
key, node, receipt hash, packet id, event hash, producer and verification time.

| Document | Path | Notes |
|---|---|---|
| heartbeat | `runtime/devices/<device>/heartbeat.json` | `heartbeat_ok`, `uptime_seconds`, `agent_version` |
| health report | `runtime/devices/<device>/health_report.json` | `health_ok`, `degraded`, `failure_count`, `health_status`, `posture_hash` |
| policy attestation | `runtime/devices/<device>/policy_attest.json` | `policy_ok` = compliant and not mismatched; `policy_check` ∈ {match, mismatch, unpinned}; `drift_reason` |
| Constellation health facet | `runtime/services/<service_id>/health_report_<yyyyMMddTHHmmssZ>_<packet_id[0:12]>.json` | for bound services only; one file per newer observation |

`observed_utc` is always the producer's observation time, never publish time, so stale telemetry
can never look fresh. An older observation never replaces a newer one. A health facet never
contains `generated_utc` (Constellation's oversight would read it as freshness).

## 9. Alerts (`watchtower.alert.v1`)

| Condition | alert_type | severity | state |
|---|---|---|---|
| Rejected, signer verified, replay/order/clock code | `TELEMETRY_REJECTED` | critical | unknown |
| Rejected, signer verified, any other code | `TELEMETRY_REJECTED` | warning | unknown |
| Rejected, signer not verified | `UNVERIFIED_PACKET` | warning | unknown |
| health_status fail / degraded | `HEALTH_FAIL` / `HEALTH_DEGRADED` | critical / warning | broken / degraded |
| policy hash ≠ pinned | `POLICY_DRIFT` | critical | drift |
| compliance noncompliant | `POLICY_NONCOMPLIANT` | warning | drift |
| producer alert event | `PRODUCER_<alert_type>` | by state: broken → critical; drift, stale, degraded → warning; else info | producer's |

An alert for an unverified packet is never attributed to a device (`device_id` `unknown`) and
is dated at verification time. Producer strings are bounded (128 characters, 32 codes). Every
alert carries `evidence[]` with the receipt hash and, when known, packet id and event hash.

## 10. Sealing, NFL and pledges

When the receipt ledger has receipts not covered by the last checkpoint:

1. **Checkpoint** (`watchtower.checkpoint.v1`, event_type `ledger.checkpoint.seal`): receipt head
   and count, the sealed range, alert head and count, time and verifier. Its canonical line is
   signed (namespace `watchtower`) to `proofs/receipts/checkpoints/<checkpoint_hash>.sig`
   before the row is appended.
2. **Receipt packet** in `packets/outbox/<packet_id>` (PCv1 Option A, manifest
   `watchtower.receipt_packet.v1`, kind `telemetry_receipts`). Payload: `receipt.json`
   (Receipt Artifact v1, kind `attestation_ingest`), `transcript_slice.ndjson` (the sealed
   receipt rows, byte-identical), `checkpoint.json` and its signature. Signatures:
   `signatures/receipt.ed25519.sig` over `receipt_id` + LF (namespace `watchtower`) and
   `signatures/manifest.sig` over `manifest.json` (namespace `packet/envelope`).
   `receipt_id` = SHA-256 of the canonical receipt without `receipt_id`, + LF.
3. **Device pledge** (`watchtower.device_pledge.v1`): binds receipt head, alert head, checkpoint
   hash and outbox packet id; signed (namespace `watchtower/device-pledge`) before it is appended.

## 11. Ledgers

All four ledgers are NDJSON hash chains: each row is canonical JSON;
`hash = sha256(canonical_json(row without its hash field) + LF)`; the first row's previous hash
is `GENESIS`. Each row is appended in a single flushed write ending in LF; a partial last line, CR, empty line
or non-canonical line fails the chain.

`Test-WtLedger` (CLI `ledger`) recomputes every link, verifies every checkpoint and pledge
signature against the pinned authority key, checks that each checkpoint seals the receipt and
alert heads it names and that each pledge binds an existing checkpoint and the receipt head at
that point, and that every referenced outbox packet still verifies. Missing routed or outbox
packets are warnings, not failures.

## 12. Doctor and evidence index

`Invoke-WtDoctor` (CLI `doctor`) runs isolated checks: `ssh_keygen` (a throwaway key proves SSHSIG sign and verify work; OpenSSH 8.1+), `settings`, `trust_bundle`,
`allowed_signers_derived`, `authority_key`, `ledgers`, `ingest_lock`. `-Publish` writes
`runtime/doctor_report.json` and a signed `watchtower.health_report.v1` facet for the `watchtower`
service itself (`proof_status` `self-check`). A broken ledger is never reported healthy.

`Export-WtEvidenceIndex` (CLI `index`, also run by every ingest) writes the discovery document
operator surfaces read: ledger locations with verified count and head (`state` `invalid` + code
when a chain is broken, never an exception), the latest documents per device and service, the
outbox packet count and the last ingest record.

## 13. Command line

`bin/watchtower.ps1 <command> [-Root <dir>] [-VerificationTime <utc>] [-Json]`

| Command | Purpose |
|---|---|
| `init` | Create or validate the authority key and trust bundle (never rotates silently) |
| `enroll` | Enroll a producer: `-Principal -KeyId -PublicKey [-Namespace] [-AllowTestKey]` |
| `trust` | Show the trust bundle; confirm `allowed_signers` is exactly derived |
| `verify-packet <path>` | PCv1 verification (read-only) |
| `verify-telemetry <path>` | Telemetry verification against pinned trust (read-only) |
| `ingest` | §7 |
| `ledger` | §11 (read-only) |
| `doctor [-Publish]` | §12 |
| `index` | Rewrite the evidence index |
| `version`, `help` | |

Output is `key=value` lines and one final token: `WATCHTOWER_<COMMAND>_OK` (exit 0) or
`WATCHTOWER_<COMMAND>_FAIL:<CODE>` (exit 1). Unknown commands print
`WATCHTOWER_CLI_FAIL:UNKNOWN_COMMAND`. `-Json` prints canonical JSON before the token.

## 14. Release gate

`scripts/_RUN_watchtower_canonical_full_green_v2.ps1` (wrapper for
`tests/Invoke-WatchTowerTests.ps1`) runs each suite in its own process, hashes the repository
before and after (any change fails `REPO_MUTATED`) and, with `-ReportPath`, writes a
`watchtower.test_run.v1` report that is re-read and schema-validated before any token prints.

| Token | Meaning |
|---|---|
| `WATCHTOWER_TIER0_FULL_GREEN_OK suites=6 cases=<n>` | Core, Packet, Telemetry, Ingest, Cli and Schemas all passed; nothing skipped is counted |
| `WATCHTOWER_INTEROP_OK cases=<n>` | live-state-surgeon fixture, the real CPR verifier and the real NeverLost library all agree |
| `WATCHTOWER_INTEROP_PARTIAL cases=<n> unavailable=<k>` | a sibling checkout was unavailable; its cases are reported as skipped, never as passed |

## 15. Compatibility and change control

- New schemas are additive. The four pre-existing evidence schemas were extended with optional
  properties only; their `required` lists are unchanged.
- The legacy v1 scripts in `scripts/` and their tokens are unchanged and are not part of this
  specification (`CURRENT_STATE.md` lists them).
- Any change to identity, namespaces, schemas, receipt fields, layout or token names is a
  contract change and needs a proposal under `docs/proposals`.
