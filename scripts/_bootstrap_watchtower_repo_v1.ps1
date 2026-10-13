Set-StrictMode -Version Latest
$ErrorActionPreference="Stop"
# The repository this script lives in (was hardcoded to C:\dev\watchtower).
$Root = Split-Path -Parent $PSScriptRoot

function Utf8NoBom(){ New-Object System.Text.UTF8Encoding($false) }
function WriteUtf8Lf([string]$path,[string]$text){
  $dir = Split-Path -Parent $path
  if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
  $bytes = (Utf8NoBom).GetBytes(($text -replace "`r`n","`n" -replace "`r","`n"))
  [IO.File]::WriteAllBytes($path, $bytes)
  if (-not (Test-Path -LiteralPath $path)) { throw ("WRITE_FAILED: " + $path) }
}

# --- directories ---
$dirs = @("docs","schemas","contracts","scripts") | ForEach-Object { Join-Path $Root $_ }
foreach($d in $dirs){ New-Item -ItemType Directory -Force -Path $d | Out-Null }

# --- docs ---
$p = Join-Path $Root "docs\spec-watchtower.md"
$t = @'
# Watchtower Canonical Spec v1

## Definition
Watchtower is a deterministic device custody and attestation instrument that observes, measures, and cryptographically
records every device that crosses into the system boundary. Watchtower does not manage or control devices; it
establishes verifiable truth about them.

## Hard Boundary

### Watchtower owns
- Device identity & enrollment
- Device registry (fleet inventory: metadata, not payload imaging)
- Observation snapshots (metadata sets)
- Attestation collection & verification results (platform / TRIAD / wrappers)
- Custody ledger + transcripts (append-only, hash-chained)
- Policy distribution as constraints (policy authored/decided elsewhere)

### Watchtower does NOT own
- Scheduling jobs (Atlas Artifact)
- Capture/restore/verify/attest/seal/transcript of artifacts (TRIAD)
- Repair logic (Legacy Doctor)
- Archive library behavior (Archive Recall)
- Governance decisions (Covenant Gate)

## Identity Model

### Identifiers
- device_id: Watchtower-issued stable UUID (recommended UUIDv7)
- identity_hash: sha256(canonical_json(DeviceIdentityV1))

device_id is permanent. identity_hash may change; changes are recorded as events.

### Identity Tiers
- Tier0 (dev): file key allowed; identity_class=user-asserted
- Tier1: OS keystore key required; identity_class=os-rooted
- Tier2: TPM key + quote evidence; identity_class=hardware-rooted

## Enrollment Ceremony
1) Device generates device key (tier-specific) and creates JoinRequest.
2) Device obtains pairing token (time-bounded).
3) Admin approves JoinRequest, Watchtower issues EnrollmentReceipt.
4) Watchtower assigns device_id and publishes initial policy constraints bundle reference.
5) Device becomes ENROLLED; posture computed by constraints + evidence.

Offline enrollment is supported via signed outbox/inbox packets.

## Observations
Watchtower records ObservationSets: normalized, policy-scoped metadata snapshots.
Watchtower never records secrets. Redaction is not a feature; instead, collection is policy-gated.

## Attestations
Watchtower accepts:
- Platform attestation (device → Watchtower): signed ObservationSet; optional TPM quote bundle.
- TRIAD attestation (TRIAD → Watchtower): run receipt with ArtifactId + roots + transcript_root + hashes.
- Wrapper receipts (Atlas/Legacy Doctor/Security instruments): signed run summaries with artifact hash references.

Watchtower verifies signatures + required fields; it does not re-prove TRIAD semantics.

## Ledger & Transcript
- Append-only NDJSON events.
- Each event includes prev_hash and hash.
- Daily checkpoint seals (configurable) create a SealEvent referencing transcript_head hash and checkpoint signature.

## Receipts & Artifacts
Watchtower emits Receipt Artifact v1 (manifest + sha256sums + optional transcript slice + detached signature).

## Policy Interaction (Covenant Gate)
- Gate is policy source of truth.
- Watchtower consumes signed PolicyBundle.
- Watchtower enforces constraints only: minimum attestation grades, quarantine thresholds, allowed operations.
- Overlays can only add walls; never weaken baseline.

## Posture / Zones
Posture is a computed label recorded in events:
unknown → observed → enrolled → verified → high_assurance
Failures → quarantined
Decommission → retired

Upgrade/downgrade triggers are policy-driven.
Watchtower records results; it does not invent policy.
'@
WriteUtf8Lf $p $t

$p = Join-Path $Root "docs\canonical-json.md"
$t = @'
# Canonical JSON Rules v1 (Watchtower)

All hashes and signatures rely on canonical serialization.

- UTF-8 encoding without BOM
- LF newlines when writing JSON files
- Object keys sorted lexicographically
- Arrays preserve order as authored by schema rules
- No insignificant whitespace (minified form recommended for hashing)
- Timestamps are data fields; never used as implicit ordering keys
- All hashes are sha256 over exact bytes of canonical JSON
'@
WriteUtf8Lf $p $t

$p = Join-Path $Root "docs\ledger.md"
$t = @'
# Watchtower Ledger v1

## Storage
Primary transcript format: NDJSON.
Each line is a canonical JSON object conforming to ledger_event_v1.

## Hash Chain
hash = sha256(canonical_json(event_without_hash) || "\n")
prev_hash points to the prior event hash (or GENESIS for first event).

## Checkpoint Seal
Once per day (configurable), Watchtower emits event type:
- ledger.checkpoint.seal
Payload includes:
- transcript_head_hash
- checkpoint_range (start/end event_id)
- signature by Watchtower authority key
'@
WriteUtf8Lf $p $t

$p = Join-Path $Root "docs\receipt_artifact_v1.md"
$t = @'
# Watchtower Receipt Artifact v1

A Watchtower receipt is a deterministic evidence packet consumable by other instruments.

## Layout
receipt/
  manifest.json
  sha256sums.txt
  signatures/
    receipt.ed25519.sig
  payload/
    receipt.json
    transcript_slice.ndjson   (optional)

## IDs
receipt_id = sha256(canonical_json(payload/receipt.json))

## Signing
- receipt.ed25519.sig is detached signature over receipt_id (or over receipt.json bytes; choose one and lock).
Canonical rule: sign receipt_id (hex) + "\n" as UTF-8 bytes.

## receipt.json fields
- schema_version
- tenant_id
- receipt_id
- kind (enrollment|attestation_ingest|policy_apply|triad_run_ingest|checkpoint_seal|export)
- device_id (optional depending on kind)
- refs: list of {type, sha256, media_type}
- policy_ref (if relevant)
- created_at_utc
- signer_key_id
'@
WriteUtf8Lf $p $t

$p = Join-Path $Root "docs\policy_bundle.md"
$t = @'
# Policy Bundle (Covenant Gate → Watchtower) v1

Watchtower consumes signed policy bundles and enforces constraints only.

## Fields
- policy_id
- policy_hash
- baseline_hash
- overlay_hashes[]
- constraints:
  - min_identity_tier: 0|1|2
  - min_attestation_grade: platform_signed|tpm_quote
  - quarantine_on_failed_attestation: true|false
  - allowed_operations: [triad.capture, triad.restore, triad.verify, ...]
  - ttl_seconds
- signature (Gate authority)

Overlays may only add walls; never weaken baseline.
'@
WriteUtf8Lf $p $t

$p = Join-Path $Root "docs\posture.md"
$t = @'
# Device Posture / Zones v1

Posture is a computed label recorded in ledger events.

- unknown: device seen, no trusted identity
- observed: device has identity packet but not approved
- enrolled: admin approved, device_id assigned
- verified: meets policy min attestation grade + recent heartbeat
- high_assurance: TPM-backed + secure boot evidence + policy-required cadence satisfied
- quarantined: failed checks or revoked
- retired: decommissioned; no longer valid

Upgrade/downgrade triggers are policy-driven.
Watchtower records results; it does not invent policy.
'@
WriteUtf8Lf $p $t

$p = Join-Path $Root "docs\rbac.md"
$t = @'
# Watchtower RBAC v1

Roles:
- Owner
- OrgAdmin
- DeviceAdmin
- Operator
- Auditor
- DeviceAgent (machine principal)

Must-have boundaries:
1) Enrollment / revocation is OrgAdmin+ only (Owner implicit).
2) Operator can request actions (create RunRequests) but cannot approve enroll/revoke.
3) Auditor is read-only; access to raw identifiers is policy-gated (prefer hashed facts).
4) DeviceAgent can write only:
   - its own ObservationSets
   - its own platform attestations
   It cannot read fleet or policies beyond what it is issued.
5) Policy bundles can be installed only by OrgAdmin (or by verified Gate channel).
'@
WriteUtf8Lf $p $t

# --- schemas ---
$p = Join-Path $Root "schemas\device_identity_v1.json"
$t = @'
{
  "schema": "watchtower/device_identity_v1",
  "type": "object",
  "required": ["schema_version","tenant_id","device_id","identity_class","public_key","collected_at_utc","platform","identity_facts","policy_ref"],
  "properties": {
    "schema_version": {"type":"string","enum":["1"]},
    "tenant_id": {"type":"string"},
    "device_id": {"type":"string"},
    "identity_class": {"type":"string","enum":["user-asserted","os-rooted","hardware-rooted","unknown"]},
    "public_key": {"type":"string"},
    "key_attestation": {"type":"object"},
    "collected_at_utc": {"type":"string"},
    "platform": {
      "type":"object",
      "required":["os_family","os_version"],
      "properties":{
        "os_family":{"type":"string","enum":["windows","linux","macos","android","ios","embedded","unknown"]},
        "os_version":{"type":"string"},
        "kernel_version":{"type":"string"}
      }
    },
    "identity_facts": {
      "type":"object",
      "properties":{
        "hostname":{"type":"string"},
        "tpm_present":{"type":"string","enum":["true","false","unknown"]},
        "secure_boot":{"type":"string","enum":["on","off","unknown"]},
        "tpm_ek_pub_hash":{"type":"string"},
        "machine_install_id_hash":{"type":"string"},
        "hardware_fingerprint_hash":{"type":"string"}
      }
    },
    "policy_ref": {
      "type":"object",
      "required":["policy_id","policy_hash"],
      "properties":{
        "policy_id":{"type":"string"},
        "policy_hash":{"type":"string"}
      }
    }
  }
}
'@
WriteUtf8Lf $p $t

$p = Join-Path $Root "schemas\observation_set_v1.json"
$t = @'
{
  "schema": "watchtower/observation_set_v1",
  "type": "object",
  "required": ["schema_version","tenant_id","device_id","captured_at_utc","policy_ref","observations"],
  "properties": {
    "schema_version":{"type":"string","enum":["1"]},
    "tenant_id":{"type":"string"},
    "device_id":{"type":"string"},
    "captured_at_utc":{"type":"string"},
    "policy_ref":{"type":"object","required":["policy_id","policy_hash"],"properties":{"policy_id":{"type":"string"},"policy_hash":{"type":"string"}}},
    "observations":{
      "type":"object",
      "properties":{
        "boot":{"type":"object"},
        "storage":{"type":"object"},
        "software":{"type":"object"},
        "network":{"type":"object"},
        "security":{"type":"object"},
        "update_posture":{"type":"object"}
      }
    }
  }
}
'@
WriteUtf8Lf $p $t

$p = Join-Path $Root "schemas\attestation_record_v1.json"
$t = @'
{
  "schema": "watchtower/attestation_record_v1",
  "type": "object",
  "required": ["schema_version","tenant_id","device_id","created_at_utc","attestation_type","subject_hash","claims","evidence_refs","signature"],
  "properties": {
    "schema_version":{"type":"string","enum":["1"]},
    "tenant_id":{"type":"string"},
    "device_id":{"type":"string"},
    "created_at_utc":{"type":"string"},
    "attestation_type":{"type":"string","enum":["platform","triad","wrapper"]},
    "subject_hash":{"type":"string"},
    "claims":{"type":"array","items":{"type":"object"}},
    "evidence_refs":{"type":"array","items":{"type":"object","required":["sha256","media_type"],"properties":{"sha256":{"type":"string"},"media_type":{"type":"string"},"byte_length":{"type":"integer"}}}},
    "signature":{"type":"object","required":["alg","key_id","sig"],"properties":{"alg":{"type":"string"},"key_id":{"type":"string"},"sig":{"type":"string"}}}
  }
}
'@
WriteUtf8Lf $p $t

$p = Join-Path $Root "schemas\ledger_event_v1.json"
$t = @'
{
  "schema": "watchtower/ledger_event_v1",
  "type": "object",
  "required": ["schema_version","tenant_id","event_id","device_id","type","occurred_utc","producer","payload_sha256","prev_hash","hash"],
  "properties": {
    "schema_version":{"type":"string","enum":["1"]},
    "tenant_id":{"type":"string"},
    "event_id":{"type":"string"},
    "device_id":{"type":"string"},
    "type":{"type":"string"},
    "occurred_utc":{"type":"string"},
    "producer":{"type":"string"},
    "payload_sha256":{"type":"string"},
    "prev_hash":{"type":"string"},
    "hash":{"type":"string"}
  }
}
'@
WriteUtf8Lf $p $t

# --- contracts ---
$p = Join-Path $Root "contracts\watchtower_to_triad.md"
$t = @'
# Contract: Watchtower → TRIAD (RunRequest v1)

TRIAD consumes Watchtower-signed RunRequests as inputs.

## Files
run_request.json
run_request.sig
run_request.sha256

## Required fields (run_request.json)
- schema_version: "1"
- tenant_id
- run_id (Watchtower issued)
- device_id
- device_identity_hash
- operation: capture|restore|verify|attest_only
- target: selectors (disk/volume/path)
- policy_ref: {policy_id, policy_hash}
- required_acceptance:
  - block_proof_required (bool)
  - semantic_proof_required (bool)
  - independent_agreement_required (int)
- issued_at_utc
- expires_at_utc

## Rules
- TRIAD must record the sha256 of run_request.json in its transcript.
- TRIAD must not call Watchtower for identity; it trusts the signed packet.
'@
WriteUtf8Lf $p $t

$p = Join-Path $Root "contracts\triad_to_watchtower.md"
$t = @'
# Contract: TRIAD → Watchtower (RunReceipt v1)

Watchtower ingests TRIAD receipts without re-proving semantics.

## Minimum ingest fields
- run_id
- device_id
- device_identity_hash
- artifact_id
- roots:
  - block_root
  - semantic_root
  - transcript_root
  - policy_hash
  - identity_hash
- result: pass|fail
- invariants_summary (optional)
- triad_version
- verifier_set (optional)
- signatures (TRIAD)

## Watchtower behavior
- verify signature authenticity + required fields present
- record receipt hash
- write ledger events:
  - device.triad.run.receipt
  - device.attestation.received (type=triad)
  - device.attestation.verified (pass/fail)
- emit Watchtower Receipt Artifact v1 for ingestion outcome
'@
WriteUtf8Lf $p $t

$p = Join-Path $Root "contracts\watchtower_to_atlas.md"
$t = @'
# Contract: Watchtower → Atlas Artifact (Read-Only Feed)

Atlas consumes Watchtower device registry facts and posture labels.

## Provided views
- device roster: device_id, platform, posture, last_seen, policy_ref
- entitlements: posture thresholds required for job eligibility
- signed snapshots: periodic device_state_snapshot receipts

Atlas never writes to Watchtower except via wrapper receipts (optional).
'@
WriteUtf8Lf $p $t

$p = Join-Path $Root "contracts\watchtower_to_legacy_doctor.md"
$t = @'
# Contract: Watchtower ↔ Legacy Doctor

Legacy Doctor consumes device identity + allowed operations list (constraints).

Legacy Doctor may emit wrapper receipts:
- repair run summary
- health scan summary
- evidence hashes pointing to Legacy Doctor artifacts

Watchtower records wrapper receipts as attestation_type=wrapper.
'@
WriteUtf8Lf $p $t

$p = Join-Path $Root "contracts\watchtower_to_archive_recall.md"
$t = @'
# Contract: Watchtower → Archive Recall

Archive Recall consumes device/storage metadata + provenance receipts.

Watchtower provides:
- storage inventory snapshot (metadata only)
- posture label + policy_ref
- signed custody receipts for import/restore provenance

Archive Recall remains the library system; Watchtower remains the witness.
'@
WriteUtf8Lf $p $t

# --- minimal README ---
$p = Join-Path $Root "README.md"
$t = @'
# Watchtower

Canonical witness layer for device identity, observations, attestations, custody ledger, and signed export packets.

Hard boundary: Watchtower does not schedule, capture/restore, repair, or archive. It witnesses and proves custody truth.
'@
WriteUtf8Lf $p $t

# --- parse gate sanity (markdown/json are not parsed as scripts) ---
Write-Host ("BOOTSTRAP OK: " + $Root) -ForegroundColor Green
