# Contract constants. Changing any of these is a contract change and needs a
# proposal under docs/proposals (see AGENTS.md / docs/canonical/SPEC.md).

# Identity, as registered with NeverLost (docs/SPEC_NeverLost_v1.md, contract v11e).
$script:WtAuthorityPrincipal = 'single-tenant/watchtower_authority/authority/watchtower'
$script:WtAuthorityKeyId = 'watchtower-authority-ed25519'
$script:WtAuthorityNamespaces = @('nfl/ingest-receipt', 'packet/envelope', 'watchtower', 'watchtower/device-pledge')

# What WatchTower signs, under which NeverLost-authorised namespace.
$script:WtNamespaceEvidence = 'watchtower'                 # checkpoints, receipt artifacts, published evidence
$script:WtNamespacePledge = 'watchtower/device-pledge'     # device pledges (AnchorMark law)
$script:WtNamespaceEnvelope = 'packet/envelope'            # outbound PCv1 manifest signatures

# Inbound telemetry contract (live-state-surgeon -> WatchTower).
$script:WtEnvelopeSchema = 'watchtower.telemetry_event.v1'
$script:WtManifestSchema = 'packet.manifest.v1'
$script:WtPacketKindTelemetry = 'packet.telemetry.v1'
$script:WtNamespacePacket = 'watchtower/packet'
# Ordinal (case-sensitive) map: 'WATCHTOWER.HEARTBEAT.V1' is not a supported event type.
$script:WtEventNamespaces = New-Object System.Collections.Specialized.OrderedDictionary([System.StringComparer]::Ordinal)
$script:WtEventNamespaces.Add('watchtower.heartbeat.v1', 'watchtower/telemetry-heartbeat')
$script:WtEventNamespaces.Add('watchtower.health_report.v1', 'watchtower/telemetry-health')
$script:WtEventNamespaces.Add('watchtower.policy_attest.v1', 'watchtower/telemetry-policy')
$script:WtEventNamespaces.Add('watchtower.alert.v1', 'watchtower/telemetry-alert')
$script:WtProducerNamespaces = @('watchtower/packet') + @($script:WtEventNamespaces.PSBase.Values)

# Output contracts.
$script:WtReceiptSchema = 'watchtower.telemetry.receipt.v1'
$script:WtAlertSchema = 'watchtower.alert.v1'
$script:WtCheckpointSchema = 'watchtower.checkpoint.v1'
$script:WtPledgeSchema = 'watchtower.device_pledge.v1'
$script:WtReceiptPacketSchema = 'watchtower.receipt_packet.v1'
$script:WtEvidenceIndexSchema = 'watchtower.evidence_index.v1'
$script:WtIngestRunSchema = 'watchtower.ingest_run.v1'
$script:WtSettingsSchema = 'watchtower.settings.v1'
$script:WtDoctorSchema = 'watchtower.doctor_report.v1'

$script:WtIdentifierPattern = '^[A-Za-z0-9][A-Za-z0-9._:\-]{0,127}$'
# Service ids name Constellation repository folders (registry 'repository_dir', e.g.
# 'live-state-surgeon', 'Constellation', 'StaticHarbor'), so case is preserved. No
# trailing dot and no reserved device names: they are used as directory names.
$script:WtServiceIdPattern = '^[A-Za-z0-9](?:[A-Za-z0-9._\-]{0,62}[A-Za-z0-9_\-])?$'
$script:WtReservedNamePattern = '^(?i:con|prn|aux|nul|com[0-9]|lpt[0-9])$'
