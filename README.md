# WatchTower

Deterministic verifier and telemetry receipt authority for the Constellation ecosystem.

WatchTower takes signed telemetry packets (heartbeats, health reports, policy attestations,
alerts) from producers such as live-state-surgeon, verifies them against pinned trust, and records
the outcome as evidence anyone can re-verify: a hash-chained receipt per packet, signed
latest-per-device documents, a health facet for Constellation, alert evidence, and signed
checkpoints that NFL witnesses after CPR verification. Every exchange with an upstream service
(Arbiter, NeverLost, NFL) leaves a `constellation.integration.receipt.v1`, handed to NFL too.
An optional policy gate lets Arbiter decide allow / deny / quarantine for verified telemetry.

It does not capture live state, issue identities or decide policy
(`docs/canonical/IDENTITY.md`).

## Requirements

- Windows PowerShell 5.1 or PowerShell 7 (Windows, Linux, macOS)
- OpenSSH `ssh-keygen` 8.1 or newer (`ssh-keygen -Y sign`)

Optional: an Arbiter checkout (sibling folder `arbiter` or `WATCHTOWER_ARBITER_ROOT`), only when the
policy gate is turned on in settings. No other dependencies, no network access. Everything WatchTower writes stays inside the project
folder: state under the state root, scratch under `.scratch/` (or `WATCHTOWER_TMP`); nothing goes
to `%TEMP%`, AppData or global configuration.

## Quick start

```powershell
# Create this node's authority key and NeverLost trust bundle (the repository root is the default state root)
pwsh -File bin/watchtower.ps1 init

# Enroll a producer's public key
pwsh -File bin/watchtower.ps1 enroll -Principal single-tenant/device_agent/device/node-07 -KeyId node-07-ed25519 -PublicKey ./node-07.pub
# ...or from a bundle NeverLost issued (records a watchtower > neverlost integration receipt)
pwsh -File bin/watchtower.ps1 enroll -FromBundle ../neverlost/proofs/trust/trust_bundle.json -Principal single-tenant/device_agent/device/node-07

# Producers drop packets into packets/inbox/, then:
pwsh -File bin/watchtower.ps1 ingest
pwsh -File bin/watchtower.ps1 ledger          # re-verify every ledger from bytes
pwsh -File bin/watchtower.ps1 doctor -Publish # self-check, signed health for Constellation
pwsh -File bin/watchtower.ps1 integrations    # re-verify integration receipts (-Witness: hand new ones to NFL)
```

Policy gate (optional): add `"arbiter":{"policyset":"config/arbiter/watchtower_ingest.policyset.json","policy_root":"config/arbiter"}`
to `config/watchtower.settings.json`; `config/arbiter/` holds an example policy
(`docs/contracts/arbiter.md`).

On Windows PowerShell 5.1 use
`powershell.exe -NoProfile -ExecutionPolicy Bypass -File bin\watchtower.ps1 <command>`.
Every command ends with `WATCHTOWER_<COMMAND>_OK` (exit 0) or `WATCHTOWER_<COMMAND>_FAIL:<CODE>`
(exit 1); `-Json` prints the result as canonical JSON. Optional settings:
`config/watchtower.settings.example.json`.

## Tests

```powershell
pwsh -File scripts/_RUN_watchtower_canonical_full_green_v2.ps1 -Scope all -ReportPath ./test-report.json
```

`WATCHTOWER_TIER0_FULL_GREEN_OK suites=7 cases=<n>` means all seven offline suites passed and the
repository was not modified. Interop runs against sibling checkouts of CPR, NeverLost, Arbiter and
live-state-surgeon when present (`WATCHTOWER_CPR_ROOT`, `WATCHTOWER_NEVERLOST_ROOT`,
`WATCHTOWER_ARBITER_ROOT`, `WATCHTOWER_LSS_ROOT`) and reports `PARTIAL` when one is missing. On the
Windows host, `RUN_TIER0_GATE.cmd` runs everything under Windows PowerShell 5.1 and PowerShell 7.

## Working remotely

Run in a Linux cloud session on 2026-10-15 (no Windows, no home computer):

```bash
# PowerShell 7 and OpenSSH 8.1+ (apt: openssh-client; pwsh from the PowerShell GitHub release tarball)
git clone https://github.com/Alpallyoop/WatchTower && cd WatchTower && git checkout finish/canonical-verifier-20261013
pwsh -File scripts/_RUN_watchtower_canonical_full_green_v2.ps1 -Scope standalone   # Tier-0, needs nothing else
# interop: clone CPR, NeverLost, Arbiter, live-state-surgeon anywhere and point at them
WATCHTOWER_CPR_ROOT=../cpr WATCHTOWER_NEVERLOST_ROOT=../neverlost WATCHTOWER_ARBITER_ROOT=../arbiter \
WATCHTOWER_LSS_ROOT=../live-state-surgeon pwsh -File scripts/_RUN_watchtower_canonical_full_green_v2.ps1 -Scope all
```

Only on Windows / the home computer: Windows PowerShell 5.1 and the `icacls` key protection
(`RUN_TIER0_GATE.cmd`, or CI), NFL's ingest (hard-codes `powershell.exe` and `C:\dev`), the v1 CLI
installer and UI under `ui/`, and the machine-local data under `local/`.

## Documentation

| | |
|---|---|
| `docs/canonical/IDENTITY.md` | what WatchTower is, its signing identity and namespaces |
| `docs/canonical/SPEC.md` | normative behaviour: layout, verification stages, ingest, evidence, ledgers, CLI |
| `docs/canonical/CURRENT_STATE.md` | what is proven, what is not, and the legacy v1 surface |
| `docs/contracts/` | wire contracts with live-state-surgeon, NFL/CPR, NeverLost, Arbiter, Constellation (integration receipts, health facet), Global Workbench |
| `docs/proposals/` | changes and requests that need an owner's decision (0007: what WatchTower needs from Constellation and its neighbours) |
| `docs/WATCHTOWER_WBS_OFFICIAL_v2.md`, `docs/WATCHTOWER_DOD_OFFICIAL_v2.md` | work breakdown and definition of done |
| `schemas/` | JSON Schemas for every artifact WatchTower emits or accepts |

## Repository layout

```
bin/watchtower.ps1        command line
src/WatchTower/           the module (Public/ exported commands, Private/ helpers)
schemas/                  JSON Schemas (draft 2020-12)
tests/                    gate runner, suites, reference producer, fixtures
config/                   example settings and example Arbiter policy
docs/                     canonical docs, contracts, proposals, WBS/DoD, history
scripts/, release/        legacy v1 tooling, unchanged (see CURRENT_STATE.md)
```
