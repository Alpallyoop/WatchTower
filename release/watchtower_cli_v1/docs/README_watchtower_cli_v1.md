# WatchTower CLI v1

Deterministic observer and evidence surface for WatchTower.

## Included
- scripts/watchtower_cli_v1.ps1
- scripts/watchtower_engine_v1.ps1
- scripts/_selftest_watchtower_cli_v1.ps1
- scripts/_RUN_watchtower_cli_freeze_v1.ps1
- proofs/freeze/watchtower_cli_v1/stdout.txt
- proofs/freeze/watchtower_cli_v1/stderr.txt
- proofs/freeze/watchtower_cli_v1/sha256sums.txt

## Example usage
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\scripts\watchtower_cli_v1.ps1 -RepoRoot . version
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\scripts\watchtower_cli_v1.ps1 -RepoRoot . quick-check
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\scripts\watchtower_cli_v1.ps1 -RepoRoot . engine init
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\scripts\watchtower_cli_v1.ps1 -RepoRoot . engine observe-device
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\scripts\watchtower_cli_v1.ps1 -RepoRoot . engine summary
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\scripts\_selftest_watchtower_cli_v1.ps1 -RepoRoot .

## Success tokens
- WATCHTOWER_VERSION_OK
- WATCHTOWER_QUICK_CHECK_OK
- WATCHTOWER_DOCTOR_OK
- WATCHTOWER_STATUS_OK
- WATCHTOWER_RECEIPTS_SUMMARY_OK
- WATCHTOWER_ENGINE_INIT_OK
- WATCHTOWER_ENGINE_DEVICE_OBSERVE_OK
- WATCHTOWER_ENGINE_TELEMETRY_OBSERVE_OK
- WATCHTOWER_ENGINE_SUMMARY_OK
- WATCHTOWER_CLI_SELFTEST_OK
- WATCHTOWER_CLI_FREEZE_OK
