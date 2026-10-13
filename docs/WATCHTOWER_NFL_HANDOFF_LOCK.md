# WatchTower NFL Handoff Lock

Status: GREEN / LOCKED

Canonical latest green bundle:
- proofs/receipts/20260308T033524Z (local evidence, git-ignored; present in the S drive working copy)

Frozen bundle:
- test_vectors/handoff_frozen/watchtower_nfl_handoff_green_20260308

Locked boundary surface:
- scripts/watchtower_consume_nfl_handoff_v1.ps1
- scripts/_selftest_watchtower_consume_nfl_handoff_v1.ps1

Boundary claim:
- verifies NFL handoff bundle sha256sums
- consumes canonical manifest
- appends deterministic WatchTower receipt
- emits deterministic selftest receipt bundle
- emits sha256 evidence bundle
- parse-gated locked surface
