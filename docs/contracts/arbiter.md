# Contract: WatchTower → Arbiter (policy gate)

| | |
|---|---|
| Direction | WatchTower (consumer) sends `policy.input.v1`, Arbiter returns `policy.decision.v1`; WatchTower routes on it |
| Registry | `integrations.json`: consumer `watchtower`, provider `arbiter`, contracts `policy.policyset.v1`, `policy.input.v1`, `policy.decision.v1`, carries `policy.decision.v1` (Constellation proposal 0012, Arbiter proposal 0002) |
| Arbiter reference | `arbiter/docs/INTEGRATION.md`, `docs/CLI.md`, `scripts/evaluate_arbiter_v1.ps1` |
| Status | Implemented (module 2.1.0, optional). Proven with a test double (`tests/Integration.Tests.ps1`) and with Arbiter's real engine (`tests/Interop.Tests.ps1`, Arbiter `a7ccac8`) |

## 1. Turning it on

```json
{"schema":"watchtower.settings.v1",
 "arbiter":{"policyset":"config/arbiter/watchtower_ingest.policyset.json","policy_root":"config/arbiter","timeout_seconds":120}}
```

Arbiter is located through `WATCHTOWER_ARBITER_ROOT` or a sibling checkout (`../arbiter`). It is
never imported; WatchTower runs the evaluator in a child process of its own PowerShell edition:

```
<pwsh|powershell.exe> -NoProfile -NonInteractive -ExecutionPolicy Bypass -File <arbiter>/scripts/evaluate_arbiter_v1.ps1 \
  -RepoRoot <snapshot>/rules -PolicySetPath <snapshot>/policyset.json -InputPath <tmp>/input.json -OutDecisionPath <tmp>/decision.json
```

`config/arbiter/` holds an example policy (deny untrusted namespace or key, quarantine
observations 7+ days old, allow the rest). The policy is the operator's; WatchTower authors none.

## 2. What WatchTower sends (`policy.input.v1`)

Built only from verified facts, after every WatchTower check passed (SPEC §16): `env.now` = the
verification time (the only clock Arbiter uses), `env.mode` `ingest`; the event's namespace,
producer time, producer, signer, event and packet hashes, and claims (`event_type`, `device_id`,
`seq`, `health_status`, `compliance`, `policy_check`, ...); `trust.*` resolved by WatchTower from
its pinned NeverLost bundle (Arbiter never resolves trust).

## 3. What WatchTower does with the answer

| Arbiter | WatchTower |
|---|---|
| `allow` | accepted as usual |
| `deny` | quarantined, `POLICY_DENY`, stage `policy`, warning alert |
| `quarantine` | quarantined, `POLICY_QUARANTINE`; obligations in the quarantine note; warning alert |
| exit 1, no decision, timeout, unverifiable decision, policy unreadable | deny (fail closed): `POLICY_EVALUATOR_FAILED` / `_TIMEOUT` / `_UNAVAILABLE`, `POLICY_DECISION_INVALID`, `POLICY_SET_INVALID`; critical alert |

Stored hashes are never trusted: WatchTower recomputes `policy_hash`, `input_hash` and
`decision_hash`, and checks `evaluated_at` = `env.now`.

## 4. Proof that outlives the run

`proofs/policy/inputs/<hex>.json`, `proofs/policy/decisions/<hex>.json` and the policy snapshot
`proofs/policy/sets/<hex>/` let anyone (LawVM) re-prove a decision:

```
arbiter verify proofs/policy/decisions/<d>.json --policy proofs/policy/sets/<p>/policyset.json \
  --input proofs/policy/inputs/<i>.json --root proofs/policy/sets/<p>/rules
```

`bin/watchtower.ps1 ledger` re-checks the same bytes without Arbiter. Every exchange also writes a
`constellation.integration.receipt.v1` (`integration-receipts.md`).
