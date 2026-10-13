# Contract: WatchTower ⇢ claim-protocol (optional, not implemented)

| | |
|---|---|
| Registry | `integrations.json`: consumer `claim-protocol`, provider `watchtower`, contract `watchtower.verify.receipt.v1`, registry action "compatible-added (optional connector / would break dependency direction)" |
| Where it appears | `claim-protocol/docs/CLP_OBJECT_LAW_V1.md` and its test vectors use `watchtower.verify.receipt.v1` as an example `receipt_type` inside `clp.receipt.v1` objects |
| Status | Not implemented. WatchTower emits no `watchtower.verify.receipt.v1`. |

claim-protocol names `watchtower.verify.receipt.v1` only as an example receipt type; no schema for
it exists in either repository. The registry itself marks a direct dependency as one that "would
break dependency direction", so WatchTower does not call or write into claim-protocol.

If the connector is wanted, the smallest correct form is a mapping, owned by claim-protocol, from a
WatchTower receipt row to a `clp.receipt.v1` object:

| `clp.receipt.v1` | From `watchtower.telemetry.receipt.v1` |
|---|---|
| `receipt_type` | `watchtower.verify.receipt.v1` |
| `result.ok` | `verify_result = "ok"` |
| `result.reason` | `fail_reason.code` |
| `timestamp` | `receipt_time` |
| `for_claim` | claim id chosen by claim-protocol (for example the `packet_id`) |

That decision belongs to claim-protocol and the Constellation registry; it needs a proposal there
before anything is built here.
