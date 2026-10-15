# Contracts

Wire contracts between WatchTower and the services around it. Each file says who produces and
who consumes, the exact files and fields, and what is proven today.

| Neighbour | Direction | File | Status |
|---|---|---|---|
| live-state-surgeon | packets in; receipts, alerts, documents out | `live-state-surgeon.md` | done both sides: packets from LSS's own emitter accepted end to end |
| NFL (via CPR) | receipt and integration-witness packets out (`packets/outbox`) | `nfl-and-cpr.md` | CPR accepts both; NFL hash commit not built yet (NFL side) |
| NeverLost | trust format, principal and producer bundles in | `neverlost.md` | done; NeverLost v1 bundle rules; `enroll -FromBundle` carries `neverlost.receipt.v1` |
| Arbiter | policy input out, decision in (optional gate) | `arbiter.md` | done; real engine proven |
| Constellation integration receipts | one receipt per exchange, witnessed via NFL | `integration-receipts.md` | emitting for arbiter, neverlost, nfl |
| Constellation | health facet out | `constellation.md` | done; live oversight read not recorded |
| Global Workbench | settings schema and evidence index out | `global-workbench.md` | schema and index done; plugin panels not built |
| claim-protocol | optional mapping | `claim-protocol.md` | not implemented by design |

The older files in `/contracts` (TRIAD, Atlas, Legacy Doctor, Archive/Recall) describe the v1
device-custody scope and are unchanged.
