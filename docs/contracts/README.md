# Contracts

Wire contracts between WatchTower and the services around it. Each file says who produces and
who consumes, the exact files and fields, and what is proven today.

| Neighbour | Direction | File | Status |
|---|---|---|---|
| live-state-surgeon | packets in; receipts, alerts, documents out | `live-state-surgeon.md` | WatchTower side done; producer fixes pending (proposal 0002) |
| NFL (via CPR) | receipt packets out (`packets/outbox`) | `nfl-and-cpr.md` | CPR accepts; NFL run not recorded |
| NeverLost | trust format and principal in | `neverlost.md` | done; `neverlost.receipt.v1` not consumed |
| Constellation | health facet out | `constellation.md` | done; live oversight read not recorded |
| Global Workbench | settings schema and evidence index out | `global-workbench.md` | schema and index done; plugin panels not built |
| claim-protocol | optional mapping | `claim-protocol.md` | not implemented by design |

The older files in `/contracts` (TRIAD, Atlas, Legacy Doctor, Archive/Recall) describe the v1
device-custody scope and are unchanged.
