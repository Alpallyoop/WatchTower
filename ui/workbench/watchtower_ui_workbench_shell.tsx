import React, { useEffect, useState } from "react";
import { WatchTowerAPI } from "./watchtower_api";

export default function WatchTowerWorkbench() {

  const [tab, setTab] = useState("processes");
  const [loading, setLoading] = useState(true);
  const [view, setView] = useState<any>({});

  const TABS = ["machine","processes","storage","origins","receipts"];

  useEffect(() => {
    let alive = true;

    (async () => {
      const v = {
        machine: await WatchTowerAPI.machine(),
        processes: await WatchTowerAPI.processes(),
        drives: await WatchTowerAPI.drives(),
        origins: await WatchTowerAPI.origins(),
        receipts: await WatchTowerAPI.receipts()
      };

      if (!alive) return;

      setView(v);
      setLoading(false);
    })();

    return () => { alive = false; };
  }, []);

  const render = () => {
    switch (tab) {

      case "machine":
        return (
          <div>
            <h2>Machine</h2>
            <pre>{JSON.stringify(view.machine, null, 2)}</pre>
          </div>
        );

      case "processes":
        return (
          <div>
            <h2>Processes</h2>
            {(view.processes || []).map((p: any, i: number) => (
              <div key={i} style={{ padding: 6, borderBottom: "1px solid #222" }}>
                PID: {p.pid} | {p.name}
              </div>
            ))}
          </div>
        );

      case "storage":
        return (
          <div>
            <h2>Storage</h2>
            <pre>{JSON.stringify(view.drives, null, 2)}</pre>
          </div>
        );

      case "origins":
        return (
          <div>
            <h2>Origins</h2>
            <pre>{JSON.stringify(view.origins, null, 2)}</pre>
          </div>
        );

      case "receipts":
        return (
          <div>
            <h2>Receipts</h2>
            <pre>{JSON.stringify(view.receipts, null, 2)}</pre>
          </div>
        );

      default:
        return <div>Loading...</div>;
    }
  };

  return (
    <div style={{ display: "flex", height: "100vh", background: "#0a0a0a", color: "white" }}>

      <div style={{ width: 200, borderRight: "1px solid #222", padding: 10 }}>
        {TABS.map(t => (
          <div
            key={t}
            onClick={() => setTab(t)}
            style={{
              padding: 8,
              cursor: "pointer",
              color: tab === t ? "cyan" : "white"
            }}
          >
            {t}
          </div>
        ))}
      </div>

      <div style={{ flex: 1, padding: 20 }}>
        {loading ? "Booting Inspector..." : render()}
      </div>

    </div>
  );
}


useEffect(() => {
  let alive = true;

  const safe = async (fn: any) => {
    try {
      return await fn();
    } catch {
      return null;
    }
  };

  (async () => {

    const [machine, processes, drives, origins, receipts] = await Promise.all([
      safe(WatchTowerAPI.machine),
      safe(WatchTowerAPI.processes),
      safe(WatchTowerAPI.drives),
      safe(WatchTowerAPI.origins),
      safe(WatchTowerAPI.receipts),
    ]);

    if (!alive) return;

    setView({
      machine,
      processes,
      drives,
      origins,
      receipts
    });

    setLoading(false);
  })();

  return () => { alive = false; };
}, []);
