import React, { useEffect, useMemo, useState } from "react";

const API_BASES = ["http://127.0.0.1:43187", "http://localhost:43187"];

type AnyObj = Record<string, any>;

const TABS = [
  ["monitor", "Monitor"],
  ["devices", "Devices"],
  ["processes", "Processes"],
  ["performance", "Performance"],
  ["inventory", "Evidence"],
  ["receipts", "Receipts"],
] as const;

function asArray(v: any): any[] {
  return Array.isArray(v) ? v : [];
}

function clean(v: any, fallback = "N/A") {
  if (v === null || v === undefined || v === "") return fallback;
  return String(v);
}

function short(v: any, n = 18) {
  const s = clean(v);
  if (s === "N/A") return s;
  return s.length > n ? `${s.slice(0, n)}...${s.slice(-8)}` : s;
}

function num(v: any) {
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function pct(v: any) {
  const n = num(v);
  return n === null ? "N/A" : `${Math.round(n * 10) / 10}%`;
}

function pctBar(v: any) {
  const n = num(v);
  if (n === null) return 0;
  return Math.max(0, Math.min(100, Math.round(n)));
}

function bytes(v: any) {
  const n = Number(v || 0);
  if (!Number.isFinite(n)) return "N/A";
  if (n >= 1024 ** 4) return `${(n / 1024 ** 4).toFixed(2)} TB`;
  if (n >= 1024 ** 3) return `${(n / 1024 ** 3).toFixed(2)} GB`;
  if (n >= 1024 ** 2) return `${(n / 1024 ** 2).toFixed(2)} MB`;
  if (n >= 1024) return `${(n / 1024).toFixed(2)} KB`;
  return `${n} B`;
}

function unwrapBridgeEnvelope(j: any, path: string) {
  if (!j || typeof j !== "object") return j;

  if (j.ok === false) {
    return {
      error: true,
      bridge_error: true,
      path,
      message: j.error ?? j.message ?? "BRIDGE_ROUTE_ERROR",
      envelope: j,
    };
  }

  if (j.ok === true && Object.prototype.hasOwnProperty.call(j, "data")) {
    return j.data ?? {};
  }

  return j.data ?? j;
}

async function getOne(path: string): Promise<any> {
  for (const base of API_BASES) {
    try {
      const r = await fetch(`${base}${path}`, {
        method: "GET",
        cache: "no-store",
        headers: { Accept: "application/json", "Cache-Control": "no-cache" },
      });

      const text = await r.text();
      const j = JSON.parse(text);

      if (!r.ok) continue;

      const unwrapped = unwrapBridgeEnvelope(j, path);
      if (unwrapped?.error === true) continue;

      return unwrapped;
    } catch {
      // try next base
    }
  }

  return { error: true, message: "FETCH_FAILED", path };
}

async function getAny(paths: string[]) {
  for (const p of paths) {
    const j = await getOne(p);
    if (!j?.error) return j;
  }
  return { error: true, message: "ALL_FETCHES_FAILED", paths };
}

function Table({ rows, columns }: { rows: any[]; columns: string[] }) {
  return (
    <div className="wt-table-wrap">
      <table>
        <thead>
          <tr>{columns.map((c) => <th key={c}>{c}</th>)}</tr>
        </thead>
        <tbody>
          {rows.length ? rows.map((r, i) => (
            <tr key={i}>
              {columns.map((c) => <td key={c}>{clean(r?.[c], "")}</td>)}
            </tr>
          )) : (
            <tr><td colSpan={columns.length}>No rows loaded.</td></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

function Meter({ label, value }: { label: string; value: any }) {
  const w = pctBar(value);
  return (
    <div className="wt-meter">
      <div><span>{label}</span><strong>{pct(value)}</strong></div>
      <i><b style={{ width: `${w}%` }} /></i>
    </div>
  );
}

function Rail({ tab, model }: { tab: string; model: AnyObj }) {
  return (
    <div className="wt-linux-rail">
      <div className="wt-linux-cell brand"><span className="wt-linux-dot" /><strong>{tab}</strong></div>
      <div className="wt-linux-meter"><span>CPU</span><strong>{pct(model.cpu)}</strong><i><b style={{ width: `${pctBar(model.cpu)}%` }} /></i></div>
      <div className="wt-linux-meter"><span>RAM</span><strong>{pct(model.ram)}</strong><i><b style={{ width: `${pctBar(model.ram)}%` }} /></i></div>
      <div className="wt-linux-cell"><span>PROC</span><strong>{clean(model.processCount)}</strong></div>
      <div className="wt-linux-cell"><span>DRV</span><strong>{clean(model.driveCount)}</strong></div>
      <div className={model.alertCount ? "wt-linux-cell warn" : "wt-linux-cell"}><span>ALERT</span><strong>{model.alertCount}</strong></div>
    </div>
  );
}

function walk(obj: any, visit: (v: any, key: string) => boolean, depth = 0): any {
  if (depth > 8 || obj === null || obj === undefined) return undefined;

  if (Array.isArray(obj)) {
    for (const item of obj) {
      const hit = walk(item, visit, depth + 1);
      if (hit !== undefined) return hit;
    }
    return undefined;
  }

  if (typeof obj !== "object") return undefined;

  for (const key of Object.keys(obj)) {
    const value = obj[key];
    if (visit(value, key)) return value;
  }

  for (const key of Object.keys(obj)) {
    const hit = walk(obj[key], visit, depth + 1);
    if (hit !== undefined) return hit;
  }

  return undefined;
}

function deepNumber(obj: any, names: string[]) {
  const wanted = new Set(names.map((x) => x.toLowerCase()));
  const hit = walk(obj, (v, key) => {
    if (!wanted.has(String(key).toLowerCase())) return false;
    return num(v) !== null;
  });

  const n = num(hit);
  return n === null ? null : n;
}

function deepString(obj: any, names: string[]) {
  const wanted = new Set(names.map((x) => x.toLowerCase()));
  const hit = walk(obj, (v, key) => {
    if (!wanted.has(String(key).toLowerCase())) return false;
    return v !== null && v !== undefined && String(v).trim() !== "";
  });

  return hit === undefined ? undefined : String(hit);
}

function scoreDriveRow(row: any) {
  if (!row || typeof row !== "object" || Array.isArray(row)) return 0;
  let score = 0;
  const keys = Object.keys(row).map((k) => k.toLowerCase());
  for (const k of ["drive_letter", "letter", "root", "mount", "path", "name"]) if (keys.includes(k)) score++;
  for (const k of ["filesystem", "fs", "label", "volume_label", "size", "total", "total_bytes", "size_remaining", "free", "free_bytes"]) if (keys.includes(k)) score++;
  return score;
}

function scoreProcessRow(row: any) {
  if (!row || typeof row !== "object" || Array.isArray(row)) return 0;
  let score = 0;
  const keys = Object.keys(row).map((k) => k.toLowerCase());
  for (const k of ["pid", "process_id", "name", "process_name", "executable_path", "root_path", "drive_root", "origin", "origin_kind"]) if (keys.includes(k)) score++;
  return score;
}

function scoreAlertRow(row: any) {
  if (!row || typeof row !== "object" || Array.isArray(row)) return 0;
  let score = 0;
  const keys = Object.keys(row).map((k) => k.toLowerCase());
  for (const k of ["severity", "kind", "message", "root", "utc", "timestamp"]) if (keys.includes(k)) score++;
  return score;
}

function deepBestArray(obj: any, scorer: (row: any) => number): any[] {
  let best: any[] = [];
  let bestScore = 0;

  function scan(v: any, depth = 0) {
    if (depth > 8 || v === null || v === undefined) return;

    if (Array.isArray(v)) {
      const sample = v.slice(0, 8);
      const score = sample.reduce((sum, row) => sum + scorer(row), 0);

      if (v.length > 0 && score > bestScore) {
        best = v;
        bestScore = score;
      }

      for (const item of sample) scan(item, depth + 1);
      return;
    }

    if (typeof v !== "object") return;

    for (const key of Object.keys(v)) scan(v[key], depth + 1);
  }

  scan(obj);
  return best;
}

function buildModel(view: AnyObj) {
  const performance = view.performance ?? {};
  const summary = view.summary ?? {};
  const drives = view.drives ?? {};
  const processes = view.processes ?? {};
  const alerts = view.alerts ?? {};

  const cpu =
    deepNumber(performance, ["cpu_percent", "cpu", "cpu_load", "processor_percent", "cpuUsage", "cpu_usage"]) ??
    deepNumber(summary, ["cpu_percent", "cpu", "cpu_load", "processor_percent", "cpuUsage", "cpu_usage"]) ??
    "N/A";

  const ram =
    deepNumber(performance, ["ram_percent", "memory_percent", "ram", "mem_percent", "memory", "ramUsage", "memory_usage"]) ??
    deepNumber(summary, ["ram_percent", "memory_percent", "ram", "mem_percent", "memory", "ramUsage", "memory_usage"]) ??
    "N/A";

  const driveRows = deepBestArray(drives, scoreDriveRow);
  const processRows = deepBestArray(processes, scoreProcessRow);
  const alertRows = deepBestArray(alerts, scoreAlertRow);

  const processCount =
    deepNumber(performance, ["process_count", "processes", "processCount"]) ??
    deepNumber(summary, ["process_count", "processes", "processCount"]) ??
    deepNumber(processes, ["process_count", "count", "total", "processCount"]) ??
    (processRows.length || "N/A");

  const runtime =
    deepString(summary, ["runtime_root", "runtimeRoot"]) ??
    deepString(view.health, ["runtime_root", "runtimeRoot"]) ??
    deepString(performance, ["runtime_root", "runtimeRoot"]) ??
    "";

  const machineId =
    deepString(view.machine, ["machine_id", "machineId", "machine_hash"]) ??
    deepString(summary, ["machine_id", "machineId", "machine_hash"]) ??
    deepString(view.health, ["machine_id", "machineId", "machine_hash"]) ??
    "unknown";

  const observed =
    deepString(summary, ["last_observed_utc", "observed_utc", "observed", "utc", "timestamp"]) ??
    deepString(performance, ["observed_utc", "observed", "utc", "timestamp"]) ??
    view.loadedAt ??
    "N/A";

  return {
    cpu,
    ram,
    processCount,
    driveCount: driveRows.length || "N/A",
    alertCount: alertRows.length,
    driveRows,
    processRows,
    alertRows,
    runtime,
    machineId,
    observed,
  };
}
export default function WatchTowerWorkbench() {
  const [tab, setTab] = useState("monitor");
  const [view, setView] = useState<AnyObj>({});
  const [loading, setLoading] = useState(true);

  async function load() {
    setLoading(true);
    const [health, summary, performance, drives, processes, alerts, receipts, origins, inventoryLatest, inventoryDiff] = await Promise.all([
      getOne("/health"),
      getOne("/engine/summary"),
      getOne("/engine/performance"),
      getOne("/engine/observe-drives"),
      getOne("/engine/observe-processes"),
      getOne("/engine/alerts"),
      getOne("/engine/receipts"),
      getOne("/engine/process-origins"),
      getOne("/engine/inventory-latest"),
      getOne("/engine/inventory-diff"),
    ]);

    const machine = summary?.machine ?? summary?.machine_identity ?? summary?.host ?? health?.machine ?? {};

    setView({ health, summary, performance, drives, processes, alerts, machine, receipts, origins, inventoryLatest, inventoryDiff, loadedAt: new Date().toISOString() });
    setLoading(false);
  }

  useEffect(() => {
    let cancelled = false;
    const run = async () => { if (!cancelled) await load(); };
    void run();
    const t = window.setInterval(() => void run(), 2500);
    return () => { cancelled = true; window.clearInterval(t); };
  }, []);

  const model = useMemo(() => buildModel(view), [view]);

  const driveRows = model.driveRows.map((d: any) => {
    const size = Number(d.size ?? d.total ?? d.total_bytes ?? d.capacity ?? 0);
    const free = Number(d.size_remaining ?? d.free ?? d.free_bytes ?? d.available ?? 0);
    const used = Number(d.used ?? d.used_bytes ?? Math.max(0, size - Math.max(0, free)));
    const usage = size > 0 ? Math.round((used / size) * 100) : Number(d.usage_percent ?? d.percent ?? 0);
    const root = d.drive_letter ?? d.letter ?? d.root ?? d.mount ?? d.path ?? d.name ?? "";
    return {
      drive: String(root).includes("\\") ? String(root) : `${String(root).replace(":", "").toUpperCase()}:\\`,
      label: clean(d.label ?? d.volume_label, "unlabeled"),
      filesystem: clean(d.filesystem ?? d.fs),
      usage: `${usage}%`,
      used: bytes(used),
      free: bytes(free),
      total: bytes(size),
      status: clean(d.health_status ?? d.status, "unknown"),
    };
  });

  const processRows = model.processRows.slice(0, 80).map((p: any) => ({
    pid: p.pid ?? p.process_id ?? "",
    name: p.name ?? p.process_name ?? "",
    root: p.root_path ?? p.drive_root ?? p.executable_path ?? "",
    origin: p.origin_kind ?? p.origin ?? "",
  }));

  const receiptRows = asArray(view.receipts?.items ?? view.receipts?.entries).slice(0, 80);
  const originRows = asArray(view.origins?.items ?? view.origins?.groups ?? view.origins?.rows).slice(0, 80);

  return (
    <div className="wt-clean-app">
      <aside className="wt-side">
        <div className="wt-brand"><span>WT</span><strong>WatchTower</strong><em>Dynamic Device Inspector</em></div>
        <nav>
          {TABS.map(([id, label]) => (
            <button key={id} className={tab === id ? "active" : ""} onClick={() => setTab(id)}>{label}</button>
          ))}
        </nav>
      </aside>

      <main className="wt-main">
        <Rail tab={TABS.find(([id]) => id === tab)?.[1] ?? tab} model={model} />

        <header className="wt-page-head">
          <div>
            <span>{loading ? "observing" : "connected"}</span>
            <h1>{TABS.find(([id]) => id === tab)?.[1] ?? tab}</h1>
          </div>
          <button onClick={() => void load()}>Refresh</button>
        </header>

        {tab === "monitor" && (
          <>
            <section className="wt-debug-strip">
              <span>Bridge Debug</span>
              <strong>summary {view.summary?.error ? "ERR" : "OK"}</strong>
              <strong>perf {view.performance?.error ? "ERR" : "OK"}</strong>
              <strong>drives {view.drives?.error ? "ERR" : "OK"}</strong>
              <strong>processes {view.processes?.error ? "ERR" : "OK"}</strong>
            </section>
            <section className="wt-live-grid">
              <Meter label="CPU" value={model.cpu} />
              <Meter label="RAM" value={model.ram} />
              <div><span>Processes</span><strong>{clean(model.processCount)}</strong></div>
              <div><span>Mounted</span><strong>{clean(model.driveCount)}</strong></div>
              <div><span>Alerts</span><strong>{model.alertCount}</strong></div>
            </section>

            <section className="wt-panel">
              <div className="wt-panel-head"><h2>Drive Performance</h2><span>{driveRows.length} mounted drive routes</span></div>
              <Table rows={driveRows} columns={["drive", "label", "filesystem", "usage", "used", "free", "total", "status"]} />
            </section>

            <section className="wt-panel">
              <div className="wt-panel-head"><h2>Attention Feed</h2><span>{model.alertCount ? `${model.alertCount} active` : "clear"}</span></div>
              <Table rows={model.alertRows.slice(0, 12)} columns={["severity", "kind", "message", "root", "utc"]} />
            </section>
          </>
        )}

        {tab === "devices" && (
          <section className="wt-panel">
            <div className="wt-panel-head"><h2>Mounted Devices</h2><span>{driveRows.length} routes</span></div>
            <Table rows={driveRows} columns={["drive", "label", "filesystem", "usage", "used", "free", "total", "status"]} />
          </section>
        )}

        {tab === "processes" && (
          <section className="wt-panel">
            <div className="wt-panel-head"><h2>Process Routes</h2><span>showing first {processRows.length}</span></div>
            <Table rows={processRows} columns={["pid", "name", "root", "origin"]} />
          </section>
        )}

        {tab === "performance" && (
          <section className="wt-live-grid">
            <Meter label="CPU" value={model.cpu} />
            <Meter label="RAM" value={model.ram} />
            <div><span>Processes</span><strong>{clean(model.processCount)}</strong></div>
            <div><span>Mounted</span><strong>{clean(model.driveCount)}</strong></div>
            <div><span>Observed</span><strong>{short(model.observed)}</strong></div>
          </section>
        )}

        {tab === "inventory" && (
          <>
            <section className="wt-panel">
              <div className="wt-panel-head"><h2>Inventory Latest</h2><span>evidence mode</span></div>
              <pre>{JSON.stringify(view.inventoryLatest ?? {}, null, 2)}</pre>
            </section>
            <section className="wt-panel">
              <div className="wt-panel-head"><h2>Inventory Diff</h2><span>evidence mode</span></div>
              <pre>{JSON.stringify(view.inventoryDiff ?? {}, null, 2)}</pre>
            </section>
          </>
        )}

        {tab === "receipts" && (
          <section className="wt-panel">
            <div className="wt-panel-head"><h2>Receipts</h2><span>evidence mode</span></div>
            <Table rows={receiptRows} columns={["utc", "kind", "schema", "payload_hash", "file"]} />
          </section>
        )}

        {tab === "summary" && (
          <section className="wt-panel">
            <div className="wt-panel-head"><h2>Summary</h2><span>raw on demand</span></div>
            <pre>{JSON.stringify(view.summary ?? {}, null, 2)}</pre>
          </section>
        )}

        {tab === "origins" && (
          <section className="wt-panel">
            <div className="wt-panel-head"><h2>Origins</h2><span>process route groups</span></div>
            <Table rows={originRows} columns={["origin", "drive", "root_path", "count"]} />
          </section>
        )}
      </main>
    </div>
  );
}
