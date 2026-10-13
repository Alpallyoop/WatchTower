import React, { useEffect, useMemo, useState } from "react";

const API_BASES = ["http://127.0.0.1:43187", "http://localhost:43187"];

async function apiGet(path: string): Promise<any> {
  for (const base of API_BASES) {
    try {
      const r = await fetch(`${base}${path}`, {
        method: "GET",
        cache: "no-store",
        headers: {
          Accept: "application/json",
          "Cache-Control": "no-cache"
        }
      });

      const text = await r.text();
      const j = JSON.parse(text);

      if (!r.ok) continue;
      if (j && j.ok === true && Object.prototype.hasOwnProperty.call(j, "data")) return j.data;
      return j;
    } catch {
      // try next base
    }
  }

  return { error: true, message: "BRIDGE_FETCH_FAILED" };
}

function asArray(v: any): any[] {
  return Array.isArray(v) ? v : [];
}

function firstNumber(values: any[], fallback: any) {
  for (const v of values) {
    const n = Number(v);
    if (Number.isFinite(n)) return n;
  }
  return fallback;
}

function firstPositive(values: any[], fallback: any) {
  for (const v of values) {
    const n = Number(v);
    if (Number.isFinite(n) && n > 0) return n;
  }
  return fallback;
}

function pctText(v: any) {
  const n = Number(v);
  if (!Number.isFinite(n)) return "N/A";
  return `${Math.round(n * 10) / 10}%`;
}

function pctBar(v: any) {
  const n = Number(v);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(100, Math.round(n)));
}

export default function WatchTowerDesktopTopRail() {
  const [data, setData] = useState<any>({
    health: {},
    summary: {},
    performance: {},
    drives: {},
    processes: {},
    alerts: {},
    updated: ""
  });

  useEffect(() => {
    let cancelled = false;

    async function load() {
      const [health, summary, performance, drives, processes, alerts] = await Promise.all([
        apiGet("/health"),
        apiGet("/engine/summary"),
        apiGet("/engine/performance"),
        apiGet("/engine/observe-drives"),
        apiGet("/engine/observe-processes"),
        apiGet("/engine/alerts")
      ]);

      if (cancelled) return;

      setData({
        health,
        summary,
        performance,
        drives,
        processes,
        alerts,
        updated: new Date().toISOString()
      });
    }

    void load();
    const timer = window.setInterval(() => void load(), 2000);

    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, []);

  const model = useMemo(() => {
    const perf = data.performance ?? {};
    const summary = data.summary ?? {};
    const processes = data.processes ?? {};
    const drives = data.drives ?? {};
    const alerts = data.alerts ?? {};

    const hist = asArray(perf.history ?? perf.samples ?? perf.recent_samples);
    const last = hist.length ? hist[hist.length - 1] : {};

    const cpu = firstNumber([
      perf.cpu_percent,
      perf.cpu,
      last.cpu_percent,
      last.cpu,
      summary.cpu_percent,
      summary.cpu
    ], "N/A");

    const ram = firstNumber([
      perf.ram_percent,
      perf.memory_percent,
      perf.ram,
      last.ram_percent,
      last.memory_percent,
      last.ram,
      summary.ram_percent,
      summary.memory_percent,
      summary.ram
    ], "N/A");

    const processRows = asArray(processes.items ?? processes.processes ?? processes.rows);
    const processCount = firstPositive([
      perf.process_count,
      summary.process_count,
      summary.processes,
      processes.process_count,
      processes.count,
      processRows.length
    ], "N/A");

    const mounted = asArray(drives.items)
      .filter((d: any) => d?.drive_letter && String(d.drive_letter).trim() !== "");

    const alertCount = asArray(alerts.items ?? alerts.alerts).length;

    const runtime =
      summary.runtime_root ??
      data.health?.runtime_root ??
      perf.runtime_root ??
      "";

    return {
      connected: data.health?.ok !== false && data.health?.error !== true,
      cpu,
      ram,
      cpuBar: pctBar(cpu),
      ramBar: pctBar(ram),
      processCount,
      mountedCount: mounted.length || "N/A",
      alertCount,
      runtime,
      updated: data.updated
    };
  }, [data]);

  return (
    <div className="wt-desktop-rail" data-connected={model.connected ? "true" : "false"}>
      <div className="wt-desktop-cell wt-desktop-brand">
        <span className="wt-desktop-dot" />
        <strong>WatchTower</strong>
      </div>

      <div className="wt-desktop-meter">
        <span>CPU</span>
        <strong>{pctText(model.cpu)}</strong>
        <i><b style={{ width: `${model.cpuBar}%` }} /></i>
      </div>

      <div className="wt-desktop-meter">
        <span>RAM</span>
        <strong>{pctText(model.ram)}</strong>
        <i><b style={{ width: `${model.ramBar}%` }} /></i>
      </div>

      <div className="wt-desktop-cell">
        <span>PROC</span>
        <strong>{model.processCount}</strong>
      </div>

      <div className="wt-desktop-cell">
        <span>DRV</span>
        <strong>{model.mountedCount}</strong>
      </div>

      <div className={model.alertCount ? "wt-desktop-cell wt-desktop-warn" : "wt-desktop-cell"}>
        <span>ALERT</span>
        <strong>{model.alertCount}</strong>
      </div>

      <div className="wt-desktop-runtime">
        {model.runtime ? model.runtime : "local monitor"}
      </div>
    </div>
  );
}
