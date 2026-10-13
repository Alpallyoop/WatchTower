import React, { useMemo, useState } from "react";

function loadDevices() {
  return [
    {
      deviceId: "936257f45d13ce95962d64d2c829b477253fded2caaa44a93cd9e92bd286d5a4",
      label: "Lenovo · SN-BIND-001",
      osFamily: "windows",
      trustLevel: "T1",
      state: "broken",
      alerts: 1,
      lastSeen: "2026-01-01T00:02:00Z",
      hardwareFingerprint: "hwfp-binding-001",
      manufacturer: "Lenovo",
      serial: "SN-BIND-001",
    },
    {
      deviceId: "5be9ba3333ebd249e66b7cef00b359d6371d30daa76cb840acfa4aa3a4f4610c",
      label: "Binding Selftest Device",
      osFamily: "windows",
      trustLevel: "T1",
      state: "ok",
      alerts: 0,
      lastSeen: "2026-03-01T00:15:00Z",
      hardwareFingerprint: "hwfp-binding-001",
      manufacturer: "Lenovo",
      serial: "SN-BIND-001",
    },
  ];
}

function loadTelemetryTimeline() {
  return [
    {
      ts: "2026-01-01T00:00:00Z",
      type: "telemetry/watchtower.test.telemetry.v1",
      summary: "Initial telemetry bind accepted",
      hash: "9fb8626624b1c614052678152025868a5f6446a78da669fc40a3823d759845bf",
    },
    {
      ts: "2026-01-01T00:01:00Z",
      type: "alert/state",
      summary: "State classified as broken",
      hash: "f4fdf7e1748eaf5927b669dc17a4222919c0626a3c91aba7f40663aa8fc7a715",
    },
    {
      ts: "2026-01-01T00:02:00Z",
      type: "device/append",
      summary: "Append-only chain advanced",
      hash: "f7e2a135e84b40097a226381c7965310a6d94a75d3191206afa30ed11883096a",
    },
  ];
}

function loadStateCards() {
  return [
    { name: "ok", count: 1 },
    { name: "stale", count: 1 },
    { name: "drift", count: 1 },
    { name: "broken", count: 1 },
  ];
}

function loadReceipts() {
  const root = ".";  // repository-relative
  return [
    {
      name: "watchtower_tier0_freeze.ndjson",
      path: root + "/proofs/receipts/watchtower_tier0_freeze.ndjson",
      kind: "freeze receipt",
    },
    {
      name: "freeze_manifest.json",
      path: root + "/proofs/freeze/watchtower_tier0_v1/freeze_manifest.json",
      kind: "freeze manifest",
    },
    {
      name: "sha256sums.txt",
      path: root + "/proofs/freeze/watchtower_tier0_v1/sha256sums.txt",
      kind: "evidence hashes",
    },
    {
      name: "watchtower_bind_telemetry_to_device_event.ndjson",
      path: root + "/proofs/receipts/watchtower_bind_telemetry_to_device_event.ndjson",
      kind: "binding receipt",
    },
  ];
}

function loadFreezeEvidence() {
  const root = "./proofs/freeze/watchtower_tier0_v1";
  return {
    freezeRoot: root,
    manifest: root + "/freeze_manifest.json",
    sha256sums: root + "/sha256sums.txt",
    fullGreenStdout: root + "/full_green.stdout.txt",
    fullGreenStderr: root + "/full_green.stderr.txt",
    bindingStdout: root + "/device_binding.stdout.txt",
    bindingStderr: root + "/device_binding.stderr.txt",
    tier0Receipt: "./proofs/receipts/watchtower_tier0_freeze.ndjson",
  };
}

function StatePill({ state }: { state: string }) {
  const map: Record<string, string> = {
    ok: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
    stale: "border-amber-500/30 bg-amber-500/10 text-amber-300",
    drift: "border-sky-500/30 bg-sky-500/10 text-sky-300",
    broken: "border-rose-500/30 bg-rose-500/10 text-rose-300",
  };
  const cls = map[state] ?? map.ok;
  return <span className={`inline-flex items-center rounded-full border px-2.5 py-1 text-xs ${cls}`}>{state}</span>;
}

export default function WatchtowerUiWorkbenchShell() {
  const devices = loadDevices();
  const telemetryTimeline = loadTelemetryTimeline();
  const stateCards = loadStateCards();
  const receipts = loadReceipts();
  const freezeEvidence = loadFreezeEvidence();

  const [query, setQuery] = useState("");
  const [selectedId, setSelectedId] = useState(devices[0].deviceId);
  const [tab, setTab] = useState<"timeline" | "state" | "alerts" | "receipts">("timeline");

  const filteredDevices = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return devices;
    return devices.filter((d) =>
      [d.deviceId, d.label, d.osFamily, d.manufacturer, d.serial, d.state].join(" ").toLowerCase().includes(q)
    );
  }, [query, devices]);

  const selected = filteredDevices.find((d) => d.deviceId === selectedId) ?? devices.find((d) => d.deviceId === selectedId) ?? devices[0];

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 p-8">
      <div className="mx-auto max-w-7xl">
        <div className="rounded-3xl border border-zinc-800 bg-zinc-900/70 p-8 shadow-2xl shadow-black/30">
          <div className="text-xs uppercase tracking-[0.2em] text-zinc-500">WatchTower Observatory Workbench</div>
          <h1 className="mt-3 text-4xl font-semibold tracking-tight">Deterministic device observatory</h1>
          <p className="mt-3 max-w-3xl text-sm text-zinc-400">Tier-0 sealed. This workbench rides on top of frozen WatchTower outputs and presents device identity, state, telemetry, alerts, and receipts as evidence.</p>

          <div className="mt-8 grid gap-4 md:grid-cols-4">
            <div className="rounded-2xl border border-zinc-800 bg-zinc-950/70 p-4"><div className="text-xs text-zinc-500">Devices</div><div className="mt-2 text-2xl font-semibold">{devices.length}</div></div>
            <div className="rounded-2xl border border-zinc-800 bg-zinc-950/70 p-4"><div className="text-xs text-zinc-500">Receipts</div><div className="mt-2 text-2xl font-semibold">{receipts.length}</div></div>
            <div className="rounded-2xl border border-zinc-800 bg-zinc-950/70 p-4"><div className="text-xs text-zinc-500">States</div><div className="mt-2 text-2xl font-semibold">{stateCards.length}</div></div>
            <div className="rounded-2xl border border-zinc-800 bg-zinc-950/70 p-4"><div className="text-xs text-zinc-500">Freeze</div><div className="mt-2 text-sm font-medium text-emerald-300">sealed</div></div>
          </div>

          <div className="mt-8 grid gap-6 lg:grid-cols-[340px_minmax(0,1fr)]">
            <div className="rounded-3xl border border-zinc-800 bg-zinc-950/70 p-5">
              <div className="text-sm font-medium">Device inventory</div>
              <div className="mt-1 text-xs text-zinc-500">First-class device artifacts, not mutable host rows.</div>
              <div className="mt-4">
                <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search device id, serial, state..." className="w-full rounded-2xl border border-zinc-800 bg-zinc-900 px-4 py-3 text-sm text-zinc-100 outline-none placeholder:text-zinc-500" />
              </div>
              <div className="mt-4 space-y-3">
                {filteredDevices.map((d) => (
                  <button key={d.deviceId} onClick={() => setSelectedId(d.deviceId)} className={`w-full rounded-2xl border p-4 text-left transition ${selected.deviceId === d.deviceId ? "border-zinc-600 bg-zinc-800/70" : "border-zinc-800 bg-zinc-900/40 hover:bg-zinc-900"}`}>
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="text-sm font-medium">{d.label}</div>
                        <div className="mt-1 break-all text-xs text-zinc-500">{d.deviceId}</div>
                      </div>
                      <StatePill state={d.state} />
                    </div>
                    <div className="mt-3 flex items-center gap-2 text-xs text-zinc-400">
                      <span className="rounded-full border border-zinc-700 px-2 py-0.5">{d.trustLevel}</span>
                      <span>{d.osFamily}</span>
                      <span>•</span>
                      <span>{d.alerts} alerts</span>
                    </div>
                  </button>
                ))}
              </div>
            </div>

            <div className="space-y-6">
              <div className="rounded-3xl border border-zinc-800 bg-zinc-950/70 p-6">
                <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                  <div>
                    <div className="text-xl font-semibold">{selected.label}</div>
                    <div className="mt-1 break-all text-xs text-zinc-500">{selected.deviceId}</div>
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    <StatePill state={selected.state} />
                    <span className="rounded-full border border-zinc-700 px-2.5 py-1 text-xs text-zinc-300">Trust {selected.trustLevel}</span>
                    <span className="rounded-full border border-zinc-700 px-2.5 py-1 text-xs text-zinc-300">{selected.osFamily}</span>
                  </div>
                </div>
                <div className="mt-6 grid gap-4 md:grid-cols-4">
                  <div className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-4"><div className="text-xs text-zinc-500">Manufacturer</div><div className="mt-2 font-medium">{selected.manufacturer}</div></div>
                  <div className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-4"><div className="text-xs text-zinc-500">Serial</div><div className="mt-2 font-medium">{selected.serial}</div></div>
                  <div className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-4"><div className="text-xs text-zinc-500">Last seen</div><div className="mt-2 font-medium">{selected.lastSeen}</div></div>
                  <div className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-4"><div className="text-xs text-zinc-500">Hardware fingerprint</div><div className="mt-2 break-all font-medium">{selected.hardwareFingerprint}</div></div>
                </div>
              </div>

              <div className="rounded-3xl border border-zinc-800 bg-zinc-950/70 p-6">
                <div className="flex flex-wrap gap-2">
                  <button onClick={() => setTab("timeline")} className={`rounded-2xl border px-4 py-2 text-sm ${tab === "timeline" ? "border-zinc-600 bg-zinc-800 text-zinc-100" : "border-zinc-800 bg-zinc-900/40 text-zinc-400"}`}>Timeline</button>
                  <button onClick={() => setTab("state")} className={`rounded-2xl border px-4 py-2 text-sm ${tab === "state" ? "border-zinc-600 bg-zinc-800 text-zinc-100" : "border-zinc-800 bg-zinc-900/40 text-zinc-400"}`}>State</button>
                  <button onClick={() => setTab("alerts")} className={`rounded-2xl border px-4 py-2 text-sm ${tab === "alerts" ? "border-zinc-600 bg-zinc-800 text-zinc-100" : "border-zinc-800 bg-zinc-900/40 text-zinc-400"}`}>Alerts</button>
                  <button onClick={() => setTab("receipts")} className={`rounded-2xl border px-4 py-2 text-sm ${tab === "receipts" ? "border-zinc-600 bg-zinc-800 text-zinc-100" : "border-zinc-800 bg-zinc-900/40 text-zinc-400"}`}>Receipts</button>
                </div>

                {tab === "timeline" && (
                  <div className="mt-4 space-y-4">
                    {telemetryTimeline.map((item, idx) => (
                      <div key={item.hash} className="relative rounded-2xl border border-zinc-800 bg-zinc-900/40 p-4">
                        {idx < telemetryTimeline.length - 1 && <div className="absolute left-[19px] top-14 h-10 w-px bg-zinc-800" />}
                        <div className="flex gap-4">
                          <div className="mt-1 h-2.5 w-2.5 rounded-full bg-zinc-300" />
                          <div className="min-w-0 flex-1">
                            <div className="flex flex-wrap items-center gap-2">
                              <div className="text-sm font-medium">{item.summary}</div>
                              <span className="rounded-full border border-zinc-700 px-2 py-0.5 text-xs text-zinc-300">{item.type}</span>
                            </div>
                            <div className="mt-1 text-xs text-zinc-500">{item.ts}</div>
                            <div className="mt-3 break-all text-xs text-zinc-400">{item.hash}</div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {tab === "state" && (
                  <div className="mt-4 grid gap-4 md:grid-cols-4">
                    {stateCards.map((s) => (
                      <div key={s.name} className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-4">
                        <div className="flex items-center justify-between">
                          <div className="text-sm font-medium capitalize">{s.name}</div>
                          <StatePill state={s.name} />
                        </div>
                        <div className="mt-4 text-3xl font-semibold">{s.count}</div>
                      </div>
                    ))}
                  </div>
                )}

                {tab === "alerts" && (
                  <div className="mt-4 rounded-2xl border border-amber-500/30 bg-amber-500/10 p-4 text-amber-100">
                    <div className="font-medium">Broken state requires review</div>
                    <div className="mt-1 text-sm text-amber-200/80">Latest state classifier returned broken with one alert derived from the current telemetry vector set.</div>
                  </div>
                )}

                {tab === "receipts" && (
                  <div className="mt-4 space-y-6">
                    <div className="rounded-2xl border border-emerald-500/20 bg-emerald-500/5 p-4">
                      <div className="text-sm font-medium text-emerald-300">Freeze evidence bundle</div>
                      <div className="mt-3 space-y-2 text-xs text-zinc-300">
                        <div><span className="text-zinc-500">Freeze root:</span> {freezeEvidence.freezeRoot}</div>
                        <div><span className="text-zinc-500">Manifest:</span> {freezeEvidence.manifest}</div>
                        <div><span className="text-zinc-500">sha256sums:</span> {freezeEvidence.sha256sums}</div>
                        <div><span className="text-zinc-500">Full green stdout:</span> {freezeEvidence.fullGreenStdout}</div>
                        <div><span className="text-zinc-500">Full green stderr:</span> {freezeEvidence.fullGreenStderr}</div>
                        <div><span className="text-zinc-500">Binding stdout:</span> {freezeEvidence.bindingStdout}</div>
                        <div><span className="text-zinc-500">Binding stderr:</span> {freezeEvidence.bindingStderr}</div>
                        <div><span className="text-zinc-500">Tier-0 receipt:</span> {freezeEvidence.tier0Receipt}</div>
                      </div>
                    </div>

                    <div className="space-y-3">
                      {receipts.map((r) => (
                        <div key={r.path} className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-4">
                          <div className="text-sm font-medium">{r.name}</div>
                          <div className="mt-1 text-xs text-zinc-500">{r.path}</div>
                          <div className="mt-2 text-xs text-zinc-400">{r.kind}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
