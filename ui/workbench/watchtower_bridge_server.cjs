const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const PORT = 43187;
const HOST = "127.0.0.1";

// Everything lives inside the project (was %LOCALAPPDATA%): <repo>/local/WatchTowerCLI and
// <repo>/local/WatchTowerInspector, or WATCHTOWER_LOCAL_ROOT when set.
const REPO_ROOT = path.resolve(__dirname, "..", "..");
const LOCAL_ROOT = process.env.WATCHTOWER_LOCAL_ROOT ? path.resolve(process.env.WATCHTOWER_LOCAL_ROOT) : path.join(REPO_ROOT, "local");
const BUNDLE_ROOT = path.join(LOCAL_ROOT, "WatchTowerCLI", "watchtower_cli_v1");
const RUNTIME_ROOT = path.join(BUNDLE_ROOT, "runtime", "watchtower_engine_v1");
const INSPECTOR_ROOT = path.join(LOCAL_ROOT, "WatchTowerInspector");
const REGISTRY_ROOT = path.join(INSPECTOR_ROOT, "device_registry");
const SESSION_ROOT = path.join(INSPECTOR_ROOT, "sessions");
const INVENTORY_ROOT = path.join(INSPECTOR_ROOT, "inventory");
const SETTINGS_PATH = path.join(INSPECTOR_ROOT, "settings.json");
const PERF_PATH = path.join(INSPECTOR_ROOT, "performance_samples.ndjson");
const REGISTRY_PATH = path.join(REGISTRY_ROOT, "machine_registry.json");

function ensureDir(p) {
  fs.mkdirSync(p, { recursive: true });
}

function stableJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(stableJson).join(",") + "]";
  return "{" + Object.keys(value).sort().map((k) => JSON.stringify(k) + ":" + stableJson(value[k])).join(",") + "}";
}

function sha256(value) {
  return crypto.createHash("sha256").update(stableJson(value), "utf8").digest("hex");
}

function json(res, obj) {
  res.writeHead(200, {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "*",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
  });
  res.end(JSON.stringify(obj));
}

function ok(reqPath, data) {
  return {
    ok: true,
    ts: Date.now(),
    path: reqPath,
    source: "watchtower_performance_session_v11",
    runtime_root: RUNTIME_ROOT,
    data
  };
}

function readJson(filePath, fallback) {
  try {
    if (!fs.existsSync(filePath)) return fallback;
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch (e) {
    return { error: true, message: "JSON_READ_FAILED", path: filePath, detail: String(e) };
  }
}

function writeJson(filePath, value) {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, JSON.stringify(value, null, 2) + "\n", "utf8");
}

function asArray(x) {
  if (Array.isArray(x)) return x;
  if (!x || typeof x !== "object") return [];
  if (Array.isArray(x.items)) return x.items;
  if (Array.isArray(x.data)) return x.data;
  if (Array.isArray(x.drives)) return x.drives;
  if (Array.isArray(x.volumes)) return x.volumes;
  if (Array.isArray(x.processes)) return x.processes;
  if (Array.isArray(x.process_origins)) return x.process_origins;
  return [];
}

function psJson(script, fallback) {
  const child = spawnSync("powershell.exe", [
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
    "-Command",
    script
  ], {
    encoding: "utf8",
    timeout: 9000,
    windowsHide: true
  });

  if (child.status !== 0) {
    return { ...fallback, error: true, stderr: child.stderr || "", exit_code: child.status };
  }

  try {
    return JSON.parse(child.stdout || "{}");
  } catch (e) {
    return { ...fallback, error: true, stdout: child.stdout || "", detail: String(e) };
  }
}

function systemMetrics() {
  return psJson(`
    $ErrorActionPreference='SilentlyContinue'
    $os = Get-CimInstance Win32_OperatingSystem
    $cpuObj = Get-CimInstance Win32_Processor
    $cpu = ($cpuObj | Measure-Object -Property LoadPercentage -Average).Average
    if($null -eq $cpu){ $cpu = 0 }
    $memTotal = [double]$os.TotalVisibleMemorySize * 1024
    $memFree = [double]$os.FreePhysicalMemory * 1024
    $memUsed = $memTotal - $memFree
    [pscustomobject]@{
      cpu_percent=[math]::Round([double]$cpu,1)
      memory_total=[int64]$memTotal
      memory_used=[int64]$memUsed
      memory_free=[int64]$memFree
      memory_percent=[math]::Round(($memUsed / $memTotal) * 100,1)
      observed_utc=(Get-Date).ToUniversalTime().ToString('o')
    } | ConvertTo-Json -Depth 5
  `, {
    cpu_percent: null,
    memory_total: null,
    memory_used: null,
    memory_free: null,
    memory_percent: null,
    observed_utc: new Date().toISOString()
  });
}

function deriveOrigin(row) {
  const exe = String(row.executable_path || row.path || "").trim();

  if (!exe) {
    return { pid: row.pid, name: row.name, origin: "protected_or_system", drive: "", root_path: "", executable_path: "" };
  }

  const driveMatch = exe.match(/^([A-Za-z]):\\/);
  const drive = driveMatch ? driveMatch[1].toUpperCase() : "";
  const lower = exe.toLowerCase();

  let origin = "unknown";
  if (lower.startsWith("c:\\windows\\") || lower.startsWith("c:\\program files\\windowsapps\\")) {
    origin = "protected_or_system";
  } else if (drive) {
    origin = "local_drive";
  }

  let rootPath = "";
  if (drive) {
    const parts = exe.split("\\").filter(Boolean);
    rootPath = parts.length >= 2 ? drive + ":\\" + parts[1] : drive + ":\\";
  }

  return { pid: row.pid, name: row.name, origin, drive, root_path: rootPath, executable_path: exe };
}

function groupOrigins(rows) {
  const map = new Map();

  for (const row of rows) {
    const derived = deriveOrigin(row);
    const origin = row.origin_kind || row.origin || row.kind || derived.origin || "unknown";
    const drive = row.drive_root || row.drive || derived.drive || "";
    const rootPath = row.root_path || derived.root_path || "";
    const key = origin + "|" + drive + "|" + rootPath;

    if (!map.has(key)) {
      map.set(key, { origin, drive: drive || "N/A", root_path: rootPath || "N/A", count: 0 });
    }

    map.get(key).count += 1;
  }

  return Array.from(map.values()).sort((a, b) => b.count - a.count);
}

function loadMachine() {
  const machinePath = path.join(RUNTIME_ROOT, "machine", "machine.json");
  const data = readJson(machinePath, {});
  return {
    title: "Machine Identity",
    ok: fs.existsSync(machinePath),
    exit_code: 0,
    machine_id: data.machine_id || data.id || data.machineId || "",
    machine_path: machinePath,
    ...data
  };
}

function loadDrives() {
  const drivesPath = path.join(RUNTIME_ROOT, "drives", "drives.json");
  const parsed = readJson(drivesPath, []);
  const items = asArray(parsed);

  return {
    title: "Mounted Storage",
    ok: fs.existsSync(drivesPath),
    drives_path: drivesPath,
    disks: parsed.disks?.length ?? parsed.disk_count ?? 0,
    volumes: items.length,
    items
  };
}

function loadProcesses() {
  const processesPath = path.join(RUNTIME_ROOT, "processes", "processes.json");
  const originsPath = path.join(RUNTIME_ROOT, "processes", "process_origins.json");

  const items = asArray(readJson(processesPath, []));
  const explicitOrigins = asArray(readJson(originsPath, []));
  const origins = explicitOrigins.length ? explicitOrigins : items.map(deriveOrigin);

  return {
    title: "Processes",
    ok: fs.existsSync(processesPath),
    process_count: items.length,
    process_origins: origins.length,
    origin_source: explicitOrigins.length ? "process_origins.json" : "derived_from_processes",
    processes_path: processesPath,
    process_origins_path: originsPath,
    items,
    origins
  };
}

function collectReceiptFiles() {
  const roots = [
    path.join(RUNTIME_ROOT, "receipts"),
    path.join(RUNTIME_ROOT, "proofs", "receipts"),
    path.join(BUNDLE_ROOT, "receipts"),
    path.join(BUNDLE_ROOT, "proofs", "receipts"),
    path.join(BUNDLE_ROOT, "runtime", "receipts")
  ];

  const out = [];
  const seen = new Set();

  function walk(dir, depth) {
    if (depth > 6) return;
    if (!fs.existsSync(dir)) return;

    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
    catch { return; }

    for (const ent of entries) {
      const full = path.join(dir, ent.name);

      if (ent.isDirectory()) {
        walk(full, depth + 1);
        continue;
      }

      if (!ent.isFile()) continue;
      if (!(full.endsWith(".json") || full.endsWith(".ndjson"))) continue;

      const k = full.toLowerCase();
      if (seen.has(k)) continue;

      seen.add(k);
      out.push(full);
    }
  }

  for (const root of roots) walk(root, 0);
  return out.sort();
}

function readReceiptEntries(limit) {
  const files = collectReceiptFiles();
  const entries = [];

  for (const file of files.slice(-120)) {
    try {
      if (file.endsWith(".json")) {
        entries.push({ file, ...readJson(file, {}) });
      } else {
        const lines = fs.readFileSync(file, "utf8").split(/\r?\n/).filter(Boolean).slice(-25);
        for (const line of lines) {
          try { entries.push({ file, ...JSON.parse(line) }); }
          catch { entries.push({ file, raw: line }); }
        }
      }
    } catch (e) {
      entries.push({ file, error: true, detail: String(e) });
    }
  }

  return entries.slice(-limit);
}

function loadReceipts() {
  const entries = readReceiptEntries(80);
  const files = collectReceiptFiles();

  return {
    title: "Receipts",
    ok: true,
    count: files.length,
    loaded_entries: entries.length,
    entries
  };
}

function normalizeVolumeKey(v) {
  return {
    drive_letter: String(v.drive_letter || ""),
    volume_id: String(v.volume_id || ""),
    filesystem: String(v.filesystem || ""),
    label: String(v.label || ""),
    size: Number(v.size || 0)
  };
}

function routeKeyOf(g) {
  return {
    origin: String(g.origin || "unknown"),
    drive: String(g.drive || "N/A"),
    root_path: String(g.root_path || "N/A")
  };
}

function keyString(x) {
  return stableJson(x);
}

function registryProjection() {
  const machine = loadMachine();
  const drives = loadDrives();
  const processes = loadProcesses();
  const metrics = systemMetrics();

  const volumeKeys = asArray(drives.items).map(normalizeVolumeKey).sort((a, b) => keyString(a).localeCompare(keyString(b)));
  const originGroups = groupOrigins(asArray(processes.items));
  const routeKeys = originGroups.map(routeKeyOf).sort((a, b) => keyString(a).localeCompare(keyString(b)));

  const machineId = machine.machine_id || "unknown-machine";

  const identitySnapshot = {
    machine_id: machineId,
    volumes: volumeKeys,
    route_keys: routeKeys
  };

  const runtimeSnapshot = {
    process_count: processes.process_count,
    origin_group_count: originGroups.length,
    cpu_percent: metrics.cpu_percent,
    memory_percent: metrics.memory_percent,
    observed_utc: metrics.observed_utc
  };

  const identityHash = sha256(identitySnapshot);
  const runtimeHash = sha256({
    process_count: processes.process_count,
    origin_group_count: originGroups.length,
    volume_count: volumeKeys.length
  });

  const now = new Date().toISOString();

  let registry = readJson(REGISTRY_PATH, {
    schema: "watchtower.inspector.machine_registry.v2",
    machines: {}
  });

  if (!registry || typeof registry !== "object" || !registry.machines) {
    registry = { schema: "watchtower.inspector.machine_registry.v2", machines: {} };
  }

  const existing = registry.machines[machineId] || null;
  const structuralChanges = [];
  const runtimeChanges = [];

  if (existing && existing.last_identity_hash && existing.last_identity_hash !== identityHash) {
    const beforeVolumes = new Set(asArray(existing.last_volumes).map((x) => keyString(normalizeVolumeKey(x))));
    const afterVolumes = new Set(volumeKeys.map(keyString));

    for (const v of afterVolumes) {
      if (!beforeVolumes.has(v)) structuralChanges.push({ utc: now, kind: "volume_connected", volume: JSON.parse(v) });
    }

    for (const v of beforeVolumes) {
      if (!afterVolumes.has(v)) structuralChanges.push({ utc: now, kind: "volume_removed", volume: JSON.parse(v) });
    }

    const beforeRoutes = new Set(asArray(existing.last_route_keys).map((x) => keyString(routeKeyOf(x))));
    const afterRoutes = new Set(routeKeys.map(keyString));

    for (const r of afterRoutes) {
      if (!beforeRoutes.has(r)) structuralChanges.push({ utc: now, kind: "route_added", route: JSON.parse(r) });
    }

    for (const r of beforeRoutes) {
      if (!afterRoutes.has(r)) structuralChanges.push({ utc: now, kind: "route_removed", route: JSON.parse(r) });
    }

    if (structuralChanges.length === 0) {
      structuralChanges.push({ utc: now, kind: "identity_hash_changed", previous_hash: existing.last_identity_hash, current_hash: identityHash });
    }
  }

  if (existing && existing.last_runtime_hash && existing.last_runtime_hash !== runtimeHash) {
    runtimeChanges.push({
      utc: now,
      kind: "runtime_changed",
      previous_hash: existing.last_runtime_hash,
      current_hash: runtimeHash,
      process_count: processes.process_count,
      origin_group_count: originGroups.length,
      volume_count: volumeKeys.length
    });
  }

  const previousRecentChanges = asArray(existing?.recent_changes)
    .filter((x) => x && x.kind !== "snapshot_changed" && x.kind !== "runtime_changed")
    .slice(-40);

  const previousRuntimeChanges = asArray(existing?.recent_runtime_changes).slice(-40);

  let returnCount = 1;
  if (existing) {
    const lastSeenMs = Date.parse(existing.last_seen_utc || "");
    const nowMs = Date.parse(now);
    const gapMs = Number.isFinite(lastSeenMs) ? (nowMs - lastSeenMs) : 0;
    returnCount = existing.return_count || 1;
    if (gapMs > 300000) returnCount += 1;
  }

  const record = {
    machine_id: machineId,
    first_seen_utc: existing?.first_seen_utc || now,
    last_seen_utc: now,
    return_count: returnCount,
    status: structuralChanges.length ? "changed" : "known",
    health: "observed",
    last_identity_hash: identityHash,
    previous_identity_hash: existing?.last_identity_hash || "",
    last_runtime_hash: runtimeHash,
    previous_runtime_hash: existing?.last_runtime_hash || "",
    last_volumes: volumeKeys,
    last_route_keys: routeKeys,
    last_process_count: processes.process_count,
    last_origin_group_count: originGroups.length,
    last_metrics: metrics,
    recent_changes: [...previousRecentChanges, ...structuralChanges].slice(-50),
    recent_runtime_changes: [...previousRuntimeChanges, ...runtimeChanges].slice(-50)
  };

  registry.schema = "watchtower.inspector.machine_registry.v2";
  registry.machines[machineId] = record;
  registry.last_observed_machine_id = machineId;
  registry.updated_utc = now;

  writeJson(REGISTRY_PATH, registry);

  return {
    title: "Device Registry",
    registry_path: REGISTRY_PATH,
    record,
    identity_snapshot: identitySnapshot,
    runtime_snapshot: runtimeSnapshot,
    identity_hash: identityHash,
    runtime_hash: runtimeHash,
    changes: structuralChanges,
    runtime_changes: runtimeChanges
  };
}

function performanceProjection() {
  const metrics = systemMetrics();
  const processes = loadProcesses();
  const drives = loadDrives();

  const sample = {
    utc: metrics.observed_utc || new Date().toISOString(),
    cpu_percent: metrics.cpu_percent,
    memory_percent: metrics.memory_percent,
    memory_used: metrics.memory_used,
    memory_total: metrics.memory_total,
    process_count: processes.process_count,
    volume_count: drives.volumes
  };

  ensureDir(path.dirname(PERF_PATH));
  fs.appendFileSync(PERF_PATH, JSON.stringify(sample) + "\n", "utf8");

  let history = [];
  try {
    history = fs.readFileSync(PERF_PATH, "utf8")
      .split(/\r?\n/)
      .filter(Boolean)
      .slice(-120)
      .map((line) => JSON.parse(line));
  } catch {
    history = [sample];
  }

  fs.writeFileSync(PERF_PATH, history.map((x) => JSON.stringify(x)).join("\n") + "\n", "utf8");

  return {
    title: "Performance Board",
    sample,
    history,
    sample_count: history.length,
    performance_path: PERF_PATH
  };
}

function summaryProjection() {
  const machine = loadMachine();
  const drives = loadDrives();
  const processes = loadProcesses();
  const receipts = loadReceipts();
  const registry = registryProjection();
  const metrics = registry.record.last_metrics;

  return {
    title: "Engine Summary",
    health: fs.existsSync(RUNTIME_ROOT) ? "connected" : "runtime_missing",
    runtime_root: RUNTIME_ROOT,
    machine_id: machine.machine_id || "",
    device_status: registry.record.status,
    first_seen_utc: registry.record.first_seen_utc,
    last_seen_utc: registry.record.last_seen_utc,
    return_count: registry.record.return_count,
    snapshot_hash: registry.identity_hash,
    runtime_hash: registry.runtime_hash,
    process_count: processes.process_count,
    engine_receipts: receipts.count,
    engine_events: receipts.count,
    origin_rows: processes.process_origins,
    volumes: drives.volumes,
    cpu_percent: metrics.cpu_percent,
    memory_percent: metrics.memory_percent,
    memory_used: metrics.memory_used,
    memory_total: metrics.memory_total,
    recent_changes: registry.record.recent_changes,
    recent_runtime_changes: registry.record.recent_runtime_changes
  };
}

function originsProjection() {
  const processes = loadProcesses();
  const rows = asArray(processes.origins).length ? asArray(processes.origins) : asArray(processes.items).map(deriveOrigin);

  return {
    title: "Process Origins",
    ok: rows.length > 0,
    origin_source: processes.origin_source,
    groups: groupOrigins(rows),
    rows
  };
}

function exportSessionProjection() {
  const exported_utc = new Date().toISOString();

  const session = {
    schema: "watchtower.inspector.session_export.v1",
    exported_utc,
    runtime_root: RUNTIME_ROOT,
    machine: loadMachine(),
    summary: summaryProjection(),
    performance: performanceProjection(),
    drives: loadDrives(),
    processes: loadProcesses(),
    origins: originsProjection(),
    receipts: loadReceipts(),
    registry: registryProjection()
  };

  const sessionHash = sha256(session);
  const safeStamp = exported_utc.replace(/[:.]/g, "-");
  const filePath = path.join(SESSION_ROOT, "watchtower_session_" + safeStamp + "_" + sessionHash.slice(0, 16) + ".json");

  writeJson(filePath, { ...session, session_hash: sessionHash });

  return {
    title: "Session Export",
    ok: true,
    session_hash: sessionHash,
    session_path: filePath,
    exported_utc,
    process_count: session.processes.process_count,
    volume_count: session.drives.volumes,
    receipt_count: session.receipts.count
  };
}

function sessionHistoryProjection() {
  const exportFolder = inspectorSettings().export_folder || SESSION_ROOT;
  ensureDir(exportFolder);

  let files = [];
  try {
    files = fs.readdirSync(SESSION_ROOT)
      .filter((x) => x.endsWith(".json"))
      .map((x) => path.join(SESSION_ROOT, x))
      .filter((x) => fs.existsSync(x) && fs.statSync(x).isFile())
      .sort();
  } catch {
    files = [];
  }

  const sessions = [];

  for (const file of files.slice(-30).reverse()) {
    const j = readJson(file, {});
    sessions.push({
      exported_utc: j.exported_utc || "",
      session_hash: j.session_hash || "",
      process_count: j.processes?.process_count ?? j.summary?.process_count ?? "",
      volume_count: j.drives?.volumes ?? j.summary?.volumes ?? "",
      receipt_count: j.receipts?.count ?? j.summary?.engine_receipts ?? "",
      file
    });
  }

  return {
    title: "Session History",
    session_root: SESSION_ROOT,
    count: files.length,
    sessions
  };
}

function alertsProjection() {
  const summary = summaryProjection();
  const performance = performanceProjection();
  const history = asArray(performance.history);

  const alerts = [];
  const now = new Date().toISOString();

  const recent = history.slice(-12);
  const highCpu = recent.filter((x) => Number(x.cpu_percent) >= 85).length;
  const highRam = recent.filter((x) => Number(x.memory_percent) >= 85).length;

  if (summary.device_status === "changed") {
    alerts.push({
      utc: now,
      severity: "medium",
      kind: "device_structure_changed",
      message: "Mounted-device or route structure changed.",
      device_hash: summary.snapshot_hash
    });
  }

  for (const change of asArray(summary.recent_changes).slice(-8)) {
    alerts.push({
      utc: change.utc || now,
      severity: "medium",
      kind: change.kind || "structural_change",
      message: "Structural change recorded in device registry.",
      route: change.route || "",
      volume: change.volume || ""
    });
  }

  if (highCpu >= 3) {
    alerts.push({
      utc: now,
      severity: "high",
      kind: "sustained_cpu_pressure",
      message: "CPU stayed above 85 percent for multiple recent samples.",
      sample_hits: highCpu
    });
  }

  if (highRam >= 3) {
    alerts.push({
      utc: now,
      severity: "high",
      kind: "sustained_memory_pressure",
      message: "RAM stayed above 85 percent for multiple recent samples.",
      sample_hits: highRam
    });
  }

  if (Number(summary.volumes || 0) === 0) {
    alerts.push({
      utc: now,
      severity: "high",
      kind: "no_volumes_observed",
      message: "No mounted volumes are visible to WatchTower."
    });
  }

  return {
    title: "WatchTower Alerts",
    ok: true,
    alert_count: alerts.length,
    alerts,
    thresholds: {
      cpu_high_percent: 85,
      memory_high_percent: 85,
      sustained_sample_hits: 3,
      recent_window_samples: 12
    }
  };
}

function inspectorSettings() {
  const defaults = {
    schema: "watchtower.inspector.settings.v1",
    export_folder: SESSION_ROOT,
    export_on_exit: false,
    inventory_default_limit: 5000,
    inventory_hash_files: false,
    inventory_max_bytes_to_hash: 1048576
  };

  const current = readJson(SETTINGS_PATH, defaults);

  return {
    ...defaults,
    ...(current && typeof current === "object" ? current : {})
  };
}

function saveInspectorSettings(next) {
  const settings = {
    ...inspectorSettings(),
    ...(next && typeof next === "object" ? next : {}),
    updated_utc: new Date().toISOString()
  };

  writeJson(SETTINGS_PATH, settings);

  return settings;
}

function safeDecode(value) {
  try {
    return decodeURIComponent(String(value || ""));
  } catch {
    return String(value || "");
  }
}

function parseQuery(urlValue) {
  const out = {};
  const idx = String(urlValue || "").indexOf("?");

  if (idx < 0) return out;

  const qs = String(urlValue).slice(idx + 1);

  for (const part of qs.split("&")) {
    if (!part) continue;

    const eq = part.indexOf("=");
    if (eq < 0) {
      out[safeDecode(part)] = "";
      continue;
    }

    const key = safeDecode(part.slice(0, eq));
    const val = safeDecode(part.slice(eq + 1));

    out[key] = val;
  }

  return out;
}

function routePathOnly(urlValue) {
  return String(urlValue || "").split("?")[0];
}

function isUnsafeInventoryRoot(root) {
  const r = String(root || "").trim().toLowerCase();

  if (!r) return true;
  if (r === "c:\\" || r === "c:/" || r === "c:") return true;
  if (r === "c:\\windows" || r.startsWith("c:\\windows\\")) return true;
  if (r === "c:\\program files" || r.startsWith("c:\\program files\\")) return true;
  if (r === "c:\\program files (x86)" || r.startsWith("c:\\program files (x86)\\")) return true;

  return false;
}

function stableFileId(row) {
  return stableJson({
    rel_path: row.rel_path,
    kind: row.kind,
    size: row.size,
    modified_utc: row.modified_utc
  });
}

function normalizeRootPath(root) {
  let r = String(root || "").trim();

  if (!r) return "";

  r = r.replace(/\//g, "\\");

  if (/^[A-Za-z]:$/.test(r)) {
    r = r + "\\";
  }

  return r;
}

function scanInventoryRoot(rootInput, limitInput) {
  const settings = inspectorSettings();
  const root = normalizeRootPath(rootInput);
  const limitRaw = Number(limitInput || settings.inventory_default_limit || 5000);
  const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(100000, Math.floor(limitRaw))) : 5000;

  if (!root) {
    return {
      ok: false,
      error: "MISSING_ROOT",
      message: "Choose a mounted drive or folder to scan."
    };
  }

  if (isUnsafeInventoryRoot(root)) {
    return {
      ok: false,
      error: "UNSAFE_SCAN_ROOT",
      root,
      message: "Refusing to scan this root by default. Choose a mounted device, project folder, or safer subfolder."
    };
  }

  if (!fs.existsSync(root)) {
    return {
      ok: false,
      error: "ROOT_NOT_FOUND",
      root
    };
  }

  ensureDir(INVENTORY_ROOT);

  const started = new Date().toISOString();
  const rows = [];
  const errors = [];
  const queue = [root];
  const rootLower = root.toLowerCase();

  while (queue.length && rows.length < limit) {
    const dir = queue.shift();

    let entries = [];

    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (e) {
      errors.push({
        path: dir,
        error: "READ_DIR_FAILED",
        detail: String(e).slice(0, 240)
      });
      continue;
    }

    for (const ent of entries) {
      if (rows.length >= limit) break;

      const full = path.join(dir, ent.name);
      let stat = null;

      try {
        stat = fs.statSync(full);
      } catch (e) {
        errors.push({
          path: full,
          error: "STAT_FAILED",
          detail: String(e).slice(0, 240)
        });
        continue;
      }

      const rel = full.toLowerCase().startsWith(rootLower)
        ? full.slice(root.length).replace(/^\\+/, "")
        : full;

      const row = {
        rel_path: rel,
        full_path: full,
        name: ent.name,
        kind: ent.isDirectory() ? "dir" : ent.isFile() ? "file" : "other",
        size: stat.size,
        modified_utc: stat.mtime ? stat.mtime.toISOString() : "",
        created_utc: stat.birthtime ? stat.birthtime.toISOString() : ""
      };

      row.entry_hash = sha256(stableFileId(row));

      rows.push(row);

      if (ent.isDirectory()) {
        queue.push(full);
      }
    }
  }

  const finished = new Date().toISOString();

  const scan = {
    schema: "watchtower.inventory.scan.v1",
    ok: true,
    root,
    started_utc: started,
    finished_utc: finished,
    limit,
    truncated: queue.length > 0 || rows.length >= limit,
    item_count: rows.length,
    error_count: errors.length,
    items: rows,
    errors
  };

  const scanHash = sha256({
    root: scan.root,
    started_utc: scan.started_utc,
    item_count: scan.item_count,
    items: rows.map((x) => ({
      rel_path: x.rel_path,
      kind: x.kind,
      size: x.size,
      modified_utc: x.modified_utc,
      entry_hash: x.entry_hash
    }))
  });

  scan.scan_hash = scanHash;

  const stamp = started.replace(/[:.]/g, "-");
  const file = path.join(INVENTORY_ROOT, "inventory_scan_" + stamp + "_" + scanHash.slice(0, 16) + ".json");

  writeJson(file, scan);

  const index = inventoryIndexProjection();
  const nextIndex = {
    ...index,
    schema: "watchtower.inventory.index.v1",
    inventory_root: INVENTORY_ROOT,
    latest_scan: file,
    latest_scan_hash: scanHash,
    updated_utc: finished
  };

  writeJson(path.join(INVENTORY_ROOT, "inventory_index.json"), nextIndex);

  return {
    title: "Inventory Scan",
    ok: true,
    root,
    scan_hash: scanHash,
    scan_path: file,
    item_count: scan.item_count,
    error_count: scan.error_count,
    truncated: scan.truncated,
    started_utc: started,
    finished_utc: finished
  };
}

function inventoryIndexProjection() {
  ensureDir(INVENTORY_ROOT);

  const indexPath = path.join(INVENTORY_ROOT, "inventory_index.json");
  const index = readJson(indexPath, {
    schema: "watchtower.inventory.index.v1",
    inventory_root: INVENTORY_ROOT,
    latest_scan: "",
    latest_scan_hash: "",
    updated_utc: ""
  });

  let files = [];

  try {
    files = fs.readdirSync(INVENTORY_ROOT)
      .filter((x) => x.startsWith("inventory_scan_") && x.endsWith(".json"))
      .map((x) => path.join(INVENTORY_ROOT, x))
      .sort();
  } catch {
    files = [];
  }

  return {
    ...index,
    inventory_root: INVENTORY_ROOT,
    scan_count: files.length,
    scans: files.slice(-20).reverse().map((file) => {
      const j = readJson(file, {});
      return {
        root: j.root || "",
        started_utc: j.started_utc || "",
        scan_hash: j.scan_hash || "",
        item_count: j.item_count ?? "",
        error_count: j.error_count ?? "",
        truncated: j.truncated ?? "",
        file
      };
    })
  };
}

function inventoryLatestProjection() {
  const index = inventoryIndexProjection();

  if (!index.latest_scan || !fs.existsSync(index.latest_scan)) {
    return {
      title: "Latest Inventory",
      ok: true,
      inventory_root: INVENTORY_ROOT,
      latest_scan: "",
      item_count: 0,
      items: []
    };
  }

  const scan = readJson(index.latest_scan, {});

  return {
    title: "Latest Inventory",
    ok: true,
    inventory_root: INVENTORY_ROOT,
    latest_scan: index.latest_scan,
    latest_scan_hash: index.latest_scan_hash,
    root: scan.root || "",
    item_count: scan.item_count || 0,
    error_count: scan.error_count || 0,
    truncated: scan.truncated || false,
    started_utc: scan.started_utc || "",
    finished_utc: scan.finished_utc || "",
    items: asArray(scan.items).slice(0, 1000),
    errors: asArray(scan.errors).slice(0, 100)
  };
}

function inventoryDiffProjection() {
  const index = inventoryIndexProjection();
  const scans = asArray(index.scans).slice().reverse();

  if (scans.length < 2) {
    return {
      title: "Inventory Diff",
      ok: true,
      message: "At least two scans are needed before WatchTower can diff this device.",
      added: [],
      removed: [],
      changed: []
    };
  }

  const previousMeta = scans[scans.length - 2];
  const currentMeta = scans[scans.length - 1];

  const previous = readJson(previousMeta.file, {});
  const current = readJson(currentMeta.file, {});

  const before = new Map();
  const after = new Map();

  for (const row of asArray(previous.items)) {
    before.set(String(row.rel_path || ""), row);
  }

  for (const row of asArray(current.items)) {
    after.set(String(row.rel_path || ""), row);
  }

  const added = [];
  const removed = [];
  const changed = [];

  for (const [rel, row] of after.entries()) {
    if (!before.has(rel)) {
      added.push(row);
      continue;
    }

    const oldRow = before.get(rel);

    if (
      String(oldRow.entry_hash || "") !== String(row.entry_hash || "") ||
      Number(oldRow.size || 0) !== Number(row.size || 0) ||
      String(oldRow.modified_utc || "") !== String(row.modified_utc || "")
    ) {
      changed.push({
        rel_path: rel,
        before: oldRow,
        after: row
      });
    }
  }

  for (const [rel, row] of before.entries()) {
    if (!after.has(rel)) {
      removed.push(row);
    }
  }

  return {
    title: "Inventory Diff",
    ok: true,
    previous_scan: previousMeta.file,
    current_scan: currentMeta.file,
    previous_hash: previousMeta.scan_hash,
    current_hash: currentMeta.scan_hash,
    added_count: added.length,
    removed_count: removed.length,
    changed_count: changed.length,
    added: added.slice(0, 500),
    removed: removed.slice(0, 500),
    changed: changed.slice(0, 500)
  };
}

function inventoryScanFilesV14() {
  ensureDir(INVENTORY_ROOT);

  try {
    return fs.readdirSync(INVENTORY_ROOT)
      .filter((x) => x.startsWith("inventory_scan_") && x.endsWith(".json"))
      .map((x) => path.join(INVENTORY_ROOT, x))
      .sort();
  } catch {
    return [];
  }
}

function inventoryScanSummaryFromFileV14(file) {
  const j = readJson(file, {});
  return {
    root: j.root || "",
    started_utc: j.started_utc || "",
    finished_utc: j.finished_utc || "",
    scan_hash: j.scan_hash || "",
    item_count: j.item_count ?? 0,
    error_count: j.error_count ?? 0,
    truncated: j.truncated === true,
    file
  };
}

function inventoryRootRegistryProjection() {
  ensureDir(INVENTORY_ROOT);

  const files = inventoryScanFilesV14();
  const byRoot = new Map();

  for (const file of files) {
    const s = inventoryScanSummaryFromFileV14(file);
    if (!s.root) continue;

    const key = String(s.root).toUpperCase();
    if (!byRoot.has(key)) byRoot.set(key, []);
    byRoot.get(key).push(s);
  }

  const roots = [];

  for (const [key, scans] of byRoot.entries()) {
    scans.sort((a, b) => {
      const at = String(a.started_utc || "");
      const bt = String(b.started_utc || "");
      if (at < bt) return -1;
      if (at > bt) return 1;
      return String(a.file).localeCompare(String(b.file));
    });

    const latest = scans[scans.length - 1] || null;
    const previous = scans.length >= 2 ? scans[scans.length - 2] : null;

    roots.push({
      root: latest ? latest.root : key,
      scan_count: scans.length,
      latest_scan: latest ? latest.file : "",
      previous_scan: previous ? previous.file : "",
      latest_hash: latest ? latest.scan_hash : "",
      previous_hash: previous ? previous.scan_hash : "",
      item_count: latest ? latest.item_count : 0,
      error_count: latest ? latest.error_count : 0,
      truncated: latest ? latest.truncated : false,
      last_scanned_utc: latest ? latest.finished_utc || latest.started_utc : "",
      previous_scanned_utc: previous ? previous.finished_utc || previous.started_utc : ""
    });
  }

  roots.sort((a, b) => String(a.root).localeCompare(String(b.root)));

  return {
    title: "Inventory by Device",
    ok: true,
    inventory_root: INVENTORY_ROOT,
    root_count: roots.length,
    scan_count: files.length,
    roots
  };
}

function diffTwoInventoryScansV14(previousFile, currentFile) {
  const previous = readJson(previousFile, {});
  const current = readJson(currentFile, {});

  const before = new Map();
  const after = new Map();

  for (const row of Array.isArray(previous.items) ? previous.items : []) {
    before.set(String(row.rel_path || ""), row);
  }

  for (const row of Array.isArray(current.items) ? current.items : []) {
    after.set(String(row.rel_path || ""), row);
  }

  const added = [];
  const removed = [];
  const changed = [];

  for (const [rel, row] of after.entries()) {
    if (!before.has(rel)) {
      added.push(row);
      continue;
    }

    const oldRow = before.get(rel);

    if (
      String(oldRow.entry_hash || "") !== String(row.entry_hash || "") ||
      Number(oldRow.size || 0) !== Number(row.size || 0) ||
      String(oldRow.modified_utc || "") !== String(row.modified_utc || "")
    ) {
      changed.push({
        rel_path: rel,
        before: oldRow,
        after: row
      });
    }
  }

  for (const [rel, row] of before.entries()) {
    if (!after.has(rel)) {
      removed.push(row);
    }
  }

  return {
    added_count: added.length,
    removed_count: removed.length,
    changed_count: changed.length,
    added: added.slice(0, 500),
    removed: removed.slice(0, 500),
    changed: changed.slice(0, 500)
  };
}

function inventoryRootDiffProjection(rootFilter) {
  const registry = inventoryRootRegistryProjection();
  const wanted = String(rootFilter || "").trim().toUpperCase();

  const roots = registry.roots
    .filter((r) => !wanted || String(r.root || "").toUpperCase() === wanted)
    .map((r) => {
      if (!r.latest_scan || !r.previous_scan) {
        return {
          root: r.root,
          ok: true,
          ready: false,
          message: "At least two scans are needed for this root before WatchTower can diff it.",
          latest_scan: r.latest_scan,
          previous_scan: r.previous_scan,
          latest_hash: r.latest_hash,
          previous_hash: r.previous_hash,
          added_count: 0,
          removed_count: 0,
          changed_count: 0,
          added: [],
          removed: [],
          changed: []
        };
      }

      const d = diffTwoInventoryScansV14(r.previous_scan, r.latest_scan);

      return {
        root: r.root,
        ok: true,
        ready: true,
        latest_scan: r.latest_scan,
        previous_scan: r.previous_scan,
        latest_hash: r.latest_hash,
        previous_hash: r.previous_hash,
        ...d
      };
    });

  return {
    title: "Inventory Diff by Device",
    ok: true,
    inventory_root: INVENTORY_ROOT,
    root_count: roots.length,
    roots
  };
}

function inventoryRootLatestProjection(rootFilter) {
  const wanted = String(rootFilter || "").trim().toUpperCase();
  const registry = inventoryRootRegistryProjection();

  if (!wanted) {
    return {
      title: "Selected Root Inventory",
      ok: false,
      error: "MISSING_ROOT",
      message: "Choose a mounted root first.",
      items: []
    };
  }

  const root = registry.roots.find((r) => String(r.root || "").toUpperCase() === wanted);

  if (!root || !root.latest_scan || !fs.existsSync(root.latest_scan)) {
    return {
      title: "Selected Root Inventory",
      ok: true,
      root: root ? root.root : rootFilter,
      message: "No scan has been saved for this root yet.",
      item_count: 0,
      items: []
    };
  }

  const scan = readJson(root.latest_scan, {});

  return {
    title: "Selected Root Inventory",
    ok: true,
    inventory_root: INVENTORY_ROOT,
    root: scan.root || root.root,
    latest_scan: root.latest_scan,
    latest_scan_hash: root.latest_hash,
    previous_scan: root.previous_scan || "",
    previous_hash: root.previous_hash || "",
    scan_count: root.scan_count || 0,
    item_count: scan.item_count || 0,
    error_count: scan.error_count || 0,
    truncated: scan.truncated === true,
    started_utc: scan.started_utc || "",
    finished_utc: scan.finished_utc || "",
    items: Array.isArray(scan.items) ? scan.items.slice(0, 1000) : [],
    errors: Array.isArray(scan.errors) ? scan.errors.slice(0, 100) : []
  };
}
const server = http.createServer((req, res) => {
  const url = req.url || "/";
  const cleanUrl = routePathOnly(url);
  const query = parseQuery(url);

  if (cleanUrl === "/health") {
    return json(res, ok(url, {
      bridge: "watchtower_performance_session_v11",
      port: PORT,
      runtime_root: RUNTIME_ROOT,
      registry_path: REGISTRY_PATH,
      performance_path: PERF_PATH,
      session_root: SESSION_ROOT
    }));
  }

  if (cleanUrl === "/engine/summary") return json(res, ok(cleanUrl, summaryProjection()));
  if (cleanUrl === "/engine/performance") return json(res, ok(cleanUrl, performanceProjection()));
  if (cleanUrl === "/engine/export-session") return json(res, ok(cleanUrl, exportSessionProjection()));
  if (cleanUrl === "/engine/session-history") return json(res, ok(cleanUrl, sessionHistoryProjection()));
  if (cleanUrl === "/engine/alerts") return json(res, ok(cleanUrl, alertsProjection()));
  if (cleanUrl === "/engine/observe-machine") return json(res, ok(cleanUrl, loadMachine()));
  if (cleanUrl === "/engine/observe-drives") return json(res, ok(cleanUrl, loadDrives()));
  if (cleanUrl === "/engine/observe-processes") return json(res, ok(cleanUrl, loadProcesses()));
  if (cleanUrl === "/engine/process-origins") return json(res, ok(cleanUrl, originsProjection()));
  if (cleanUrl === "/engine/receipts") return json(res, ok(cleanUrl, loadReceipts()));

  if (cleanUrl === "/engine/settings") return json(res, ok(cleanUrl, inspectorSettings()));
  if (cleanUrl === "/engine/set-export-folder") return json(res, ok(cleanUrl, saveInspectorSettings({ export_folder: query.path || SESSION_ROOT })));
  if (cleanUrl === "/engine/set-export-on-exit") return json(res, ok(cleanUrl, saveInspectorSettings({ export_on_exit: String(query.enabled || "").toLowerCase() === "true" })));
  if (cleanUrl === "/engine/inventory-index") return json(res, ok(cleanUrl, inventoryIndexProjection()));
  if (cleanUrl === "/engine/inventory-latest") return json(res, ok(cleanUrl, inventoryLatestProjection()));
  if (cleanUrl === "/engine/inventory-diff") return json(res, ok(cleanUrl, inventoryDiffProjection()));
  if (cleanUrl === "/engine/inventory-scan") return json(res, ok(cleanUrl, scanInventoryRoot(query.root || "", query.limit || "")));
    if (cleanUrl === "/engine/inventory-root-registry") return json(res, ok(cleanUrl, inventoryRootRegistryProjection()));
  if (cleanUrl === "/engine/inventory-root-diff") return json(res, ok(cleanUrl, inventoryRootDiffProjection(query.root || "")));
    if (cleanUrl === "/engine/inventory-root-latest") return json(res, ok(cleanUrl, inventoryRootLatestProjection(query.root || "")));
  return json(res, { ok: false, ts: Date.now(), path: cleanUrl, error: "UNKNOWN_ROUTE" });
});

server.listen(PORT, HOST, () => {
  console.log("WATCHTOWER_PERFORMANCE_SESSION_V11_OK http://" + HOST + ":" + PORT);
  console.log("RUNTIME_ROOT=" + RUNTIME_ROOT);
  console.log("REGISTRY_PATH=" + REGISTRY_PATH);
  console.log("PERFORMANCE_PATH=" + PERF_PATH);
  console.log("SESSION_ROOT=" + SESSION_ROOT);
});
