const API_BASES = [
  "http://127.0.0.1:43187",
  "http://localhost:43187"
];

async function get(path: string) {
  const errors: string[] = [];

  for (const base of API_BASES) {
    try {
      const r = await fetch(`${base}${path}`, {
        method: "GET",
        cache: "no-store",
        headers: {
          "Accept": "application/json",
          "Cache-Control": "no-cache"
        }
      });

      const text = await r.text();
      const j = JSON.parse(text);

      if (!r.ok) {
        errors.push(`${base}${path} HTTP_${r.status}`);
        continue;
      }

      if (j && j.ok === true && Object.prototype.hasOwnProperty.call(j, "data")) {
        return j.data;
      }

      return j;
    } catch (e) {
      errors.push(`${base}${path} ${String(e)}`);
    }
  }

  return {
    error: true,
    path,
    message: "BRIDGE_FETCH_FAILED",
    tried: API_BASES,
    errors
  };
}

export const WatchTowerAPI = {
  health: () => get("/health"),

  summary: () => get("/engine/summary"),
  performance: () => get("/engine/performance"),
  exportSession: () => get("/engine/export-session"),
  sessionHistory: () => get("/engine/session-history"),
  alerts: () => get("/engine/alerts"),

  machine: () => get("/engine/observe-machine"),
  drives: () => get("/engine/observe-drives"),
  processes: () => get("/engine/observe-processes"),
  origins: () => get("/engine/process-origins"),
  receipts: () => get("/engine/receipts"),

  settings: () => get("/engine/settings"),
  setExportFolder: (path: string) => get(`/engine/set-export-folder?path=${encodeURIComponent(path)}`),
  setExportOnExit: (enabled: boolean) => get(`/engine/set-export-on-exit?enabled=${encodeURIComponent(String(enabled))}`),

  inventoryIndex: () => get("/engine/inventory-index"),
  inventoryLatest: () => get("/engine/inventory-latest"),
  inventoryDiff: () => get("/engine/inventory-diff"),
  inventoryScan: (root: string, limit: number) => get(`/engine/inventory-scan?root=${encodeURIComponent(root)}&limit=${encodeURIComponent(String(limit))}`),

  inventoryRootRegistry: () => get("/engine/inventory-root-registry"),
  inventoryRootDiff: (root?: string) => get(`/engine/inventory-root-diff${root ? `?root=${encodeURIComponent(root)}` : ""}`),
  inventoryRootLatest: (root: string) => get(`/engine/inventory-root-latest?root=${encodeURIComponent(root)}`)
};
