const API = "http://localhost:3187";

async function get(path: string) {
  const res = await fetch(`${API}${path}`);
  if (!res.ok) throw new Error(`WATCHTOWER_FETCH_FAIL: ${path}`);
  return res.json();
}

export const WatchTowerAPI = {
  summary: () => get("/engine/summary"),
  devices: () => get("/engine/observe-machine"),
  drives: () => get("/engine/observe-drives"),
  processes: () => get("/engine/observe-processes"),
  processOrigins: () => get("/engine/process-origins"),
  receipts: () => get("/engine/receipts"),
};