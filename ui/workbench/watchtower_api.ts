const API = "http://127.0.0.1:3187";

async function get(path: string) {
  const r = await fetch(`${API}${path}`);
  const j = await r.json();

  if (!j.ok) {
    return { error: true, path };
  }

  return j.data;
}

export const WatchTowerAPI = {
  summary: () => get("/engine/summary"),
  machine: () => get("/engine/summary"),
  drives: () => get("/engine/observe-drives"),
  processes: () => get("/engine/observe-processes"),
  origins: () => get("/engine/process-origins"),
  receipts: () => get("/engine/receipts"),
};
