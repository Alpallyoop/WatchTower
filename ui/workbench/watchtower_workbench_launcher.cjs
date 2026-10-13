const { spawn } = require("child_process");
const http = require("http");

const root = process.cwd();

function log(msg) {
  console.log("[watchtower-launcher] " + msg);
}

function requestJson(pathname) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: "127.0.0.1",
      port: 43187,
      path: pathname,
      method: "GET",
      timeout: 2000
    }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => body += chunk);
      res.on("end", () => {
        try {
          resolve(JSON.parse(body));
        } catch (e) {
          reject(new Error("BAD_JSON: " + String(e)));
        }
      });
    });

    req.on("timeout", () => req.destroy(new Error("REQUEST_TIMEOUT")));
    req.on("error", reject);
    req.end();
  });
}

async function waitForBridgeHealth() {
  const started = Date.now();
  let last = "";

  while (Date.now() - started < 15000) {
    try {
      const health = await requestJson("/health");

      if (health && health.ok === true && health.data) {
        log("BRIDGE_HEALTH_READY");
        log("RUNTIME_ROOT=" + String(health.data.runtime_root || "unknown"));
        log("REGISTRY_PATH=" + String(health.data.registry_path || "unknown"));
        return;
      }

      last = JSON.stringify(health).slice(0, 700);
    } catch (e) {
      last = String(e);
    }

    await new Promise((resolve) => setTimeout(resolve, 400));
  }

  throw new Error("BRIDGE_HEALTH_NOT_READY: " + last);
}

function spawnCmd(command, name) {
  const child = process.platform === "win32"
    ? spawn("cmd.exe", ["/d", "/s", "/c", command], { cwd: root, stdio: "inherit", windowsHide: false })
    : spawn("sh", ["-lc", command], { cwd: root, stdio: "inherit" });

  child.on("error", (err) => {
    log(name + "_SPAWN_ERROR " + String(err));
  });

  child.on("exit", (code, signal) => {
    log(name + "_EXIT code=" + code + " signal=" + signal);
  });

  return child;
}

async function main() {
  log("START");
  log("root=" + root);

  const bridge = spawnCmd("node workbench\\watchtower_bridge_server.cjs", "bridge");

  try {
    await waitForBridgeHealth();
  } catch (e) {
    try { bridge.kill(); } catch {}
    console.error("[watchtower-launcher] " + String(e));
    process.exit(1);
  }

  log("STARTING_TAURI");
  const tauri = spawnCmd("npm run tauri dev", "tauri");

  function shutdown() {
    try { tauri.kill(); } catch {}
    try { bridge.kill(); } catch {}
  }

  process.on("SIGINT", () => {
    shutdown();
    process.exit(0);
  });

  process.on("SIGTERM", () => {
    shutdown();
    process.exit(0);
  });
}

main().catch((e) => {
  console.error("[watchtower-launcher] FATAL " + String(e));
  process.exit(1);
});
