import React from "react";
import ReactDOM from "react-dom/client";
import WatchTowerWorkbench from "./workbench/watchtower_ui_workbench_shell";
import "./workbench/watchtower_inspector.css";

const root = document.getElementById("root");
if (!root) throw new Error("WATCHTOWER_ROOT_ELEMENT_MISSING");

ReactDOM.createRoot(root).render(
  <React.StrictMode>
    <WatchTowerWorkbench />
  </React.StrictMode>
);
