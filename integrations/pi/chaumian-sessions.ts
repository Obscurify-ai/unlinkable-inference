// pi extension: adds "obscurify-private", the models and key of your "obscurify"
// provider in models.json, sent through the local chaumian-sessions proxy. The normal provider stays
// as it is; pick either with /model.
//
// Install: copy to ~/.pi/agent/extensions/ (needs `chaumian-sessions` on PATH, or
// CHAUMIAN_BIN). The proxy is started if it is not already running and keeps
// running after pi exits, so open sessions close on their own when idle.
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

const URL = process.env.CHAUMIAN_URL ?? "http://127.0.0.1:8899";
const up = () =>
  fetch(`${URL}/_chaumian/status`).then((r) => r.ok, () => false);

export default function (pi: ExtensionAPI) {
  const dir = process.env.PI_CODING_AGENT_DIR ?? `${homedir()}/.pi/agent`;
  let normal: any;
  try {
    normal = JSON.parse(readFileSync(`${dir}/models.json`, "utf8")).providers?.obscurify;
  } catch {}
  if (!normal) return;
  pi.registerProvider("obscurify-private", {
    ...normal,
    name: "Obscurify (private)",
    baseUrl: `${URL}/v1`,
  });

  pi.on("session_start", async () => {
    if (await up()) return;
    spawn(process.env.CHAUMIAN_BIN ?? "chaumian-sessions", ["serve"], {
      detached: true,
      stdio: "ignore",
    })
      .on("error", () => {})
      .unref();
  });
}
