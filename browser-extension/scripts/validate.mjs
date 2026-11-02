import { readFile, readdir } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(await readFile(join(root, "manifest.json"), "utf8"));
if (manifest.manifest_version !== 3) throw new Error("manifest must be v3");
if (!manifest.background?.service_worker) throw new Error("service worker missing");

const rules = JSON.parse(await readFile(join(root, "rules/default-rules.json"), "utf8"));
const ids = new Set();
for (const rule of rules) {
  if (ids.has(rule.id)) throw new Error(`duplicate rule id ${rule.id}`);
  ids.add(rule.id);
  if (rule.action?.type !== "block") throw new Error(`rule ${rule.id} is not blocking`);
  if (!rule.condition?.requestDomains?.length) throw new Error(`rule ${rule.id} has no domains`);
}

const scripts = ["background.js", "content/search-guard.js", "popup/popup.js"];
for (const script of scripts) {
  const check = spawnSync(process.execPath, ["--check", join(root, script)], { encoding: "utf8" });
  if (check.status !== 0) throw new Error(`${script}: ${check.stderr}`);
}

// Catch accidental remote scripts or styles; extension code must stay local.
const html = await readFile(join(root, "popup/popup.html"), "utf8");
if (/<(script|link)[^>]+https?:\/\//i.test(html)) throw new Error("remote UI asset found");

console.log(`Blue Search Guard valid: ${rules.length} static rules, ${scripts.length} scripts checked`);
