import { readFile, readdir } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { createHash, createPublicKey } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(await readFile(join(root, "manifest.json"), "utf8"));
if (manifest.manifest_version !== 3) throw new Error("manifest must be v3");
if (!manifest.background?.service_worker) throw new Error("service worker missing");
if (!manifest.permissions?.includes("nativeMessaging")) throw new Error("nativeMessaging permission missing");

if (typeof manifest.key !== "string" || /BEGIN (?:RSA )?PRIVATE KEY/.test(manifest.key)) {
  throw new Error("manifest key must contain only the base64 DER public key");
}
const publicKey = Buffer.from(manifest.key, "base64");
if (publicKey.length < 128 || publicKey.toString("base64") !== manifest.key) {
  throw new Error("manifest key is not canonical base64 DER");
}
createPublicKey({ key: publicKey, format: "der", type: "spki" });
const idHex = createHash("sha256").update(publicKey).digest("hex").slice(0, 32);
const computedId = [...idHex]
  .map((digit) => String.fromCharCode("a".charCodeAt(0) + Number.parseInt(digit, 16)))
  .join("");
const recordedId = (await readFile(join(root, "EXTENSION_ID"), "utf8")).trim();
if (computedId !== recordedId) {
  throw new Error(`stable extension ID mismatch: expected ${computedId}, found ${recordedId}`);
}

const rules = JSON.parse(await readFile(join(root, "rules/default-rules.json"), "utf8"));
const ids = new Set();
for (const rule of rules) {
  if (ids.has(rule.id)) throw new Error(`duplicate rule id ${rule.id}`);
  ids.add(rule.id);
  if (rule.action?.type !== "block") throw new Error(`rule ${rule.id} is not blocking`);
  if (!rule.condition?.requestDomains?.length) throw new Error(`rule ${rule.id} has no domains`);
}
if (rules.length > 5000) throw new Error("static DNR ruleset is too large; full feeds belong in DNS/native checks");

const scripts = ["background.js", "content/search-guard.js", "popup/popup.js"];
for (const script of scripts) {
  const check = spawnSync(process.execPath, ["--check", join(root, script)], { encoding: "utf8" });
  if (check.status !== 0) throw new Error(`${script}: ${check.stderr}`);
}

// Catch accidental remote scripts or styles; extension code must stay local.
const html = await readFile(join(root, "popup/popup.html"), "utf8");
if (/<(script|link)[^>]+https?:\/\//i.test(html)) throw new Error("remote UI asset found");
if (!/Desktop:\s*<b id="desktop-state">/.test(html)) throw new Error("desktop connection state is not visible");

const background = await readFile(join(root, "background.js"), "utf8");
if (!background.includes('"com.epimetheus.blue"') || !background.includes("sendNativeMessage")) {
  throw new Error("native host relay is missing");
}
const content = await readFile(join(root, "content/search-guard.js"), "utf8");
if (!content.includes("NATIVE_BATCH_SIZE = 200") || !content.includes('type: "blue:check-domains"')) {
  throw new Error("batched native domain checks are missing");
}

async function findPrivateKeys(directory) {
  const found = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) found.push(...(await findPrivateKeys(path)));
    if (entry.isFile() && /\.(?:pem|key)$/i.test(entry.name)) found.push(path);
  }
  return found;
}
const privateKeyFiles = await findPrivateKeys(root);
if (privateKeyFiles.length) throw new Error(`private/key material file found: ${privateKeyFiles.join(", ")}`);

console.log(`Blue Search Guard valid: ${rules.length} static rules, ${scripts.length} scripts checked, ID ${recordedId}`);
