import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { runInNewContext } from "node:vm";

const root = new URL("../popup/", import.meta.url);
const [source, html, css] = await Promise.all(["popup.js", "popup.html", "popup.css"].map((file) => readFile(new URL(file, root), "utf8")));
const switches = ["enabled", "cleanSponsored", "stripTracking", "warnBlocked", "safeSearch"];
const settle = () => new Promise(setImmediate);

async function popup(options = {}) {
  const document = { body: {}, activeElement: null };
  document.activeElement = document.body;
  class Control {
    constructor(tag, attributes) {
      this.tagName = tag;
      this.attributes = new Map([...attributes.matchAll(/([\w-]+)="([^"]*)"/g)].map((match) => [match[1], match[2]]));
      this.className = this.attributes.get("class") || "";
      this.dataset = {};
      this.hidden = /\shidden(?:\s|$)/.test(attributes);
      this.disabled = /\sdisabled(?:\s|$)/.test(attributes);
      this.checked = false;
      this.value = "";
      this.listeners = new Map();
      this.classList = { toggle: (name, enabled) => {
        const classes = new Set(this.className.split(/\s+/).filter(Boolean));
        if (enabled) classes.add(name); else classes.delete(name);
        this.className = [...classes].join(" ");
      } };
    }
    set disabled(value) {
      this.isDisabled = value;
      if (value && document.activeElement === this) document.activeElement = document.body;
    }
    get disabled() { return this.isDisabled; }
    setAttribute(name, value) { this.attributes.set(name, String(value)); }
    getAttribute(name) { return this.attributes.get(name) ?? null; }
    removeAttribute(name) { this.attributes.delete(name); }
    addEventListener(type, listener) { this.listeners.set(type, listener); }
    focus() { if (!this.disabled) document.activeElement = this; }
  }
  const controls = new Map([...html.matchAll(/<(\w+)\b([^>]*\bid="([^"]+)"[^>]*)>/g)].map((match) => [match[3], new Control(match[1], match[2])]));
  const get = (id) => controls.get(id);
  document.getElementById = get;
  get("search-provider").options = [...html.matchAll(/<option value="([^"]+)"/g)].map((match) => ({ value: match[1] }));
  const stored = structuredClone(options.settings || {});
  const calls = { messages: [], writes: [], stats: [] };
  let closed = false;
  const api = options.api === null ? undefined : {
    storage: { local: {
      get: async (defaults) => {
        if (options.readError) throw new Error("Storage unavailable");
        return Object.fromEntries(Object.entries(defaults).map(([key, value]) => [key, key in stored ? stored[key] : value]));
      },
      set: async (value) => {
        calls.writes.push(structuredClone(value));
        if (options.writeError) throw new Error("Write denied");
        if (options.save) await options.save();
        Object.assign(stored, structuredClone(value));
      }
    } },
    runtime: options.messaging === false ? undefined : { sendMessage: async (message) => {
      calls.messages.push(structuredClone(message));
      if (options.message) return options.message(message, calls.messages.length);
      return message.type === "blue:search" ? { ok: true } : { ok: false, connected: false, error: "No native host" };
    } },
    tabs: {
      query: async () => [{ id: 7, url: options.url || "https://news.example.com/search" }],
      sendMessage: async (id, message) => {
        calls.stats.push({ id, message: structuredClone(message) });
        if (!options.stats) throw new Error("No content script");
        return options.stats;
      }
    }
  };
  runInNewContext(source, { document, [options.namespace || "browser"]: api, URL, Intl, window: { close: () => { closed = true; } } });
  await settle();
  return { get, stored, calls, document, closed: () => closed, fire: async (id, type) => {
    await get(id).listeners.get(type)({ target: get(id), preventDefault() {} });
    await settle();
  } };
}

test("unavailable browser APIs leave mutation, search and bridge actions disabled", async () => {
  const ui = await popup({ api: null });
  for (const id of [...switches, "allow-site", "block-site", "search-provider", "search-query", "search-submit", "refresh-native"]) {
    assert.equal(ui.get(id).disabled, true, id);
  }
  assert.equal(ui.get("protection-label").textContent, "Settings unavailable");
  assert.equal(ui.get("popup-message").dataset.tone, "error");
  assert.equal(ui.get("desktop-state").textContent, "Bridge unavailable");
  assert.equal(ui.get("desktop-records").hidden, true);
  assert.equal(ui.get("page-stats").hidden, true);
});

test("missing messaging does not disable independent browser preferences", async () => {
  const ui = await popup({ messaging: false });
  assert.equal(ui.get("enabled").disabled, false);
  assert.equal(ui.get("search-provider").disabled, false);
  for (const id of ["search-query", "search-submit", "refresh-native"]) assert.equal(ui.get(id).disabled, true, id);
  assert.match(ui.get("search-message").textContent, /messaging.*unavailable/i);
  assert.equal(ui.calls.messages.length, 0);
});

test("current-site rules match background normalization and inherited allow precedence", async () => {
  const ui = await popup({ settings: { allowedDomains: [" HTTPS://WWW.Example.COM/list "], blockedDomains: ["news.example.com"] } });
  assert.equal(ui.get("site-rule").textContent, "Allow rule");
  assert.equal(ui.get("allow-site").getAttribute("aria-pressed"), "true");
  assert.equal(ui.get("block-site").getAttribute("aria-pressed"), "false");
  assert.match(ui.get("site-detail").textContent, /inherited from example.com/);
  await ui.fire("block-site", "click");
  assert.deepEqual(ui.stored.allowedDomains, ["example.com"]);
  assert.deepEqual(ui.stored.blockedDomains, ["news.example.com"]);
  assert.match(ui.get("popup-message").textContent, /allow rule for example.com still takes precedence/);
});

test("settings failures and non-web tabs cannot write a site rule", async () => {
  for (const options of [{ readError: true }, { url: "chrome://newtab/" }]) {
    const ui = await popup(options);
    assert.equal(ui.get("allow-site").disabled, true);
    assert.equal(ui.get("block-site").disabled, true);
    await ui.fire("allow-site", "click");
    assert.equal(ui.calls.writes.length, 0);
  }
});

test("failed preference, provider and site saves keep previous state", async () => {
  const ui = await popup({ writeError: true, settings: { allowedDomains: ["news.example.com"] } });
  ui.get("enabled").checked = false;
  await ui.fire("enabled", "change");
  assert.equal(ui.get("enabled").checked, true);
  assert.equal(ui.get("protection-label").textContent, "Enabled in settings");
  ui.get("search-provider").value = "brave";
  await ui.fire("search-provider", "change");
  assert.equal(ui.get("search-provider").value, "duckduckgo");
  await ui.fire("block-site", "click");
  assert.equal(ui.get("site-rule").textContent, "Allow rule");
  assert.equal(ui.get("allow-site").getAttribute("aria-pressed"), "true");
  assert.equal(ui.get("popup-message").dataset.tone, "error");
  assert.equal(ui.get("search-message").dataset.tone, "error");
});

test("async actions restore keyboard focus without stealing focus moved elsewhere", async () => {
  const ui = await popup({ message: () => ({ ok: false, connected: false }) });
  ui.get("enabled").checked = false;
  ui.get("search-provider").value = "brave";
  ui.get("search-query").value = "blue";
  for (const [id, type] of [["enabled", "change"], ["search-provider", "change"], ["block-site", "click"], ["refresh-native", "click"], ["search-submit", "submit"]]) {
    ui.get(id).focus();
    await ui.fire(id === "search-submit" ? "search-form" : id, type);
    assert.equal(ui.document.activeElement === ui.get(id), true, `Focus restored to ${id}`);
  }
  let complete;
  const pendingSave = new Promise((resolve) => { complete = resolve; });
  const pending = await popup({ save: () => pendingSave });
  pending.get("enabled").focus();
  pending.get("enabled").checked = false;
  const save = pending.fire("enabled", "change");
  assert.equal(pending.get("enabled").disabled, true);
  pending.get("search-query").focus();
  complete();
  await save;
  assert.equal(pending.document.activeElement, pending.get("search-query"));
});

test("desktop checks are manual read-only snapshots and discard stale or invalid counts", async () => {
  const ui = await popup({ namespace: "chrome", message: (_, call) => call === 1
    ? { ok: true, connected: true, counts: { artifacts: 0, findings: 2, quarantined: -1, blocked: "3" }, active_feeds: [] }
    : { ok: false, connected: false } });
  assert.equal(ui.calls.messages.length, 1);
  assert.equal(ui.get("desktop-state").textContent, "Bridge available");
  assert.equal(ui.get("native-artifacts").textContent, "0");
  assert.equal(ui.get("native-quarantined").textContent, "—");
  assert.equal(ui.get("native-blocked").textContent, "—");
  assert.equal(ui.get("desktop-records").hidden, false);
  await ui.fire("refresh-native", "click");
  assert.deepEqual(ui.calls.messages, [{ type: "blue:native-status" }, { type: "blue:native-status" }]);
  assert.equal(ui.calls.writes.length, 0);
  assert.equal(ui.get("desktop-records").hidden, true);
  assert.equal(ui.get("native-findings").textContent, "—");
  assert.equal(ui.get("refresh-native").disabled, false);
  assert.match(html, /A reply does not verify an open desktop window or active protection/);
});

test("page snapshots accept zero counts and failed search preserves the query", async () => {
  const ui = await popup({ stats: { removed: 0, cleanedLinks: 2, warnedLinks: -1 }, message: () => ({ ok: false }) });
  assert.equal(ui.get("page-stats").hidden, false);
  assert.equal(ui.get("removed").textContent, "0");
  assert.equal(ui.get("warned").textContent, "—");
  ui.get("search-query").value = "  blue search  ";
  await ui.fire("search-form", "submit");
  assert.equal(ui.closed(), false);
  assert.equal(ui.get("search-query").value, "  blue search  ");
  assert.equal(ui.get("search-submit").disabled, false);
  assert.equal(ui.get("search-form").getAttribute("aria-busy"), null);
  assert.deepEqual(ui.calls.messages.at(-1), { type: "blue:search", query: "blue search", provider: "duckduckgo" });
  assert.equal(ui.calls.stats.length, 1);
});

test("accessibility markup and CSS retain native switches, stable names and narrow/reduced-motion fallbacks", () => {
  for (const id of switches) assert.match(html, new RegExp(`<input id="${id}"[^>]*type="checkbox"[^>]*role="switch"`));
  assert.ok(/id="enabled"[^>]*aria-labelledby="protection-title"/.test(html), "Master switch has a stable accessible name");
  assert.ok(/id="protection-title"[^>]*>Browser protection<\/span>/.test(html));
  assert.match(css, /:focus-visible\s*\{[^}]*outline:/);
  assert.match(css, /max-inline-size:\s*100vw/);
  assert.ok(/\.stats dd\s*\{[^}]*overflow-wrap:\s*anywhere/.test(css), "Page counts can wrap in a narrow popup");
  assert.ok(/\.native-counts dd\s*\{[^}]*overflow-wrap:\s*anywhere/.test(css), "Desktop counts can wrap in a narrow popup");
  assert.match(css, /@media\s*\(prefers-reduced-motion:\s*reduce\)\s*\{[^}]*transition:\s*none\s*!important/);
});
