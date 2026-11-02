/* Epimetheus Blue Search Guard — background service worker.
 * No remote code, analytics, or network calls. Settings stay in the profile. */

const api = globalThis.browser ?? globalThis.chrome;
const NATIVE_HOST = "com.epimetheus.blue";
let nativeSequence = 0;

const DEFAULTS = Object.freeze({
  enabled: true,
  cleanSponsored: true,
  stripTracking: true,
  warnBlocked: true,
  safeSearch: true,
  searchProvider: "duckduckgo",
  blockedDomains: [],
  allowedDomains: []
});

const RESOURCE_TYPES = [
  "main_frame", "sub_frame", "stylesheet", "script", "image", "font",
  "object", "xmlhttprequest", "ping", "media", "websocket", "other"
];

async function settings() {
  return { ...DEFAULTS, ...(await api.storage.local.get(DEFAULTS)) };
}

/**
 * Send one read-only request to the desktop app. Chromium starts the native
 * host for sendNativeMessage, so callers are responsible for batching rather
 * than issuing one request per link.
 */
async function nativeRequest(message) {
  const id = message.id ?? `${Date.now()}-${++nativeSequence}`;
  try {
    const response = await api.runtime.sendNativeMessage(
      NATIVE_HOST,
      { ...message, id }
    );
    if (!response || typeof response !== "object") {
      throw new Error("native host returned no response");
    }
    return response;
  } catch (error) {
    return {
      id,
      ok: false,
      connected: false,
      error: `Desktop app is not connected: ${error?.message || String(error)}`
    };
  }
}

function normalizedDomain(value) {
  return String(value || "")
    .toLowerCase()
    .trim()
    .replace(/^https?:\/\//, "")
    .split("/")[0]
    .replace(/^www\./, "")
    .replace(/\.$/, "");
}

async function rebuildDynamicRules() {
  const state = await settings();
  await api.declarativeNetRequest.updateEnabledRulesets({
    enableRulesetIds: state.enabled ? ["blue_default_filters"] : [],
    disableRulesetIds: state.enabled ? [] : ["blue_default_filters"]
  });
  const existing = await api.declarativeNetRequest.getDynamicRules();
  const removeRuleIds = existing
    .filter((rule) => rule.id >= 10000 && rule.id < 30000)
    .map((rule) => rule.id);
  const addRules = [];

  if (state.enabled) {
    [...new Set(state.blockedDomains.map(normalizedDomain).filter(Boolean))]
      .slice(0, 5000)
      .forEach((domain, index) => {
        addRules.push({
          id: 10000 + index,
          priority: 1,
          action: { type: "block" },
          condition: { requestDomains: [domain], resourceTypes: RESOURCE_TYPES }
        });
      });

    [...new Set(state.allowedDomains.map(normalizedDomain).filter(Boolean))]
      .slice(0, 5000)
      .forEach((domain, index) => {
        addRules.push({
          id: 20000 + index,
          priority: 10,
          action: { type: "allow" },
          condition: { requestDomains: [domain], resourceTypes: RESOURCE_TYPES }
        });
      });
  }

  await api.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules });
}

function searchUrl(provider, query, safe) {
  const q = encodeURIComponent(query.trim());
  const urls = {
    duckduckgo: `https://duckduckgo.com/?q=${q}${safe ? "&kp=1" : ""}`,
    brave: `https://search.brave.com/search?q=${q}${safe ? "&safesearch=strict" : ""}`,
    google: `https://www.google.com/search?q=${q}${safe ? "&safe=active" : ""}`,
    bing: `https://www.bing.com/search?q=${q}${safe ? "&adlt=strict" : ""}`
  };
  return urls[provider] || urls.duckduckgo;
}

api.runtime.onInstalled.addListener(async () => {
  const current = await api.storage.local.get(null);
  await api.storage.local.set({ ...DEFAULTS, ...current });
  await rebuildDynamicRules();
});

api.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;
  const relevant = ["enabled", "blockedDomains", "allowedDomains"];
  if (relevant.some((key) => key in changes)) {
    rebuildDynamicRules().catch((error) => console.error("Blue rule update failed", error));
  }
});

api.omnibox.onInputEntered.addListener(async (text) => {
  const state = await settings();
  const url = searchUrl(state.searchProvider, text, state.safeSearch);
  await api.tabs.update({ url });
});

api.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "blue:native-status") {
    nativeRequest({ type: "status" }).then(sendResponse);
    return true;
  }
  if (message?.type === "blue:check-domains") {
    if (!Array.isArray(message.domains)) {
      sendResponse({ ok: false, error: "domains must be an array" });
      return false;
    }
    const domains = [...new Set(message.domains.filter((domain) => typeof domain === "string"))]
      .slice(0, 200);
    nativeRequest({ type: "check_domains", domains }).then(sendResponse);
    return true;
  }
  if (message?.type === "blue:rebuild-rules") {
    rebuildDynamicRules()
      .then(() => sendResponse({ ok: true }))
      .catch((error) => sendResponse({ ok: false, error: String(error) }));
    return true;
  }
  if (message?.type === "blue:search") {
    settings()
      .then((state) => api.tabs.create({
        url: searchUrl(message.provider || state.searchProvider, message.query || "", state.safeSearch)
      }))
      .then(() => sendResponse({ ok: true }))
      .catch((error) => sendResponse({ ok: false, error: String(error) }));
    return true;
  }
  return false;
});

// Export pure helpers for the Node validation suite without affecting Chromium.
if (typeof module !== "undefined") {
  module.exports = { nativeRequest, normalizedDomain, searchUrl };
}
