const api = globalThis.browser ?? globalThis.chrome;
const settingIds = ["enabled", "cleanSponsored", "stripTracking", "warnBlocked", "safeSearch"];
let currentDomain = "";
const nativeCountIds = {
  artifacts: "native-artifacts",
  findings: "native-findings",
  quarantined: "native-quarantined",
  blocked: "native-blocked"
};

function normalize(value) {
  return String(value || "").toLowerCase().replace(/^www\./, "").replace(/\.$/, "");
}

async function load() {
  const defaults = {
    enabled: true, cleanSponsored: true, stripTracking: true,
    warnBlocked: true, safeSearch: true, searchProvider: "duckduckgo",
    blockedDomains: [], allowedDomains: []
  };
  const state = { ...defaults, ...(await api.storage.local.get(defaults)) };
  for (const id of settingIds) document.getElementById(id).checked = Boolean(state[id]);
  document.getElementById("search-provider").value = state.searchProvider;
  showState(state.enabled);
  // Exactly one automatic native-host launch per popup open. Further checks
  // happen only when the user presses Refresh.
  const desktopStatus = refreshNative();

  const [tab] = await api.tabs.query({ active: true, currentWindow: true });
  try { currentDomain = normalize(new URL(tab.url).hostname); } catch (_) { currentDomain = ""; }
  document.getElementById("site-domain").textContent = currentDomain || "No website selected";
  if (tab?.id) {
    try {
      const stats = await api.tabs.sendMessage(tab.id, { type: "blue:stats" });
      document.getElementById("removed").textContent = stats.removed;
      document.getElementById("cleaned").textContent = stats.cleanedLinks;
      document.getElementById("warned").textContent = stats.warnedLinks;
    } catch (_) {
      // Current tab is not a supported search page.
    }
  }
  await desktopStatus;
}

function showNativeCounts(counts = {}) {
  for (const [name, id] of Object.entries(nativeCountIds)) {
    document.getElementById(id).textContent = Number.isFinite(counts[name]) ? counts[name] : "—";
  }
}

async function refreshNative() {
  const refresh = document.getElementById("refresh-native");
  const status = document.getElementById("desktop-state");
  const detail = document.getElementById("desktop-detail");
  refresh.disabled = true;
  status.textContent = "Checking…";
  status.className = "";
  try {
    const response = await api.runtime.sendMessage({ type: "blue:native-status" });
    if (!response?.ok || response.connected !== true) {
      throw new Error(response?.error || "Desktop app did not respond");
    }
    status.textContent = "Connected";
    status.className = "connected";
    showNativeCounts(response.counts);
    const feeds = response.active_feeds?.length
      ? `${response.active_feeds.length} active feed${response.active_feeds.length === 1 ? "" : "s"}`
      : "no active feeds";
    detail.textContent = `v${response.version} · ${feeds}${response.kill_switch ? " · kill switch on" : ""}`;
  } catch (error) {
    status.textContent = "Disconnected";
    status.className = "disconnected";
    showNativeCounts();
    detail.textContent = error?.message || String(error);
  } finally {
    refresh.disabled = false;
  }
}

function showState(enabled) {
  document.getElementById("state-dot").classList.toggle("off", !enabled);
  const label = document.getElementById("protection-label");
  label.textContent = enabled ? "Active" : "Paused";
  label.style.color = enabled ? "#3ecf8e" : "#8b99af";
}

for (const id of settingIds) {
  document.getElementById(id).addEventListener("change", async (event) => {
    await api.storage.local.set({ [id]: event.target.checked });
    if (id === "enabled") showState(event.target.checked);
  });
}

document.getElementById("search-provider").addEventListener("change", async (event) => {
  await api.storage.local.set({ searchProvider: event.target.value });
});

document.getElementById("search-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const query = document.getElementById("search-query").value.trim();
  if (!query) return;
  await api.runtime.sendMessage({
    type: "blue:search",
    query,
    provider: document.getElementById("search-provider").value
  });
  window.close();
});

async function updateDomainList(block) {
  if (!currentDomain) return;
  const state = await api.storage.local.get({ blockedDomains: [], allowedDomains: [] });
  const blocked = new Set(state.blockedDomains.map(normalize));
  const allowed = new Set(state.allowedDomains.map(normalize));
  if (block) {
    blocked.add(currentDomain);
    allowed.delete(currentDomain);
  } else {
    allowed.add(currentDomain);
    blocked.delete(currentDomain);
  }
  await api.storage.local.set({ blockedDomains: [...blocked], allowedDomains: [...allowed] });
  document.getElementById("site-domain").textContent = `${currentDomain} · ${block ? "blocked" : "allowed"}`;
}

document.getElementById("block-site").addEventListener("click", () => updateDomainList(true));
document.getElementById("allow-site").addEventListener("click", () => updateDomainList(false));
document.getElementById("refresh-native").addEventListener("click", refreshNative);

load().catch((error) => {
  document.getElementById("site-domain").textContent = `Error: ${error}`;
});
