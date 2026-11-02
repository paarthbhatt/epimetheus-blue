const api = globalThis.browser ?? globalThis.chrome;
const settingIds = ["enabled", "cleanSponsored", "stripTracking", "warnBlocked", "safeSearch"];
let currentDomain = "";

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

load().catch((error) => {
  document.getElementById("site-domain").textContent = `Error: ${error}`;
});
