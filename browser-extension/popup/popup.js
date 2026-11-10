const api = globalThis.browser ?? globalThis.chrome;
const messagingAvailable = typeof api?.runtime?.sendMessage === "function";
const settingIds = ["enabled", "cleanSponsored", "stripTracking", "warnBlocked", "safeSearch"];
const defaults = {
  enabled: true, cleanSponsored: true, stripTracking: true,
  warnBlocked: true, safeSearch: true, searchProvider: "duckduckgo",
  blockedDomains: [], allowedDomains: []
};
let state = { ...defaults };
let currentDomain = "";
let settingsReady = false;
let siteRulePending = false;
let nativePending = false;
let searchPending = false;
const nativeCountIds = {
  artifacts: "native-artifacts",
  findings: "native-findings",
  quarantined: "native-quarantined",
  blocked: "native-blocked"
};
const countFormatter = new Intl.NumberFormat();
const element = (id) => document.getElementById(id);

function normalize(value) {
  return String(value || "")
    .toLowerCase()
    .trim()
    .replace(/^https?:\/\//, "")
    .split("/")[0]
    .replace(/^www\./, "")
    .replace(/\.$/, "");
}

function restoreFocus(control, wasFocused) {
  if (wasFocused && !control.disabled && document.activeElement === document.body) {
    control.focus({ preventScroll: true });
  }
}

function domainFromTab(url) {
  try {
    const parsed = new URL(url);
    return ["http:", "https:"].includes(parsed.protocol) ? normalize(parsed.hostname) : "";
  } catch (_) {
    return "";
  }
}

function matchingRule(domains) {
  let match = "";
  for (const value of domains) {
    const domain = normalize(value);
    if (domain && (currentDomain === domain || currentDomain.endsWith(`.${domain}`)) && domain.length > match.length) {
      match = domain;
    }
  }
  return match;
}

function showFeedback(message, error = false, id = "popup-message") {
  const feedback = element(id);
  feedback.textContent = message;
  feedback.dataset.tone = error ? "error" : "notice";
  feedback.hidden = !message;
}

function showSiteRule() {
  const allowed = settingsReady && currentDomain ? matchingRule(state.allowedDomains) : "";
  const blocked = settingsReady && currentDomain ? matchingRule(state.blockedDomains) : "";
  // Browser allow rules have higher priority than block rules, including when
  // inherited from a parent domain. This describes saved rules, not feed verdicts.
  const rule = allowed ? "allow" : blocked ? "block" : "default";
  element("site-domain").textContent = currentDomain || "No website selected";
  element("site-rule").dataset.rule = rule;
  element("site-rule").textContent = !currentDomain ? "No site rule"
    : !settingsReady ? "Rule unavailable"
    : { allow: "Allow rule", block: "Block rule", default: "Default rules" }[rule];
  element("allow-site").setAttribute("aria-pressed", String(Boolean(allowed)));
  element("block-site").setAttribute("aria-pressed", String(Boolean(blocked && !allowed)));
  for (const id of ["allow-site", "block-site"]) {
    element(id).disabled = !settingsReady || !currentDomain || siteRulePending;
  }
  if (!currentDomain) {
    element("site-detail").textContent = "Open an HTTP or HTTPS website to set a browser-local rule.";
  } else if (!settingsReady) {
    element("site-detail").textContent = "Browser settings are unavailable. No site rule was changed.";
  } else {
    const inherited = (allowed || blocked) && (allowed || blocked) !== currentDomain
      ? ` Rule inherited from ${allowed || blocked}.` : "";
    const precedence = allowed && blocked ? " An allow rule takes precedence over a block rule." : "";
    const paused = !state.enabled ? " Browser filtering is paused; saved rules are kept." : "";
    element("site-detail").textContent = `Saved in this browser profile, not desktop DNS.${inherited}${precedence}${paused}`;
  }
}

function showState(enabled) {
  element("state-dot").classList.toggle("off", !settingsReady || !enabled);
  element("protection-label").textContent = !settingsReady ? "Settings unavailable"
    : enabled ? "Enabled in settings" : "Paused in settings";
  element("protection-detail").textContent = !settingsReady
    ? "No browser setting was changed. Reopen the popup to try again."
    : enabled
      ? "Uses the rules and search-page preferences saved in this browser profile. This is a setting, not a live-protection check."
      : "Browser filtering and search-page cleanup are paused. Your saved rules are kept.";
  showSiteRule();
}

function validCount(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function displayCount(value) {
  return validCount(value) ? countFormatter.format(value) : "—";
}

function showNativeCounts(counts = {}) {
  for (const [name, id] of Object.entries(nativeCountIds)) {
    element(id).textContent = displayCount(counts[name]);
  }
  element("desktop-records").hidden = !Object.keys(nativeCountIds).some((name) => validCount(counts[name]));
}

async function refreshNative() {
  if (nativePending) return;
  nativePending = true;
  const refresh = element("refresh-native");
  const status = element("desktop-state");
  const detail = element("desktop-detail");
  const wasFocused = document.activeElement === refresh;
  refresh.disabled = true;
  refresh.setAttribute("aria-busy", "true");
  status.textContent = "Checking bridge…";
  status.className = "";
  detail.textContent = "Requesting a read-only local status snapshot.";
  detail.title = "";
  showNativeCounts();
  try {
    if (!messagingAvailable) throw new Error("Browser extension messaging is unavailable");
    const response = await api.runtime.sendMessage({ type: "blue:native-status" });
    if (!response?.ok || response.connected !== true) {
      throw new Error(response?.error || "Native Messaging did not return a status snapshot");
    }
    status.textContent = "Bridge available";
    status.className = "connected";
    showNativeCounts(response.counts ?? {});
    const version = typeof response.version === "string" ? `Local host v${response.version}.` : "Local host replied.";
    const feeds = Array.isArray(response.active_feeds)
      ? `${response.active_feeds.length} active desktop feed${response.active_feeds.length === 1 ? "" : "s"} reported.`
      : "Feed count not reported.";
    detail.textContent = `${version} ${feeds}${response.kill_switch === true ? " Desktop kill switch reported on." : ""}`;
  } catch (error) {
    status.textContent = "Bridge unavailable";
    status.className = "disconnected";
    showNativeCounts();
    detail.textContent = messagingAvailable
      ? "No local status snapshot. Browser-only features are controlled separately; desktop feed checks need the Native Messaging host."
      : "Browser extension messaging is unavailable. Open this popup from the installed extension to check the local host.";
    detail.title = String(error?.message || error).replace(/Desktop app is not connected:\s*/i, "Native Messaging: ");
  } finally {
    refresh.disabled = !messagingAvailable;
    refresh.removeAttribute("aria-busy");
    nativePending = false;
    restoreFocus(refresh, wasFocused);
  }
}

async function load() {
  // Exactly one automatic native-host launch per popup open. Further requests
  // happen only when the user chooses Check again; there is no polling.
  const desktopStatus = refreshNative();
  try {
    state = { ...defaults, ...(await api.storage.local.get(defaults)) };
    if (!Array.isArray(state.blockedDomains) || !Array.isArray(state.allowedDomains)) {
      throw new Error("Browser rule lists could not be read");
    }
    settingsReady = true;
    for (const id of settingIds) {
      state[id] = Boolean(state[id]);
      element(id).checked = state[id];
      element(id).disabled = false;
    }
    const provider = element("search-provider");
    const providers = Array.from(provider.options, (option) => option.value);
    provider.value = providers.includes(state.searchProvider) ? state.searchProvider : defaults.searchProvider;
    state.searchProvider = provider.value;
    provider.disabled = false;
    element("search-query").disabled = !messagingAvailable;
    element("search-submit").disabled = !messagingAvailable;
    if (!messagingAvailable) {
      showFeedback("Browser extension messaging is unavailable. Search cannot be opened from this popup.", true, "search-message");
    }
    showState(state.enabled);
  } catch (_) {
    settingsReady = false;
    showState(false);
    showFeedback("Browser settings could not be read. Reopen this popup to try again.", true);
  }

  try {
    const [tab] = await api.tabs.query({ active: true, currentWindow: true });
    currentDomain = domainFromTab(tab?.url);
    showSiteRule();
    if (!tab || !Number.isInteger(tab.id)) throw new Error("No current tab");
    const stats = await api.tabs.sendMessage(tab.id, { type: "blue:stats" });
    if (!stats || ![stats.removed, stats.cleanedLinks, stats.warnedLinks].some(validCount)) {
      throw new Error("No search-page snapshot");
    }
    element("removed").textContent = displayCount(stats.removed);
    element("cleaned").textContent = displayCount(stats.cleanedLinks);
    element("warned").textContent = displayCount(stats.warnedLinks);
    element("page-stats").hidden = false;
    element("page-detail").textContent = "Search-page snapshot at popup open. These counters are not refreshed live.";
  } catch (_) {
    element("page-stats").hidden = true;
    element("page-detail").textContent = "No search-page snapshot available. Counters are reported only by supported search pages.";
  }
  await desktopStatus;
}

for (const id of settingIds) {
  element(id).addEventListener("change", async (event) => {
    const input = event.target;
    const previous = state[id];
    const feedbackId = id === "enabled" ? "popup-message" : "preferences-message";
    const wasFocused = document.activeElement === input;
    input.disabled = true;
    try {
      await api.storage.local.set({ [id]: input.checked });
      state[id] = input.checked;
      showState(state.enabled);
      showFeedback("Browser preference saved.", false, feedbackId);
    } catch (_) {
      input.checked = previous;
      showFeedback("Browser preference could not be saved. The previous setting is kept.", true, feedbackId);
    } finally {
      input.disabled = false;
      restoreFocus(input, wasFocused);
    }
  });
}

element("search-provider").addEventListener("change", async (event) => {
  const provider = event.target;
  const wasFocused = document.activeElement === provider;
  provider.disabled = true;
  try {
    await api.storage.local.set({ searchProvider: provider.value });
    state.searchProvider = provider.value;
    showFeedback("Search provider saved.", false, "search-message");
  } catch (_) {
    provider.value = state.searchProvider;
    showFeedback("Search provider could not be saved. The previous provider is kept.", true, "search-message");
  } finally {
    provider.disabled = false;
    restoreFocus(provider, wasFocused);
  }
});

element("search-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!settingsReady || !messagingAvailable || searchPending) return;
  const query = element("search-query").value.trim();
  if (!query) return;
  searchPending = true;
  const submit = element("search-submit");
  const wasFocused = document.activeElement === submit;
  submit.disabled = true;
  element("search-form").setAttribute("aria-busy", "true");
  showFeedback("", false, "search-message");
  try {
    const response = await api.runtime.sendMessage({
      type: "blue:search",
      query,
      provider: element("search-provider").value
    });
    if (!response?.ok) throw new Error("Search could not be opened");
    window.close();
  } catch (_) {
    showFeedback("Search could not be opened. Your query is still here; try again.", true, "search-message");
  } finally {
    submit.disabled = false;
    element("search-form").removeAttribute("aria-busy");
    searchPending = false;
    restoreFocus(submit, wasFocused);
  }
});

async function updateDomainList(block) {
  if (!settingsReady || !currentDomain || siteRulePending) return;
  const button = element(block ? "block-site" : "allow-site");
  const wasFocused = document.activeElement === button;
  siteRulePending = true;
  showSiteRule();
  try {
    const stored = await api.storage.local.get({ blockedDomains: [], allowedDomains: [] });
    const blocked = new Set(stored.blockedDomains.map(normalize));
    const allowed = new Set(stored.allowedDomains.map(normalize));
    if (block) {
      blocked.add(currentDomain);
      allowed.delete(currentDomain);
    } else {
      allowed.add(currentDomain);
      blocked.delete(currentDomain);
    }
    const rules = { blockedDomains: [...blocked], allowedDomains: [...allowed] };
    await api.storage.local.set(rules);
    state = { ...state, ...rules };
    const overridingAllow = block && matchingRule(state.allowedDomains);
    showFeedback(overridingAllow
      ? `Block rule saved. The allow rule for ${overridingAllow} still takes precedence.`
      : `${block ? "Block" : "Allow"} rule saved for ${currentDomain}.`);
  } catch (_) {
    showFeedback("Site rule could not be saved. The previous rule is kept.", true);
  } finally {
    siteRulePending = false;
    showSiteRule();
    restoreFocus(button, wasFocused);
  }
}

element("block-site").addEventListener("click", () => updateDomainList(true));
element("allow-site").addEventListener("click", () => updateDomainList(false));
element("refresh-native").addEventListener("click", refreshNative);

load().catch(() => {
  showFeedback("The popup could not finish loading. Reopen it to try again.", true);
});
