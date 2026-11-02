/* Search-page protection. It removes only elements positively identified as
 * sponsored, strips known tracking parameters, and marks blocked domains. */

(() => {
  "use strict";
  const api = globalThis.browser ?? globalThis.chrome;
  const TRACKING_KEYS = new Set([
    "gclid", "dclid", "fbclid", "msclkid", "mc_cid", "mc_eid", "igshid",
    "vero_id", "wickedid", "yclid", "_hsenc", "_hsmi"
  ]);
  const NATIVE_BATCH_SIZE = 200;
  const nativeVerdicts = new Map();
  const linksByDomain = new Map();
  const pendingNativeDomains = new Set();
  let state = null;
  let removed = 0;
  let cleanedLinks = 0;
  let warnedLinks = 0;
  let scheduled = false;
  let nativeCheckTimer = null;
  let nativeCheckInFlight = false;
  let nativeUnavailable = false;

  const selectors = {
    google: ["[data-text-ad]", "[data-ta-slot]", "div.uEierd"],
    bing: ["li.b_ad", ".sb_add", "[data-bm*='ad'] .b_adlabel"],
    duckduckgo: ["[data-testid='ad']", ".result--ad", ".results--ads"],
    brave: ["[data-type='ad']", ".snippet[data-ad]", ".ad-result"]
  };

  function engine() {
    const host = location.hostname;
    if (host.includes("google.")) return "google";
    if (host === "www.bing.com") return "bing";
    if (host === "duckduckgo.com") return "duckduckgo";
    if (host === "search.brave.com") return "brave";
    return "unknown";
  }

  function domainMatches(host, list) {
    const clean = host.toLowerCase().replace(/^www\./, "").replace(/\.$/, "");
    return list.some((item) => clean === item || clean.endsWith(`.${item}`));
  }

  function cleanSponsored() {
    if (!state.cleanSponsored) return;
    for (const selector of selectors[engine()] || []) {
      for (const node of document.querySelectorAll(selector)) {
        // Some Bing selectors hit a label nested in the card.
        const card = node.matches("li, [data-text-ad], [data-testid='ad'], [data-type='ad'], .result--ad, .results--ads, .snippet")
          ? node
          : node.closest("li, .b_algo, .result, .snippet");
        if (card && !card.dataset.blueRemoved) {
          card.dataset.blueRemoved = "true";
          card.classList.add("blue-sponsored-hidden");
          removed += 1;
        }
      }
    }
  }

  function stripTracking(url) {
    let changed = false;
    for (const key of [...url.searchParams.keys()]) {
      if (key.toLowerCase().startsWith("utm_") || TRACKING_KEYS.has(key.toLowerCase())) {
        url.searchParams.delete(key);
        changed = true;
      }
    }
    return changed;
  }

  function isVisible(link) {
    if (!link.isConnected || link.closest(".blue-sponsored-hidden")) return false;
    const style = getComputedStyle(link);
    return style.display !== "none" && style.visibility !== "hidden" && link.getClientRects().length > 0;
  }

  function rememberLink(host, link) {
    let links = linksByDomain.get(host);
    if (!links) {
      links = new Set();
      linksByDomain.set(host, links);
    }
    links.add(link);
  }

  function blockDescription(host, list) {
    return list
      ? `${host} is blocked by the desktop filter list “${list}”`
      : `${host} is on your local blocked-domain list`;
  }

  function markBlocked(link, host, list = null) {
    if (link.dataset.blueBlocked === "true") return;
    link.dataset.blueBlocked = "true";
    link.dataset.blueBlockedDomain = host;
    link.dataset.blueBlockedList = list || "";
    link.classList.add("blue-blocked-link");

    const badge = document.createElement("span");
    badge.className = "blue-warning-badge";
    badge.textContent = "BLUE BLOCKED";
    badge.title = blockDescription(host, list);
    link.insertAdjacentElement("afterend", badge);

    if (link.dataset.blueWarningBound !== "true") {
      link.dataset.blueWarningBound = "true";
      link.addEventListener("click", (event) => {
        if (link.dataset.blueBlocked !== "true") return;
        event.preventDefault();
        event.stopPropagation();
        const blockedHost = link.dataset.blueBlockedDomain;
        const blockedList = link.dataset.blueBlockedList;
        const guidance = blockedList
          ? `Desktop filter list: ${blockedList}\n\nManage desktop feeds to change this verdict.`
          : "Remove it from your blocked list in the extension before continuing.";
        alert(`Epimetheus Blue blocked this link:\n\n${blockedHost}\n\n${guidance}`);
      }, true);
    }
    warnedLinks += 1;
  }

  function clearBlocked(link) {
    if (link.dataset.blueBlocked !== "true") return;
    link.classList.remove("blue-blocked-link");
    delete link.dataset.blueBlocked;
    delete link.dataset.blueBlockedDomain;
    delete link.dataset.blueBlockedList;
    if (link.nextElementSibling?.classList.contains("blue-warning-badge")) {
      link.nextElementSibling.remove();
    }
    warnedLinks = Math.max(0, warnedLinks - 1);
  }

  function scheduleNativeCheck() {
    if (nativeUnavailable || nativeCheckInFlight || nativeCheckTimer || pendingNativeDomains.size === 0) {
      return;
    }
    // Give search pages one short turn to insert a whole result batch.
    nativeCheckTimer = setTimeout(flushNativeChecks, 50);
  }

  async function flushNativeChecks() {
    nativeCheckTimer = null;
    if (nativeUnavailable || nativeCheckInFlight || pendingNativeDomains.size === 0) return;

    const domains = [...pendingNativeDomains].slice(0, NATIVE_BATCH_SIZE);
    for (const domain of domains) pendingNativeDomains.delete(domain);
    nativeCheckInFlight = true;
    try {
      const response = await api.runtime.sendMessage({
        type: "blue:check-domains",
        domains
      });
      if (!response?.ok) {
        if (response?.connected === false) nativeUnavailable = true;
        return;
      }

      const results = response.domains || {};
      for (const domain of domains) {
        const verdict = results[domain] || { blocked: false };
        nativeVerdicts.set(domain, verdict);
        if (!verdict.blocked || domainMatches(domain, state.allowedDomains || [])) continue;
        for (const link of linksByDomain.get(domain) || []) {
          if (link.isConnected && state.warnBlocked) {
            markBlocked(link, domain, verdict.list || "desktop feed");
          }
        }
      }
    } catch (_) {
      // A missing host is expected when the desktop app is not installed.
      nativeUnavailable = true;
    } finally {
      nativeCheckInFlight = false;
      if (!nativeUnavailable && pendingNativeDomains.size > 0) scheduleNativeCheck();
    }
  }

  function queueNativeCheck(host, link) {
    if (nativeUnavailable || link.dataset.blueNativeChecked === "true") return;
    link.dataset.blueNativeChecked = "true";
    rememberLink(host, link);

    if (nativeVerdicts.has(host)) {
      const verdict = nativeVerdicts.get(host);
      if (verdict.blocked) markBlocked(link, host, verdict.list || "desktop feed");
      return;
    }

    pendingNativeDomains.add(host);
    scheduleNativeCheck();
  }

  function inspectLinks() {
    const blocked = (state.blockedDomains || []).map((item) => String(item).toLowerCase());
    const allowed = (state.allowedDomains || []).map((item) => String(item).toLowerCase());
    for (const link of document.querySelectorAll("a[href^='http']")) {
      let url;
      try {
        url = new URL(link.href);
      } catch (_) {
        continue;
      }
      // Preserve the full hostname for the desktop matcher. In particular,
      // stripping "www" would break exact DNS suffix attribution for a list
      // that contains only www.example.test.
      const host = url.hostname.toLowerCase().replace(/\.$/, "");

      if (link.dataset.blueChecked !== "true") {
        link.dataset.blueChecked = "true";
        if (state.stripTracking && stripTracking(url)) {
          link.href = url.toString();
          cleanedLinks += 1;
        }
      }

      if (!state.warnBlocked || domainMatches(host, allowed)) {
        link.dataset.blueNativeChecked = "true";
        continue;
      }
      if (domainMatches(host, blocked)) {
        link.dataset.blueNativeChecked = "true";
        markBlocked(link, host);
        continue;
      }
      if (isVisible(link)) queueNativeCheck(host, link);
    }
  }

  function protect() {
    scheduled = false;
    if (!state?.enabled) return;
    cleanSponsored();
    inspectLinks();
  }

  function schedule() {
    if (scheduled) return;
    scheduled = true;
    requestAnimationFrame(protect);
  }

  api.runtime.onMessage.addListener((message, _sender, respond) => {
    if (message?.type === "blue:stats") {
      respond({ removed, cleanedLinks, warnedLinks, engine: engine() });
    }
  });

  api.storage.onChanged.addListener((_changes, area) => {
    if (area !== "local") return;
    api.storage.local.get(null).then((next) => {
      state = next;
      for (const link of document.querySelectorAll("a[data-blue-checked]")) {
        clearBlocked(link);
        delete link.dataset.blueNativeChecked;
      }
      schedule();
    });
  });

  api.storage.local.get({
    enabled: true,
    cleanSponsored: true,
    stripTracking: true,
    warnBlocked: true,
    blockedDomains: [],
    allowedDomains: []
  }).then((loaded) => {
    state = loaded;
    protect();
    new MutationObserver(schedule).observe(document.documentElement, {
      childList: true,
      subtree: true
    });
  });
})();
