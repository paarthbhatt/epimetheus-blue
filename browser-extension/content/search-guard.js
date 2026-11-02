/* Search-page protection. It removes only elements positively identified as
 * sponsored, strips known tracking parameters, and marks user-blocked domains. */

(() => {
  "use strict";
  const api = globalThis.browser ?? globalThis.chrome;
  const TRACKING_KEYS = new Set([
    "gclid", "dclid", "fbclid", "msclkid", "mc_cid", "mc_eid", "igshid",
    "vero_id", "wickedid", "yclid", "_hsenc", "_hsmi"
  ]);
  let state = null;
  let removed = 0;
  let cleanedLinks = 0;
  let warnedLinks = 0;
  let scheduled = false;

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

  function inspectLinks() {
    const blocked = (state.blockedDomains || []).map((x) => String(x).toLowerCase());
    const allowed = (state.allowedDomains || []).map((x) => String(x).toLowerCase());
    for (const link of document.querySelectorAll("a[href^='http']")) {
      if (link.dataset.blueChecked === "true") continue;
      link.dataset.blueChecked = "true";
      let url;
      try {
        url = new URL(link.href);
      } catch (_) {
        continue;
      }
      const host = url.hostname.toLowerCase().replace(/^www\./, "");
      if (state.stripTracking && stripTracking(url)) {
        link.href = url.toString();
        cleanedLinks += 1;
      }
      if (
        state.warnBlocked &&
        domainMatches(host, blocked) &&
        !domainMatches(host, allowed)
      ) {
        link.classList.add("blue-blocked-link");
        link.dataset.blueBlockedDomain = host;
        const badge = document.createElement("span");
        badge.className = "blue-warning-badge";
        badge.textContent = "BLUE BLOCKED";
        badge.title = `${host} is on your local blocked-domain list`;
        link.insertAdjacentElement("afterend", badge);
        link.addEventListener("click", (event) => {
          event.preventDefault();
          event.stopPropagation();
          alert(`Epimetheus Blue blocked this link:\n\n${host}\n\nRemove it from your blocked list in the extension before continuing.`);
        }, true);
        warnedLinks += 1;
      }
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
