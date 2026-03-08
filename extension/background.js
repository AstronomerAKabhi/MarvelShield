// MarvelShield background service worker
// Connection status is driven by the bridge (localhost:3000).
// Patches and live stats are fetched from the gateway (localhost:8000).

const BRIDGE_HEALTH_URL     = "http://localhost:3000/health";
const GATEWAY_PATCHES_URL   = "http://localhost:8000/api/patches";
const GATEWAY_STATS_URL     = "http://localhost:8000/api/stats";
const POLL_INTERVAL_MINUTES = 0.5; // every 30 seconds

const STORAGE_KEY_PATCHES   = "ms_patches";
const STORAGE_KEY_STATS     = "ms_stats";
const STORAGE_KEY_STATUS    = "ms_connection_status";

// ─── Initial bootstrap ───────────────────────────────────────────────────────

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({
    [STORAGE_KEY_PATCHES]: [],
    [STORAGE_KEY_STATUS]:  "connecting",
    [STORAGE_KEY_STATS]: {
      // Gateway-level stats (from /api/stats)
      gatewayTotalRequests: 0,
      gatewayBlocked:       0,
      gatewayPatches:       0,
      gatewayBannedIPs:     0,
      // Browser-level stats (from content script)
      browserBlocked:       0,
      browserAllowed:       0,
      lastSync:             null,
    },
  });
  chrome.alarms.create("syncPatches", { periodInMinutes: POLL_INTERVAL_MINUTES });
  syncPatches();
});

chrome.runtime.onStartup.addListener(() => {
  chrome.alarms.create("syncPatches", { periodInMinutes: POLL_INTERVAL_MINUTES });
  syncPatches();
});

// ─── Alarm handler ───────────────────────────────────────────────────────────

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "syncPatches") syncPatches();
});

// ─── Patch + stats sync ───────────────────────────────────────────────────────

async function syncPatches() {
  // ── Step 1: Check bridge reachability (drives connection status badge) ──
  let bridgeUp = false;
  try {
    const res = await fetch(BRIDGE_HEALTH_URL, {
      cache:  "no-store",
      signal: AbortSignal.timeout(3000),
    });
    bridgeUp = res.ok;
  } catch {
    bridgeUp = false;
  }

  if (!bridgeUp) {
    await chrome.storage.local.set({ [STORAGE_KEY_STATUS]: "disconnected" });
    chrome.action.setBadgeText({ text: "!" });
    chrome.action.setBadgeBackgroundColor({ color: "#555" });
    return;
  }

  // Bridge is up → mark as connected
  await chrome.storage.local.set({ [STORAGE_KEY_STATUS]: "connected" });

  // ── Step 2: Fetch patches + stats from gateway (best-effort) ──
  let patches     = [];
  let gatewayData = {};

  try {
    const [patchRes, statsRes] = await Promise.allSettled([
      fetch(GATEWAY_PATCHES_URL, { cache: "no-store", signal: AbortSignal.timeout(3000) }),
      fetch(GATEWAY_STATS_URL,   { cache: "no-store", signal: AbortSignal.timeout(3000) }),
    ]);

    if (patchRes.status === "fulfilled" && patchRes.value.ok) {
      const data = await patchRes.value.json();
      patches = data.patches || [];
      await chrome.storage.local.set({ [STORAGE_KEY_PATCHES]: patches });
    }

    if (statsRes.status === "fulfilled" && statsRes.value.ok) {
      gatewayData = await statsRes.value.json();
    }
  } catch {
    // Gateway not reachable — keep existing patches
  }

  // ── Step 3: Merge gateway stats with browser-level stats ──
  const existing = await chrome.storage.local.get(STORAGE_KEY_STATS);
  const stats    = existing[STORAGE_KEY_STATS] || {};

  await chrome.storage.local.set({
    [STORAGE_KEY_STATS]: {
      ...stats,
      lastSync:             new Date().toISOString(),
      gatewayTotalRequests: gatewayData.total_requests ?? stats.gatewayTotalRequests ?? 0,
      gatewayBlocked:       gatewayData.blocked_count  ?? stats.gatewayBlocked       ?? 0,
      gatewayPatches:       gatewayData.active_patches ?? patches.length,
      gatewayBannedIPs:     gatewayData.banned_ips     ?? stats.gatewayBannedIPs     ?? 0,
    },
  });

  // Update badge: show active patch count (green = connected, crimson = patches active)
  const count = patches.length;
  chrome.action.setBadgeText({ text: count > 0 ? String(count) : "" });
  chrome.action.setBadgeBackgroundColor({ color: count > 0 ? "#8b0000" : "#2e6b2e" });
}

// ─── Message handler ─────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === "GET_PATCHES") {
    chrome.storage.local.get([STORAGE_KEY_PATCHES, STORAGE_KEY_STATUS], (result) => {
      sendResponse({
        patches: result[STORAGE_KEY_PATCHES] || [],
        status:  result[STORAGE_KEY_STATUS]  || "disconnected",
      });
    });
    return true;
  }

  if (msg.type === "SYNC_NOW") {
    syncPatches().then(() => sendResponse({ ok: true }));
    return true;
  }

  if (msg.type === "REQUEST_BLOCKED") {
    chrome.storage.local.get(STORAGE_KEY_STATS, (result) => {
      const stats = result[STORAGE_KEY_STATS] || {};
      chrome.storage.local.set({
        [STORAGE_KEY_STATS]: { ...stats, browserBlocked: (stats.browserBlocked || 0) + 1 },
      });
    });
  }

  if (msg.type === "REQUEST_ALLOWED") {
    chrome.storage.local.get(STORAGE_KEY_STATS, (result) => {
      const stats = result[STORAGE_KEY_STATS] || {};
      chrome.storage.local.set({
        [STORAGE_KEY_STATS]: { ...stats, browserAllowed: (stats.browserAllowed || 0) + 1 },
      });
    });
  }
});
