// MarvelShield content script
// Intercepts outgoing fetch and XMLHttpRequest calls, checks them against
// active AI-generated patches, and shows a warning modal if a match is found.

(function () {
  "use strict";

  // ─── Patch cache ────────────────────────────────────────────────────────────

  let cachedPatches = [];
  let cacheAge      = 0;
  const CACHE_TTL   = 30_000; // 30 s

  function refreshCache() {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({ type: "GET_PATCHES" }, (response) => {
        if (response && response.patches) {
          cachedPatches = response.patches;
          cacheAge      = Date.now();
        }
        resolve();
      });
    });
  }

  async function getPatches() {
    if (Date.now() - cacheAge > CACHE_TTL) await refreshCache();
    return cachedPatches;
  }

  // ─── Pattern matching ───────────────────────────────────────────────────────

  function findMatch(url, body) {
    for (const patch of cachedPatches) {
      if (!patch.regex) continue;
      try {
        const re = new RegExp(patch.regex, "i");
        if (re.test(url) || (body && re.test(body))) return patch;
      } catch {
        // invalid regex from server — skip
      }
    }
    return null;
  }

  // ─── Warning modal ──────────────────────────────────────────────────────────

  function injectStyles() {
    if (document.getElementById("ms-styles")) return;
    const style = document.createElement("style");
    style.id = "ms-styles";
    style.textContent = `
      #ms-overlay {
        position: fixed; inset: 0; z-index: 2147483647;
        background: rgba(0,0,0,0.75);
        display: flex; align-items: center; justify-content: center;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        animation: ms-fade-in 0.15s ease;
      }
      @keyframes ms-fade-in { from { opacity: 0; } to { opacity: 1; } }
      #ms-modal {
        background: #1a1a2e; color: #e0e0e0;
        border: 1px solid #8b0000; border-radius: 12px;
        padding: 28px 32px; max-width: 480px; width: 90%;
        box-shadow: 0 8px 48px rgba(139,0,0,0.5);
      }
      #ms-modal .ms-header {
        display: flex; align-items: center; gap: 12px; margin-bottom: 20px;
      }
      #ms-modal .ms-shield {
        font-size: 32px; line-height: 1;
      }
      #ms-modal .ms-title {
        font-size: 18px; font-weight: 700; color: #ff4444;
        margin: 0;
      }
      #ms-modal .ms-subtitle {
        font-size: 12px; color: #888; margin: 4px 0 0;
      }
      #ms-modal .ms-row {
        display: flex; gap: 8px; margin: 8px 0; align-items: baseline;
      }
      #ms-modal .ms-label {
        font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em;
        color: #888; min-width: 90px;
      }
      #ms-modal .ms-value {
        font-size: 13px; color: #e0e0e0;
      }
      #ms-modal .ms-badge {
        display: inline-block; padding: 2px 8px; border-radius: 4px;
        font-size: 11px; font-weight: 700; text-transform: uppercase;
      }
      #ms-modal .ms-badge.critical { background: #8b0000; color: #fff; }
      #ms-modal .ms-badge.high     { background: #c0392b; color: #fff; }
      #ms-modal .ms-badge.medium   { background: #e67e22; color: #fff; }
      #ms-modal .ms-badge.low      { background: #2980b9; color: #fff; }
      #ms-modal .ms-badge.unknown  { background: #555;    color: #ccc; }
      #ms-modal .ms-regex {
        background: #0d0d1a; border: 1px solid #333; border-radius: 6px;
        padding: 8px 12px; font-family: monospace; font-size: 12px;
        color: #ff6b6b; word-break: break-all; margin: 10px 0;
        max-height: 60px; overflow-y: auto;
      }
      #ms-modal .ms-reasoning {
        font-size: 12px; color: #aaa; font-style: italic;
        margin: 8px 0 18px; line-height: 1.5;
      }
      #ms-modal .ms-actions {
        display: flex; gap: 12px; margin-top: 20px;
      }
      #ms-modal button {
        flex: 1; padding: 10px; border: none; border-radius: 8px;
        font-size: 14px; font-weight: 600; cursor: pointer;
        transition: opacity 0.15s;
      }
      #ms-modal button:hover { opacity: 0.85; }
      #ms-modal #ms-btn-block {
        background: #8b0000; color: #fff;
      }
      #ms-modal #ms-btn-allow {
        background: #1e3a1e; color: #4caf50;
        border: 1px solid #2e6b2e;
      }
      #ms-modal .ms-confidence {
        font-size: 11px; color: #888; text-align: right; margin-top: 4px;
      }
    `;
    document.head.appendChild(style);
  }

  function showWarningModal(match, url) {
    return new Promise((resolve) => {
      injectStyles();

      const overlay = document.createElement("div");
      overlay.id = "ms-overlay";

      const severity = (match.severity || "unknown").toLowerCase();
      const badgeClass = ["critical","high","medium","low"].includes(severity)
        ? severity : "unknown";

      const confidence = match.confidence != null
        ? `${Math.round(match.confidence * 100)}%` : "N/A";

      overlay.innerHTML = `
        <div id="ms-modal" role="alertdialog" aria-modal="true" aria-labelledby="ms-modal-title">
          <div class="ms-header">
            <span class="ms-shield">🛡️</span>
            <div>
              <p class="ms-title" id="ms-modal-title">⚠️ Suspicious Request Detected</p>
              <p class="ms-subtitle">MarvelShield AI WAF has flagged this outgoing request</p>
            </div>
          </div>

          <div class="ms-row">
            <span class="ms-label">Attack Type</span>
            <span class="ms-value">${escapeHtml(match.attack_type || "Unknown")}</span>
          </div>
          <div class="ms-row">
            <span class="ms-label">Severity</span>
            <span class="ms-badge ${badgeClass}">${escapeHtml(match.severity || "UNKNOWN")}</span>
          </div>
          <div class="ms-row">
            <span class="ms-label">Reference</span>
            <span class="ms-value">${escapeHtml(match.cve_reference || "—")}</span>
          </div>
          <div class="ms-row">
            <span class="ms-label">Destination</span>
            <span class="ms-value" style="font-size:11px;word-break:break-all;">${escapeHtml(url)}</span>
          </div>

          <div class="ms-row" style="margin-top:12px;">
            <span class="ms-label">Matched Pattern</span>
          </div>
          <div class="ms-regex">${escapeHtml(match.regex || "")}</div>

          ${match.reasoning ? `<p class="ms-reasoning">${escapeHtml(match.reasoning)}</p>` : ""}

          <div class="ms-confidence">AI Confidence: ${confidence}</div>

          <div class="ms-actions">
            <button id="ms-btn-block">🚫 Block Request</button>
            <button id="ms-btn-allow">⚠️ Allow Anyway</button>
          </div>
        </div>
      `;

      document.body.appendChild(overlay);

      overlay.querySelector("#ms-btn-block").addEventListener("click", () => {
        overlay.remove();
        chrome.runtime.sendMessage({ type: "REQUEST_BLOCKED" });
        resolve(false);
      });

      overlay.querySelector("#ms-btn-allow").addEventListener("click", () => {
        overlay.remove();
        chrome.runtime.sendMessage({ type: "REQUEST_ALLOWED" });
        resolve(true);
      });

      // Keyboard: Escape = block, Enter = allow
      const onKey = (e) => {
        if (e.key === "Escape")  { document.removeEventListener("keydown", onKey); overlay.querySelector("#ms-btn-block").click(); }
        if (e.key === "Enter")   { document.removeEventListener("keydown", onKey); overlay.querySelector("#ms-btn-allow").click(); }
      };
      document.addEventListener("keydown", onKey);
    });
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  // ─── Core inspection logic ───────────────────────────────────────────────────

  async function inspect(url, body) {
    const patches = await getPatches();
    if (!patches.length) return true; // no patches loaded, allow
    const match = findMatch(url, body);
    if (!match) return true; // clean
    return showWarningModal(match, url);
  }

  function bodyToString(body) {
    if (!body) return "";
    if (typeof body === "string") return body;
    if (body instanceof URLSearchParams) return body.toString();
    if (body instanceof FormData) {
      const parts = [];
      body.forEach((v, k) => parts.push(`${k}=${v}`));
      return parts.join("&");
    }
    try { return JSON.stringify(body); } catch { return ""; }
  }

  // ─── fetch override ─────────────────────────────────────────────────────────

  const _originalFetch = window.fetch.bind(window);
  window.fetch = async function (input, init = {}) {
    const url  = input instanceof Request ? input.url : String(input);
    const body = bodyToString(init.body || (input instanceof Request ? await input.clone().text().catch(() => "") : ""));
    const allowed = await inspect(url, body);
    if (!allowed) {
      return new Response(
        JSON.stringify({ error: "Blocked by MarvelShield browser extension", blocked: true }),
        { status: 403, headers: { "Content-Type": "application/json" } }
      );
    }
    return _originalFetch(input, init);
  };

  // ─── XMLHttpRequest override ─────────────────────────────────────────────────

  const _XHROpen = XMLHttpRequest.prototype.open;
  const _XHRSend = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function (method, url, ...rest) {
    this._msUrl = String(url);
    return _XHROpen.call(this, method, url, ...rest);
  };

  XMLHttpRequest.prototype.send = function (body) {
    const xhrSelf = this;
    const url     = this._msUrl || "";
    const bodyStr = bodyToString(body);

    // We use a detached async flow: pause with a dummy timeout, then decide
    inspect(url, bodyStr).then((allowed) => {
      if (allowed) {
        _XHRSend.call(xhrSelf, body);
      } else {
        // Synthesise a blocked 403 response
        Object.defineProperty(xhrSelf, "status",       { get: () => 403 });
        Object.defineProperty(xhrSelf, "responseText", { get: () => '{"error":"Blocked by MarvelShield"}' });
        Object.defineProperty(xhrSelf, "readyState",   { get: () => 4 });
        xhrSelf.dispatchEvent(new Event("readystatechange"));
        xhrSelf.dispatchEvent(new Event("load"));
      }
    });
  };

  // Bootstrap cache on page load
  refreshCache();
})();
