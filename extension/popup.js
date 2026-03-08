// MarvelShield popup — enhanced UI with gateway live stats

const STORAGE_KEY_PATCHES = "ms_patches";
const STORAGE_KEY_STATS   = "ms_stats";
const STORAGE_KEY_STATUS  = "ms_connection_status";
const STORAGE_KEY_TOKEN   = "ms_auth_token";

const DASHBOARD_URL    = "http://localhost:3000";
const DASHBOARD_HEALTH = "http://localhost:3000/health";
const LOGIN_URL        = "http://localhost:3000/api/login";
const AUTH_CHECK_URL   = "http://localhost:3000/api/auth/check";
const LOGOUT_URL       = "http://localhost:3000/api/logout";

const SIGNUP_URL       = "http://localhost:3000/api/signup";

// ─── Login Screen ─────────────────────────────────────────────────────────────

const loginScreen     = document.getElementById("login-screen");
const signupScreen    = document.getElementById("signup-screen");
const mainContainer   = document.getElementById("main-container");
const extLoginForm    = document.getElementById("ext-login-form");
const extUserInput    = document.getElementById("ext-user");
const extPassInput    = document.getElementById("ext-pass");
const extLoginError   = document.getElementById("ext-login-error");
const extLoginBtn     = document.getElementById("ext-login-btn");
const extSignupForm   = document.getElementById("ext-signup-form");
const extSignupError  = document.getElementById("ext-signup-error");
const extSignupBtn    = document.getElementById("ext-signup-btn");

function showLogin()  { loginScreen.classList.remove("hidden"); signupScreen.classList.add("hidden"); mainContainer.classList.add("hidden"); }
function showSignup() { signupScreen.classList.remove("hidden"); loginScreen.classList.add("hidden"); mainContainer.classList.add("hidden"); }
function showMain()   { loginScreen.classList.add("hidden"); signupScreen.classList.add("hidden"); mainContainer.classList.remove("hidden"); }

document.getElementById("go-signup").addEventListener("click", e => { e.preventDefault(); showSignup(); });
document.getElementById("go-login").addEventListener("click",  e => { e.preventDefault(); showLogin(); });

async function checkAuth() {
  const token = await getStoredToken();
  if (!token) { showLogin(); return; }
  try {
    const res  = await fetch(AUTH_CHECK_URL, { headers: { "x-auth-token": token } });
    const data = await res.json();
    if (data.valid) { showMain(); }
    else { await chrome.storage.local.remove(STORAGE_KEY_TOKEN); showLogin(); }
  } catch { showMain(); }
}

async function getStoredToken() {
  return new Promise(resolve => {
    chrome.storage.local.get(STORAGE_KEY_TOKEN, r => resolve(r[STORAGE_KEY_TOKEN] || null));
  });
}

extLoginForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = extUserInput.value.trim();
  const password = extPassInput.value;
  if (!username || !password) { extLoginError.textContent = "Enter username and password"; return; }
  extLoginBtn.disabled = true; extLoginBtn.textContent = "Verifying…"; extLoginError.textContent = "";
  try {
    const res  = await fetch(LOGIN_URL, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username, password }) });
    const data = await res.json();
    if (data.success) { await chrome.storage.local.set({ [STORAGE_KEY_TOKEN]: data.token }); extPassInput.value = ""; showMain(); }
    else { extLoginError.textContent = data.error || "Invalid credentials"; extPassInput.value = ""; extPassInput.focus(); }
  } catch { extLoginError.textContent = "MarvelShield not running — start services first"; }
  finally { extLoginBtn.disabled = false; extLoginBtn.textContent = "Unlock"; }
});

extSignupForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const u = document.getElementById("su-user").value.trim();
  const p = document.getElementById("su-pass").value;
  const c = document.getElementById("su-conf").value;
  extSignupError.textContent = "";
  if (p !== c) { extSignupError.textContent = "Passwords do not match."; return; }
  extSignupBtn.disabled = true; extSignupBtn.textContent = "Creating…";
  try {
    const res  = await fetch(SIGNUP_URL, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username: u, password: p }) });
    const data = await res.json();
    if (data.success) { extSignupError.style.color = "#00e676"; extSignupError.textContent = "Account created! Please log in."; setTimeout(showLogin, 1200); }
    else { extSignupError.textContent = data.error || "Signup failed."; }
  } catch { extSignupError.textContent = "MarvelShield not running — start services first."; }
  finally { extSignupBtn.disabled = false; extSignupBtn.textContent = "Create Account"; }
});

// Logout button
document.getElementById("btn-logout").addEventListener("click", async () => {
  const token = await getStoredToken();
  if (token) {
    fetch(LOGOUT_URL, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ token }) }).catch(() => {});
    await chrome.storage.local.remove(STORAGE_KEY_TOKEN);
  }
  showLogin();
  extUserInput.value = ""; extPassInput.value = "";
});

// Run auth check on popup open
checkAuth();

// ─── Attack Definitions ───────────────────────────────────────────────────────
const ATTACK_DEFINITIONS = {
  'SQL Injection':      'Malicious SQL code inserted into query inputs, granting unauthorized read/write access to the database.',
  'XSS':               'Cross-Site Scripting — injected scripts run in other users\' browsers, enabling session hijacking or credential theft.',
  'Command Injection':  'Unsanitised input passed to an OS shell lets the attacker execute arbitrary commands on the server.',
  'Code Injection':     'Language-level code (eval/exec/system) injected and executed inside the application — leads to full Remote Code Execution.',
  'Path Traversal':     '"../" sequences escape the web root, letting the attacker read or overwrite arbitrary server files.',
  'SSRF':               'Server-Side Request Forgery — server is tricked into querying internal services, bypassing firewall rules.',
  'LFI':               'Local File Inclusion — server includes an attacker-chosen local file, exposing source code or enabling log poisoning.',
  'RFI':               'Remote File Inclusion — server fetches and executes a remote attacker-controlled script (RCE).',
  'XXE':               'XML External Entity — crafted XML forces the parser to disclose local files or make internal network requests.',
  'LDAP Injection':    'Malicious LDAP syntax injected into directory queries can bypass authentication or leak user data.',
  'NoSQL Injection':   'Injected query operators manipulate NoSQL databases to bypass authentication or exfiltrate data.',
  'Open Redirect':     'Application redirects users to attacker-controlled URLs, enabling phishing and OAuth token theft.',
  'Template Injection':'Server-Side Template Injection (SSTI) — user input reaches a template engine unescaped, leading to RCE.',
};

// ─── DOM refs ────────────────────────────────────────────────────────────────

const statusBadge    = document.getElementById("status-badge");
const statusText     = document.getElementById("status-text");
const offlinePanel   = document.getElementById("offline-panel");
const statBlocked    = document.getElementById("stat-blocked");
const statAllowed    = document.getElementById("stat-allowed");
const statPatches    = document.getElementById("stat-patches");
const statIPs        = document.getElementById("stat-ips");
const browserBlocked = document.getElementById("browser-blocked");
const browserAllowed = document.getElementById("browser-allowed");
const patchList      = document.getElementById("patch-list");
const lastSyncEl     = document.getElementById("last-sync");
const syncDot        = document.getElementById("sync-dot");
const btnRefresh     = document.getElementById("btn-refresh");
const btnDashboard   = document.getElementById("btn-dashboard");
const refreshIcon    = document.getElementById("refresh-icon");

// ─── Animated counter ────────────────────────────────────────────────────────

function animateCounter(el, target) {
  const current = parseInt(el.textContent, 10) || 0;
  if (current === target) return;
  const diff     = target - current;
  const steps    = Math.min(Math.abs(diff), 20);
  const stepVal  = diff / steps;
  let   progress = 0;
  const interval = setInterval(() => {
    progress++;
    el.textContent = Math.round(current + stepVal * progress);
    if (progress >= steps) {
      el.textContent = target;
      clearInterval(interval);
    }
  }, 30);
}

// ─── Severity helpers ────────────────────────────────────────────────────────

function sevClass(severity) {
  const s = (severity || "").toLowerCase();
  if (s === "critical") return "sev-critical";
  if (s === "high")     return "sev-high";
  if (s === "medium")   return "sev-medium";
  if (s === "low")      return "sev-low";
  return "sev-unknown";
}

function escapeHtml(str) {
  return String(str || "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// ─── Render ──────────────────────────────────────────────────────────────────

function render() {
  chrome.storage.local.get(
    [STORAGE_KEY_PATCHES, STORAGE_KEY_STATS, STORAGE_KEY_STATUS],
    (result) => {
      const patches = result[STORAGE_KEY_PATCHES] || [];
      const stats   = result[STORAGE_KEY_STATS]   || {};
      const status  = result[STORAGE_KEY_STATUS]  || "disconnected";

      // Body class for shield animation
      document.body.className = status;

      // Status badge
      statusBadge.className = `status-badge ${status}`;
      statusText.textContent =
        status === "connected"   ? "LIVE"        :
        status === "connecting"  ? "Connecting"  : "Disconnected";

      // Offline help panel
      offlinePanel.classList.toggle("hidden", status !== "disconnected");

      // Gateway stats (animated counters)
      animateCounter(statBlocked, stats.gatewayBlocked       || 0);
      animateCounter(statAllowed, stats.gatewayTotalRequests || 0);
      animateCounter(statPatches, stats.gatewayPatches       ?? patches.length);
      animateCounter(statIPs,     stats.gatewayBannedIPs     || 0);

      // Browser stats
      if (browserBlocked) browserBlocked.textContent = stats.browserBlocked || 0;
      if (browserAllowed) browserAllowed.textContent = stats.browserAllowed || 0;

      // Last sync
      if (stats.lastSync) {
        const ago = Math.round((Date.now() - new Date(stats.lastSync).getTime()) / 1000);
        lastSyncEl.textContent = ago < 60
          ? `Synced ${ago}s ago`
          : `Synced ${Math.round(ago / 60)}m ago`;
        syncDot.classList.add("synced");
      } else {
        lastSyncEl.textContent = "Never synced";
        syncDot.classList.remove("synced");
      }

      // Patch list
      renderPatches(patches);
    }
  );
}

function renderPatches(patches) {
  if (patches.length === 0) {
    patchList.innerHTML = `
      <div class="empty-state">
        <span class="empty-icon">🔍</span>
        <p>No patches loaded yet.</p>
        <p class="empty-sub">Patches appear after attacks are detected.</p>
      </div>`;
    return;
  }

  patchList.innerHTML = patches.map((p, i) => {
    const sev  = (p.severity || "UNKNOWN").toUpperCase();
    const conf = p.confidence != null ? Math.round(p.confidence * 100) : 0;
    return `
      <div class="patch-item" data-idx="${i}">
        <div class="patch-item-row">
          <span class="patch-name">${escapeHtml(p.attack_type || "Unknown")}</span>
          <span class="patch-sev ${sevClass(p.severity)}">${escapeHtml(sev)}</span>
          <span class="patch-toggle">▾</span>
        </div>
        <div class="patch-details">
          <div class="patch-regex-box">${escapeHtml(p.regex || "")}</div>
          <div class="patch-meta">
            ${p.cve_reference ? `<div><span>Ref: </span>${escapeHtml(p.cve_reference)}</div>` : ""}
            ${p.reasoning     ? `<div><span>Reason: </span>${escapeHtml(p.reasoning)}</div>` : ""}
            ${ATTACK_DEFINITIONS[p.attack_type] ? `<div class="patch-definition">${escapeHtml(ATTACK_DEFINITIONS[p.attack_type])}</div>` : ""}
            <div><span>Confidence: </span>${conf}%</div>
          </div>
          <div class="confidence-bar">
            <div class="confidence-fill" style="width:${conf}%"></div>
          </div>
        </div>
      </div>`;
  }).join("");

  patchList.querySelectorAll(".patch-item").forEach((el) => {
    el.addEventListener("click", () => el.classList.toggle("expanded"));
  });
}

// ─── Dashboard button — with reachability check ──────────────────────────────

async function openDashboard() {
  btnDashboard.disabled = true;
  btnDashboard.querySelector("span").textContent = "Checking…";

  try {
    const res = await fetch(DASHBOARD_HEALTH, {
      signal: AbortSignal.timeout(2500),
      cache: "no-store",
    });
    if (res.ok) {
      getStoredToken().then(token => {
        const url = token ? (DASHBOARD_URL + "/?token=" + token) : DASHBOARD_URL;
        chrome.tabs.create({ url });
      });
    } else {
      showDashboardOffline();
    }
  } catch {
    showDashboardOffline();
  } finally {
    btnDashboard.disabled = false;
    btnDashboard.querySelector("span").textContent = "Open Dashboard";
  }
}

function showDashboardOffline() {
  btnDashboard.style.background = "linear-gradient(135deg,#555,#333)";
  btnDashboard.querySelector("span").textContent = "Not Reachable";
  setTimeout(() => {
    btnDashboard.style.background = "";
    btnDashboard.querySelector("span").textContent = "Open Dashboard";
  }, 2000);
}

// ─── Refresh button ──────────────────────────────────────────────────────────

btnRefresh.addEventListener("click", () => {
  btnRefresh.classList.add("spinning");
  chrome.runtime.sendMessage({ type: "SYNC_NOW" }, () => {
    setTimeout(() => {
      btnRefresh.classList.remove("spinning");
      render();
    }, 1000);
  });
});

// ─── Wiring ──────────────────────────────────────────────────────────────────

btnDashboard.addEventListener("click", openDashboard);

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local") render();
});

// ─── Boot ────────────────────────────────────────────────────────────────────

render();
setInterval(render, 5_000);


// ─── Animated counter ────────────────────────────────────────────────────────

function animateCounter(el, target) {
  const current = parseInt(el.textContent, 10) || 0;
  if (current === target) return;
  const diff     = target - current;
  const steps    = Math.min(Math.abs(diff), 20);
  const stepVal  = diff / steps;
  let   progress = 0;
  const interval = setInterval(() => {
    progress++;
    el.textContent = Math.round(current + stepVal * progress);
    if (progress >= steps) {
      el.textContent = target;
      clearInterval(interval);
    }
  }, 30);
}

// ─── Severity helpers ────────────────────────────────────────────────────────

function sevClass(severity) {
  const s = (severity || "").toLowerCase();
  if (s === "critical") return "sev-critical";
  if (s === "high")     return "sev-high";
  if (s === "medium")   return "sev-medium";
  if (s === "low")      return "sev-low";
  return "sev-unknown";
}

function escapeHtml(str) {
  return String(str || "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// ─── Render ──────────────────────────────────────────────────────────────────

function render() {
  chrome.storage.local.get(
    [STORAGE_KEY_PATCHES, STORAGE_KEY_STATS, STORAGE_KEY_STATUS],
    (result) => {
      const patches = result[STORAGE_KEY_PATCHES] || [];
      const stats   = result[STORAGE_KEY_STATS]   || {};
      const status  = result[STORAGE_KEY_STATUS]  || "disconnected";

      // Body class for shield animation
      document.body.className = status;

      // Status badge
      statusBadge.className = `status-badge ${status}`;
      statusText.textContent =
        status === "connected"   ? "LIVE"        :
        status === "connecting"  ? "Connecting"  : "Disconnected";

      // Offline help panel
      if (status === "disconnected") {
        offlinePanel.classList.remove("hidden");
      } else {
        offlinePanel.classList.add("hidden");
      }

      // Stats (animated counters)
      animateCounter(statBlocked, stats.blockedCount     || 0);
      animateCounter(statAllowed, stats.allowedCount     || 0);
      animateCounter(statPatches, patches.length);
      animateCounter(statIPs,     stats.ipBlocklistCount || 0);

      // Last sync
      if (stats.lastSync) {
        const ago = Math.round((Date.now() - new Date(stats.lastSync).getTime()) / 1000);
        lastSyncEl.textContent = ago < 60
          ? `Synced ${ago}s ago`
          : `Synced ${Math.round(ago / 60)}m ago`;
        syncDot.classList.add("synced");
      } else {
        lastSyncEl.textContent = "Never synced";
        syncDot.classList.remove("synced");
      }

      // Patch list
      renderPatches(patches);
    }
  );
}

function renderPatches(patches) {
  if (patches.length === 0) {
    patchList.innerHTML = `
      <div class="empty-state">
        <span class="empty-icon">🔍</span>
        <p>No patches loaded yet.</p>
        <p class="empty-sub">Patches appear after attacks are detected.</p>
      </div>`;
    return;
  }

  patchList.innerHTML = patches.map((p, i) => {
    const sev  = (p.severity || "UNKNOWN").toUpperCase();
    const conf = p.confidence != null ? Math.round(p.confidence * 100) : 0;
    return `
      <div class="patch-item" data-idx="${i}">
        <div class="patch-item-row">
          <span class="patch-name">${escapeHtml(p.attack_type || "Unknown")}</span>
          <span class="patch-sev ${sevClass(p.severity)}">${escapeHtml(sev)}</span>
          <span class="patch-toggle">▾</span>
        </div>
        <div class="patch-details">
          <div class="patch-regex-box">${escapeHtml(p.regex || "")}</div>
          <div class="patch-meta">
            ${p.cve_reference ? `<div><span>Ref: </span>${escapeHtml(p.cve_reference)}</div>` : ""}
            ${p.reasoning     ? `<div><span>Reason: </span>${escapeHtml(p.reasoning)}</div>` : ""}
            ${ATTACK_DEFINITIONS[p.attack_type] ? `<div class="patch-definition">${escapeHtml(ATTACK_DEFINITIONS[p.attack_type])}</div>` : ""}
            <div><span>Confidence: </span>${conf}%</div>
          </div>
          <div class="confidence-bar">
            <div class="confidence-fill" style="width:${conf}%"></div>
          </div>
        </div>
      </div>`;
  }).join("");

  // Expand/collapse on click
  patchList.querySelectorAll(".patch-item").forEach((el) => {
    el.addEventListener("click", () => el.classList.toggle("expanded"));
  });
}

// ─── Dashboard button — with reachability check ──────────────────────────────

async function openDashboard() {
  btnDashboard.disabled = true;
  btnDashboard.querySelector("span").textContent = "Checking…";

  try {
    const res = await fetch(DASHBOARD_HEALTH, {
      signal: AbortSignal.timeout(2500),
      cache: "no-store",
    });
    if (res.ok) {
      getStoredToken().then(token => {
        const url = token ? (DASHBOARD_URL + "/?token=" + token) : DASHBOARD_URL;
        chrome.tabs.create({ url });
      });
    } else {
      showDashboardOffline();
    }
  } catch {
    showDashboardOffline();
  } finally {
    btnDashboard.disabled = false;
    btnDashboard.querySelector("span").textContent = "Open Dashboard";
  }
}

function showDashboardOffline() {
  // Temporarily style button to show error
  btnDashboard.style.background = "linear-gradient(135deg,#555,#333)";
  btnDashboard.querySelector("span").textContent = "Not Reachable";
  setTimeout(() => {
    btnDashboard.style.background = "";
    btnDashboard.querySelector("span").textContent = "Open Dashboard";
  }, 2000);
}

// ─── Refresh button ──────────────────────────────────────────────────────────

btnRefresh.addEventListener("click", () => {
  btnRefresh.classList.add("spinning");
  // Ask the service worker to do a full sync (bridge + gateway)
  chrome.runtime.sendMessage({ type: "SYNC_NOW" }, () => {
    setTimeout(() => {
      btnRefresh.classList.remove("spinning");
      render();
    }, 1000);
  });
});

// ─── Wiring ──────────────────────────────────────────────────────────────────

btnDashboard.addEventListener("click", openDashboard);

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local") render();
});

// ─── Boot ────────────────────────────────────────────────────────────────────

// Immediately sync on popup open so user always sees fresh data
chrome.runtime.sendMessage({ type: "SYNC_NOW" }, () => render());

// While popup is open, re-sync every 10 seconds for live monitoring
setInterval(() => {
  chrome.runtime.sendMessage({ type: "SYNC_NOW" }, () => render());
}, 10_000);

// Also re-render from storage every 3 seconds (catches storage changes from background sync)
setInterval(render, 3_000);