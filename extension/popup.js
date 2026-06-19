// popup.js — Web Safety Scanner v1.1

const API         = "http://127.0.0.1:5000";
const MAX_HISTORY = 50;

// ── DOM refs ──────────────────────────────────────────────────────────────────
const serverDot    = document.getElementById("serverDot");
const urlBar       = document.getElementById("urlBar");
const scanningState= document.getElementById("scanningState");
const resultCard   = document.getElementById("resultCard");
const resultIcon   = document.getElementById("resultIcon");
const resultLabel  = document.getElementById("resultLabel");
const resultSub    = document.getElementById("resultSub");
const scoreVal     = document.getElementById("scoreVal");
const barFill      = document.getElementById("barFill");
const flagsList    = document.getElementById("flagsList");
const explainBox   = document.getElementById("explainBox");
const metaRow      = document.getElementById("metaRow");
const mlConf       = document.getElementById("mlConf");
const ruleScore    = document.getElementById("ruleScore");
const domainAge    = document.getElementById("domainAge");
const errorBox     = document.getElementById("errorBox");
const scanBtn      = document.getElementById("scanBtn");
const scanTime     = document.getElementById("scanTime");
const historyEmpty = document.getElementById("historyEmpty");
const historyItems = document.getElementById("historyItems");
const clearBtn     = document.getElementById("clearBtn");

// ── Server check ──────────────────────────────────────────────────────────────
async function checkServer() {
  try {
    const r = await fetch(`${API}/health`, { signal: AbortSignal.timeout(2000) });
    if (r.ok) { serverDot.className = "server-dot"; return true; }
  } catch (_) {}
  serverDot.className = "server-dot offline";
  return false;
}

// ── Risk explanation ──────────────────────────────────────────────────────────
function buildExplanation(data) {
  if (data.result === "SAFE") return null;
  const flags = (data.flags || []).filter(f => f.bad);
  if (flags.length === 0) return null;

  const lead = data.result === "DANGEROUS"
    ? "⚠️ This website shows multiple signs of a phishing or malicious site."
    : "🔎 This website has some suspicious characteristics worth noting.";

  const explanations = {
    "ip address":         "Legitimate websites use domain names, not raw IP addresses.",
    "brand impersonation":"The URL contains a well-known brand but is not the official domain — a classic phishing tactic.",
    "suspicious tld":     "TLDs like .xyz .tk .ml are commonly used in throwaway phishing sites.",
    "no https":           "Without HTTPS, any data you enter can be intercepted.",
    "very new domain":    "Phishing sites are often registered days before an attack.",
    "young domain":       "Newly registered domains are statistically more likely to be malicious.",
    "url shortener":      "URL shorteners hide the real destination.",
    "suspicious keywords":"Keywords like 'login', 'verify' in URLs are common in credential-harvesting pages.",
    "@ symbol":           "A @ in a URL hides the true destination.",
    "excessive hyphens":  "Multiple hyphens are used to mimic legitimate domains.",
  };

  const matched = flags.map(f => {
    const key = Object.keys(explanations).find(k => f.text.toLowerCase().includes(k));
    return key ? explanations[key] : null;
  }).filter(Boolean).slice(0, 2);

  if (matched.length === 0) return null;
  return `<b>${lead}</b> ${matched.join(" ")}`;
}

// ── UI States ─────────────────────────────────────────────────────────────────
function resetAll() {
  scanningState.style.display = "none";
  resultCard.style.display    = "none";
  flagsList.style.display     = "none";
  explainBox.style.display    = "none";
  metaRow.style.display       = "none";
  errorBox.style.display      = "none";
}

function setScanning() {
  resetAll();
  scanningState.style.display = "flex";
  scanBtn.disabled = true;
  scanBtn.innerHTML = '<div class="spinner"></div><span>Scanning...</span>';
}

function setResult(data) {
  resetAll();
  const r     = (data.result || "SAFE").toUpperCase();
  const score = data.safety_score ?? (100 - (data.risk ?? 0));
  const cls   = { SAFE:"safe", SUSPICIOUS:"suspicious", DANGEROUS:"dangerous" }[r] || "safe";

  resultCard.className     = "result-card " + cls;
  resultCard.style.display = "block";
  resultIcon.textContent   = { SAFE:"✅", SUSPICIOUS:"⚠️", DANGEROUS:"🚨" }[r] || "🔍";
  resultLabel.className    = "result-label " + cls;
  resultLabel.textContent  = { SAFE:"Safe", SUSPICIOUS:"Suspicious", DANGEROUS:"Dangerous!" }[r] || r;
  resultSub.textContent    = `Risk: ${data.risk ?? "—"}/100`;

  scoreVal.textContent      = `${score}/100`;
  barFill.style.background  = cls === "safe"
    ? "linear-gradient(90deg,#059669,#10b981)"
    : cls === "suspicious"
    ? "linear-gradient(90deg,#d97706,#f59e0b)"
    : "linear-gradient(90deg,#be123c,#f43f5e)";
  barFill.style.width = "0%";
  setTimeout(() => { barFill.style.width = score + "%"; }, 60);

  const flags = data.flags || [];
  if (flags.length > 0) {
    flagsList.style.display = "flex";
    flagsList.innerHTML = "";
    flags.slice(0, 6).forEach(f => {
      const d = document.createElement("div");
      d.className = "flag " + (f.bad ? "bad" : "good");
      d.innerHTML = `<span class="flag-icon">${f.icon}</span><span>${f.text}</span>`;
      flagsList.appendChild(d);
    });
  }

  const explanation = buildExplanation(data);
  if (explanation) {
    explainBox.style.display = "block";
    explainBox.innerHTML     = explanation;
  }

  metaRow.style.display = "flex";
  mlConf.textContent    = data.ml_confidence != null ? `${Math.round(data.ml_confidence * 100)}%` : "—";
  ruleScore.textContent = data.rule_score    != null ? `${data.rule_score}` : "—";
  domainAge.textContent = data.domain_age_days != null
    ? data.domain_age_days < 365 ? `${data.domain_age_days}d` : `${Math.floor(data.domain_age_days/365)}y`
    : "—";

  scanBtn.disabled = false;
  scanBtn.innerHTML = '<span>🔄</span><span>Scan again</span>';
}

function setError() {
  resetAll();
  errorBox.style.display = "block";
  scanBtn.disabled = false;
  scanBtn.innerHTML = '<span>🔁</span><span>Try again</span>';
}

function setReady() {
  resetAll();
  scanBtn.disabled = false;
  scanBtn.innerHTML = '<span>🔍</span><span>Scan this page</span>';
}

// ── History ───────────────────────────────────────────────────────────────────
async function loadHistory() {
  const s = await chrome.storage.local.get("scanHistory");
  return s.scanHistory || [];
}

function timeAgo(ts) {
  const diff = Date.now() - ts;
  if (diff < 60000)    return "just now";
  if (diff < 3600000)  return `${Math.floor(diff/60000)}m ago`;
  if (diff < 86400000) return `${Math.floor(diff/3600000)}h ago`;
  return `${Math.floor(diff/86400000)}d ago`;
}

async function renderHistory() {
  const history = await loadHistory();
  historyItems.innerHTML = "";

  if (history.length === 0) {
    historyEmpty.style.display = "block";
    clearBtn.style.display     = "none";
    return;
  }
  historyEmpty.style.display = "none";
  clearBtn.style.display     = "block";

  history.forEach(h => {
    const cls = (h.result || "SAFE").toLowerCase();
    let domain = h.url;
    try { domain = new URL(h.url).hostname; } catch (_) {}

    const div = document.createElement("div");
    div.className = "history-item";
    div.innerHTML = `
      <div class="h-dot ${cls}"></div>
      <div class="h-info">
        <div class="h-domain" title="${h.url}">${domain}</div>
        <div class="h-time">${timeAgo(h.timestamp)} · Risk ${h.risk ?? "—"}/100</div>
      </div>
      <div class="h-badge ${cls}">${h.result}</div>`;
    historyItems.appendChild(div);
  });
}

// ── Scan ──────────────────────────────────────────────────────────────────────
async function scan(url) {
  setScanning();
  const t = Date.now();
  try {
    const res = await fetch(`${API}/check`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url }),
      signal:  AbortSignal.timeout(12000),
    });
    if (!res.ok) throw new Error("HTTP " + res.status);
    const data = await res.json();
    setResult(data);
    scanTime.textContent = (Date.now() - t) + "ms";
    chrome.storage.local.set({ lastResult: data, lastUrl: url });
  } catch (e) {
    setError();
  }
}

// ── Init ──────────────────────────────────────────────────────────────────────
async function init() {
  await checkServer();

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url   = tab?.url || "";

  try {
    const p = new URL(url);
    urlBar.textContent = p.hostname + (p.pathname.length > 1 ? p.pathname.slice(0, 20) + "…" : "");
  } catch (_) {
    urlBar.textContent = url.slice(0, 50) || "No URL";
  }

  // Load cached result
  const stored = await chrome.storage.local.get(["lastResult", "lastUrl"]);
  if (stored.lastResult && stored.lastUrl === url) {
    setResult(stored.lastResult);
  } else {
    setReady();
  }

  // Tab switching — defined here so renderHistory is already declared above
  document.querySelectorAll(".tab").forEach(tabEl => {
    tabEl.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
      tabEl.classList.add("active");
      document.getElementById("tab-" + tabEl.dataset.tab).classList.add("active");
      if (tabEl.dataset.tab === "history") renderHistory();
    });
  });

  // Clear history button
  if (clearBtn) {
    clearBtn.addEventListener("click", async () => {
      await chrome.storage.local.set({ scanHistory: [] });
      renderHistory();
    });
  }

  // Scan button
  scanBtn.addEventListener("click", async () => {
    if (!url || url.startsWith("chrome://")) return;
    const online = await checkServer();
    if (!online) { setError(); return; }
    scan(url);
  });
}

init();