// background.js — Web Safety Scanner

const API_URL = "http://127.0.0.1:5000/check";
const cache   = new Map();
const CACHE_TTL = 5 * 60 * 1000;
const MAX_HISTORY = 50;

function shouldSkip(url) {
  return !url ||
    url.startsWith("chrome://") ||
    url.startsWith("chrome-extension://") ||
    url.startsWith("edge://") ||
    url.startsWith("about:") ||
    url.startsWith("devtools://");
}

// ── Save to history (called automatically on every page visit) ────────────────
async function saveHistory(url, data) {
  try {
    const stored = await chrome.storage.local.get("scanHistory");
    const history = stored.scanHistory || [];

    const entry = {
      url,
      result:    data.result,
      risk:      data.risk,
      score:     data.safety_score,
      timestamp: Date.now(),
    };

    // Remove duplicate, add to front
    const filtered = history.filter(h => h.url !== url);
    filtered.unshift(entry);

    await chrome.storage.local.set({
      scanHistory: filtered.slice(0, MAX_HISTORY)
    });
  } catch (e) {
    console.warn("saveHistory error:", e.message);
  }
}

// ── Scan URL ──────────────────────────────────────────────────────────────────
async function scanUrl(url) {
  const hit = cache.get(url);
  if (hit && Date.now() - hit.time < CACHE_TTL) return hit.result;

  try {
    const res = await fetch(API_URL, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url }),
    });
    if (!res.ok) throw new Error("HTTP " + res.status);
    const result = await res.json();
    cache.set(url, { result, time: Date.now() });
    return result;
  } catch (e) {
    console.error("Scan failed:", e.message);
    return null;
  }
}

// ── Badge ─────────────────────────────────────────────────────────────────────
function setBadge(tabId, result) {
  try {
    if (!chrome.action) return;
    if (!result) {
      chrome.action.setBadgeText({ text: "?", tabId });
      chrome.action.setBadgeBackgroundColor({ color: "#64748b", tabId });
      return;
    }
    const map = {
      SAFE:       { text: "OK",  color: "#10b981" },
      SUSPICIOUS: { text: "!!",  color: "#f59e0b" },
      DANGEROUS:  { text: "!!!", color: "#f43f5e" },
    };
    const b = map[result.result] || map.SAFE;
    chrome.action.setBadgeText({ text: b.text, tabId });
    chrome.action.setBadgeBackgroundColor({ color: b.color, tabId });
  } catch (e) {
    console.warn("setBadge error:", e.message);
  }
}

// ── Main listener — runs on EVERY page visit automatically ────────────────────
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete") return;
  if (shouldSkip(tab.url)) return;

  // Notify content script: scanning started
  try {
    await chrome.tabs.sendMessage(tabId, { type: "SCAN_START" });
  } catch (_) {
    await new Promise(r => setTimeout(r, 800));
    try { await chrome.tabs.sendMessage(tabId, { type: "SCAN_START" }); } catch (_) {}
  }

  const result = await scanUrl(tab.url);
  setBadge(tabId, result);

  const finalResult = result || { result: "SAFE", risk: 0, safety_score: 100, flags: [] };

  // ── Save to history automatically (every website visited) ─────────────────
  if (result) await saveHistory(tab.url, result);

  // Notify content script: result ready
  try {
    await chrome.tabs.sendMessage(tabId, {
      type: "SCAN_RESULT",
      data: finalResult,
    });
  } catch (_) {}

  // Notification for dangerous sites
  if (result && result.result === "DANGEROUS") {
    chrome.notifications.create({
      type:     "basic",
      iconUrl:  "icons/icon48.png",
      title:    "⚠️ Dangerous Website Detected!",
      message:  `This site may be phishing or malicious.\n${tab.url.slice(0, 80)}`,
      priority: 2,
    });
  }

  chrome.storage.local.set({ lastResult: result, lastUrl: tab.url });
});

// ── Messages from popup ───────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (msg.type === "RESCAN") {
    chrome.tabs.query({ active: true, currentWindow: true }, async ([tab]) => {
      if (!tab?.url || shouldSkip(tab.url)) return;
      cache.delete(tab.url);
      const result = await scanUrl(tab.url);
      setBadge(tab.id, result);
      if (result) await saveHistory(tab.url, result);
      chrome.storage.local.set({ lastResult: result, lastUrl: tab.url });
      reply({ result });
    });
    return true;
  }
});