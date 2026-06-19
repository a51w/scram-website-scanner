// content.js — SHAKE CHECK overlay (แสดงทุกเว็บ ไม่มีข้อยกเว้น)

(function () {
  "use strict";

  // ── ป้องกัน inject ซ้ำ ───────────────────────────────────────────────────
  if (document.getElementById("sc-root")) return;

  let hideTimer = null;

  // ── Inject styles ─────────────────────────────────────────────────────────
  const style = document.createElement("style");
  style.textContent = `
    #sc-root {
      position: fixed;
      bottom: 24px;
      right: 24px;
      z-index: 2147483647;
      font-family: 'Segoe UI', Tahoma, sans-serif;
    }
    #sc-panel {
      width: 270px;
      background: #0f172a;
      border: 1px solid #1e293b;
      border-radius: 14px;
      overflow: hidden;
      box-shadow: 0 20px 50px rgba(0,0,0,0.6);
      animation: sc-in 0.35s cubic-bezier(0.34,1.56,0.64,1) forwards;
      opacity: 0;
    }
    @keyframes sc-in {
      from { opacity:0; transform:translateY(16px) scale(0.94); }
      to   { opacity:1; transform:translateY(0)    scale(1);    }
    }
    @keyframes sc-out {
      from { opacity:1; transform:translateY(0)    scale(1);    }
      to   { opacity:0; transform:translateY(16px) scale(0.94); }
    }
    #sc-header {
      background: #1e293b;
      padding: 9px 12px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      border-bottom: 1px solid #334155;
    }
    #sc-header-left { display:flex; align-items:center; gap:7px; }
    #sc-logo-text { font-size:11px; font-weight:700; color:#f1f5f9; letter-spacing:.5px; }
    #sc-close {
      background:none; border:none; color:#64748b;
      cursor:pointer; font-size:15px; line-height:1; padding:0;
      transition: color .15s;
    }
    #sc-close:hover { color:#f1f5f9; }
    #sc-body { padding:13px; }

    /* scanning */
    #sc-scanning { display:flex; align-items:center; gap:9px; color:#94a3b8; font-size:12px; }
    .sc-spin {
      width:16px; height:16px; border-radius:50%;
      border:2px solid #334155; border-top-color:#6366f1;
      animation: sc-spinner .7s linear infinite; flex-shrink:0;
    }
    @keyframes sc-spinner { to { transform:rotate(360deg); } }

    /* result */
    #sc-result { display:none; }
    #sc-verdict {
      display:flex; align-items:center; gap:9px;
      margin-bottom:9px;
    }
    #sc-verdict-icon { font-size:26px; line-height:1; }
    #sc-verdict-label { font-size:14px; font-weight:700; }
    #sc-verdict-label.safe       { color:#10b981; }
    #sc-verdict-label.suspicious { color:#f59e0b; }
    #sc-verdict-label.dangerous  { color:#f43f5e; }

    /* bar */
    #sc-bar-wrap { margin-bottom:9px; }
    #sc-bar-track {
      height:5px; background:#1e293b; border-radius:3px;
      overflow:hidden; margin-bottom:3px;
    }
    #sc-bar-fill { height:100%; border-radius:3px; transition:width .9s ease; width:0; }
    #sc-bar-labels {
      display:flex; justify-content:space-between;
      font-size:9px; color:#475569; letter-spacing:.4px;
    }

    /* flags */
    #sc-flags { display:flex; flex-direction:column; gap:3px; }
    .sc-flag {
      display:flex; align-items:center; gap:7px;
      font-size:11px; padding:4px 7px; border-radius:5px;
    }
    .sc-flag.bad  { background:rgba(244,63,94,.08);  color:#fca5a5; }
    .sc-flag.good { background:rgba(16,185,129,.07); color:#86efac; }

    /* error */
    #sc-error {
      display:none; font-size:11px; color:#94a3b8;
      text-align:center; padding:4px 0; flex-direction:column; gap:3px;
    }
    #sc-error small { font-size:9px; color:#475569; }

    /* glow */
    .sc-glow-safe    { box-shadow:0 20px 50px rgba(16,185,129,.15),0 0 0 1px rgba(16,185,129,.2)!important; }
    .sc-glow-warn    { box-shadow:0 20px 50px rgba(245,158,11,.12),0 0 0 1px rgba(245,158,11,.2)!important; }
    .sc-glow-danger  { box-shadow:0 20px 50px rgba(244,63,94,.18), 0 0 0 1px rgba(244,63,94,.25)!important; }
  `;
  document.head.appendChild(style);

  // ── Build DOM ─────────────────────────────────────────────────────────────
  const root = document.createElement("div");
  root.id = "sc-root";
  root.innerHTML = `
    <div id="sc-panel">
      <div id="sc-header">
        <div id="sc-header-left">
          <span>🛡️</span>
          <span id="sc-logo-text">SHAKE CHECK</span>
        </div>
        <button id="sc-close">✕</button>
      </div>
      <div id="sc-body">

        <div id="sc-scanning">
          <div class="sc-spin"></div>
          <span>verifying...</span>
        </div>

        <div id="sc-result">
          <div id="sc-verdict">
            <span id="sc-verdict-icon"></span>
            <span id="sc-verdict-label"></span>
          </div>
          <div id="sc-bar-wrap">
            <div id="sc-bar-track"><div id="sc-bar-fill"></div></div>
            <div id="sc-bar-labels"><span>0</span><span>Safety Score</span><span>100</span></div>
          </div>
          <div id="sc-flags"></div>
        </div>

        <div id="sc-error">
          <span>⚠️ Can't connect Backend</span>
          <small>ตรวจสอบว่า python app.py Loading...</small>
        </div>

      </div>
    </div>
  `;
  document.body.appendChild(root);

  // ── Close button ──────────────────────────────────────────────────────────
  document.getElementById("sc-close").addEventListener("click", hidePanel);

  // ── State helpers ─────────────────────────────────────────────────────────
  function showScanning() {
    clearTimeout(hideTimer);
    document.getElementById("sc-scanning").style.display = "flex";
    document.getElementById("sc-result").style.display   = "none";
    document.getElementById("sc-error").style.display    = "none";
    const panel = document.getElementById("sc-panel");
    panel.className = "";
    // restart animation
    panel.style.animation = "none";
    void panel.offsetWidth;
    panel.style.animation = "";
    root.style.display = "block";
  }

  function showResult(data) {
    clearTimeout(hideTimer);
    document.getElementById("sc-scanning").style.display = "none";
    document.getElementById("sc-error").style.display    = "none";
    document.getElementById("sc-result").style.display   = "block";

    const result = (data.result || "SAFE").toUpperCase();
    const score  = data.safety_score ?? (100 - (data.risk ?? 0));
    const panel  = document.getElementById("sc-panel");

    // Verdict icon + label
    const iconMap  = { SAFE:"✅", SUSPICIOUS:"⚠️", DANGEROUS:"🚨" };
    const labelMap = {
      SAFE:"Secure",
      SUSPICIOUS:"Suspicious",
      DANGEROUS:"Dangerous"
    };
    const classMap = { SAFE:"safe", SUSPICIOUS:"suspicious", DANGEROUS:"dangerous" };
    const glowMap  = { SAFE:"sc-glow-safe", SUSPICIOUS:"sc-glow-warn", DANGEROUS:"sc-glow-danger" };

    document.getElementById("sc-verdict-icon").textContent  = iconMap[result]  || "🔍";
    const lbl = document.getElementById("sc-verdict-label");
    lbl.textContent = labelMap[result] || result;
    lbl.className   = classMap[result] || "";

    // Bar
    const fill = document.getElementById("sc-bar-fill");
    const barColor = result === "SAFE"
      ? "linear-gradient(90deg,#059669,#10b981)"
      : result === "SUSPICIOUS"
      ? "linear-gradient(90deg,#d97706,#f59e0b)"
      : "linear-gradient(90deg,#be123c,#f43f5e)";
    fill.style.background = barColor;
    fill.style.width = "0%";
    setTimeout(() => { fill.style.width = score + "%"; }, 60);

    // Flags
    const flagsEl = document.getElementById("sc-flags");
    flagsEl.innerHTML = "";
    const flags = data.flags || [];
    flags.slice(0, 5).forEach(f => {
      const d = document.createElement("div");
      d.className = "sc-flag " + (f.bad ? "bad" : "good");
      d.innerHTML = `<span>${f.icon}</span><span>${f.text}</span>`;
      flagsEl.appendChild(d);
    });

    // Glow
    panel.className = glowMap[result] || "";

    // Auto-hide
    const delay = result === "SAFE" ? 4000 : result === "SUSPICIOUS" ? 7000 : 10000;
    hideTimer = setTimeout(hidePanel, delay);
  }

  function showError() {
    clearTimeout(hideTimer);
    document.getElementById("sc-scanning").style.display = "none";
    document.getElementById("sc-result").style.display   = "none";
    document.getElementById("sc-error").style.display    = "flex";
    hideTimer = setTimeout(hidePanel, 5000);
  }

  function hidePanel() {
    const panel = document.getElementById("sc-panel");
    if (!panel) return;
    panel.style.animation = "sc-out .2s ease forwards";
    setTimeout(() => { root.style.display = "none"; }, 200);
  }

  // ── Listen จาก background.js ──────────────────────────────────────────────
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === "SCAN_START")  showScanning();
    if (msg.type === "SCAN_RESULT") {
      if (msg.data && msg.data.result) showResult(msg.data);
      else showError();
    }
  });

})();