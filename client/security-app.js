/**
 * PayVoice: Secure Multilingual Financial Agent
 * Client-Side Application Controller
 */

import { registerDevicePasskey, signStagedInvoiceWithPasskey } from "./js/passkey.js";

// Application State
let activeLanguage = "mr";
let recognition = null;
let currentStagedInvoice = null;
let currentActiveInvoiceId = null;
let sseConnection = null;
let pollingInterval = null;
let isAgentFrozenState = false;

// DOM Elements
const micZone = document.getElementById("mic-zone");
const micButton = document.getElementById("mic-button");
const micStatusHint = document.getElementById("mic-status-hint");
const transcriptInput = document.getElementById("transcript-input");
const btnProcessTranscript = document.getElementById("btn-process-transcript");
const activeLangBadge = document.getElementById("active-lang-badge");
const stagedCard = document.getElementById("staged-card");
const btnExecutePasskey = document.getElementById("btn-execute-passkey");
const checkAutoSettle = document.getElementById("check-auto-settle");
const btnSpeechRepeat = document.getElementById("btn-speech-repeat");
const btnManualSettle = document.getElementById("btn-manual-settle");
const liveInvoiceBadge = document.getElementById("live-invoice-badge");
const btnDownloadPdf = document.getElementById("btn-download-pdf");
const btnVerifyLedger = document.getElementById("btn-verify-ledger");
const buyerGrid = document.getElementById("buyer-grid");
const auditStreamBox = document.getElementById("audit-stream-box");

// Kill Switch elements
const btnKillSwitch = document.getElementById("btn-kill-switch");
const freezeAlertBanner = document.getElementById("freeze-alert-banner");
const btnUnfreezeBanner = document.getElementById("btn-unfreeze-banner");

// Staged preview elements
const previewBuyerName = document.getElementById("preview-buyer-name");
const previewBuyerDetails = document.getElementById("preview-buyer-details");
const previewAmount = document.getElementById("preview-amount");
const previewInr = document.getElementById("preview-inr");
const previewItem = document.getElementById("preview-item");
const previewQuantity = document.getElementById("preview-quantity");
const previewRbi = document.getElementById("preview-rbi");
const previewLut = document.getElementById("preview-lut");
const previewHash = document.getElementById("preview-hash");

// Risk assessment meter elements
const previewRiskBadge = document.getElementById("preview-risk-badge");
const previewRiskBar = document.getElementById("preview-risk-bar");
const previewLookalikePill = document.getElementById("preview-lookalike-pill");
const previewDeviationPill = document.getElementById("preview-deviation-pill");
const previewRiskScore = document.getElementById("preview-risk-score");

// Mobile QR handoff elements
const btnQrHandoff = document.getElementById("btn-qr-handoff");
const qrHandoffModal = document.getElementById("qr-handoff-modal");
const btnCloseQr = document.getElementById("btn-close-qr");
const qrGraphicBox = document.getElementById("qr-graphic-box");
const qrUrlDisplay = document.getElementById("qr-url-display");

// Timeline steps
const stepVoice = document.getElementById("step-voice");
const stepPolicy = document.getElementById("step-policy");
const stepAuth = document.getElementById("step-auth");
const stepDraft = document.getElementById("step-draft");
const stepSent = document.getElementById("step-sent");
const stepPaid = document.getElementById("step-paid");

/**
 * Initialize Speech Recognition
 */
function initSpeechRecognition() {
  const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (!SpeechRecognition) {
    micStatusHint.textContent = "Web Speech API not supported in this browser. Please type commands below.";
    return;
  }

  recognition = new SpeechRecognition();
  recognition.continuous = false;
  recognition.interimResults = false;

  const langMap = { mr: "mr-IN", hi: "hi-IN", en: "en-US" };
  recognition.lang = langMap[activeLanguage] || "mr-IN";

  recognition.onstart = () => {
    micZone.classList.add("recording");
    micButton.classList.add("recording");
    micStatusHint.textContent = "Listening... Speak your command in " + (activeLanguage === "mr" ? "Marathi" : activeLanguage === "hi" ? "Hindi" : "English");
  };

  recognition.onresult = (event) => {
    const transcript = event.results[0][0].transcript;
    transcriptInput.value = transcript;
    micStatusHint.textContent = `Captured: "${transcript}"`;
    // Zero-Touch Automation: Auto-stage immediately!
    handleVoiceCommand(transcript);
  };

  recognition.onerror = (event) => {
    console.warn("[Speech Error]:", event.error);
    micZone.classList.remove("recording");
    micButton.classList.remove("recording");
    micStatusHint.textContent = `Speech error (${event.error}). Click mic to retry or type below.`;
  };

  recognition.onend = () => {
    micZone.classList.remove("recording");
    micButton.classList.remove("recording");
  };
}

/**
 * Play audible read-back confirmation in localized language
 * @param {string} text
 * @param {string} lang
 */
function playAudioReadBack(text, lang = "mr") {
  if (!window.speechSynthesis || !text) return;
  try {
    window.speechSynthesis.cancel();
    const utterance = new SpeechSynthesisUtterance(text);
    const langMap = { mr: "mr-IN", hi: "hi-IN", en: "en-US" };
    utterance.lang = langMap[lang] || "en-US";
    utterance.rate = 1.0;
    utterance.pitch = 1.0;
    window.speechSynthesis.speak(utterance);
  } catch (err) {
    console.warn("[SpeechSynthesis Warning]:", err.message);
  }
}

/**
 * Reset timeline UI steps
 */
function resetTimeline() {
  [stepVoice, stepPolicy, stepAuth, stepDraft, stepSent, stepPaid].forEach((el) => {
    el.classList.remove("completed", "active");
  });
  liveInvoiceBadge.textContent = "STANDBY";
  liveInvoiceBadge.className = "badge-tag pulse-green";
  btnManualSettle.style.display = "none";
}

/**
 * Update timeline progress
 * @param {string} status
 */
function updateTimelineStatus(status) {
  liveInvoiceBadge.textContent = status;

  if (status === "STAGED") {
    stepVoice.classList.add("completed");
    stepPolicy.classList.add("completed");
    stepAuth.classList.add("active");
    liveInvoiceBadge.className = "badge-tag";
    liveInvoiceBadge.style.background = "#fef3c7";
    liveInvoiceBadge.style.color = "#92400e";
  } else if (status === "SENT") {
    stepVoice.classList.add("completed");
    stepPolicy.classList.add("completed");
    stepAuth.classList.add("completed");
    stepDraft.classList.add("completed");
    stepSent.classList.add("completed");
    stepPaid.classList.add("active");
    liveInvoiceBadge.className = "badge-tag";
    liveInvoiceBadge.style.background = "#dbeafe";
    liveInvoiceBadge.style.color = "#1e40af";
    btnManualSettle.style.display = "block";
  } else if (status === "PAID") {
    [stepVoice, stepPolicy, stepAuth, stepDraft, stepSent, stepPaid].forEach((el) => {
      el.classList.remove("active");
      el.classList.add("completed");
    });
    liveInvoiceBadge.className = "badge-tag pulse-green";
    liveInvoiceBadge.textContent = "PAID & SETTLED";
    btnManualSettle.style.display = "none";
  }
}

/**
 * Handle incoming voice or text command (Zero-Touch Staging)
 * @param {string} transcriptText
 */
async function handleVoiceCommand(transcriptText) {
  const text = transcriptText.trim();
  if (!text) return;

  micStatusHint.textContent = `Processing: "${text}"...`;
  resetTimeline();
  stepVoice.classList.add("active");

  try {
    const res = await fetch("/api/invoices/stage", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        transcript: text,
        language: activeLanguage,
      }),
    });

    const data = await res.json();

    if (!res.ok || !data.success) {
      if (res.status === 423 || data.error === "AGENT_FROZEN_BY_KILL_SWITCH") {
        updateKillSwitchUI(true, data.details || "Agent frozen");
        alert(`🚨 KILL SWITCH ACTIVE: ${data.details || "The agent is currently frozen. Resume it before staging invoices."}`);
        micStatusHint.textContent = "Agent frozen. Click 'Resume Agent' in top bar to resume.";
        return;
      }
      alert(`Staging Notice: ${data.details || data.error || data.message || "Failed to stage invoice"}`);
      micStatusHint.textContent = "Ready. Tap mic or type to retry.";
      return;
    }

    currentStagedInvoice = data;
    renderStagedPreview(data);
    updateTimelineStatus("STAGED");

    // Localized Audible Read-back
    const readBackText = data.readBackMessages?.[activeLanguage] || data.readBackMessages?.en;
    micStatusHint.textContent = `Staged! Speaking read-back: "${readBackText}"`;
    playAudioReadBack(readBackText, activeLanguage);

  } catch (err) {
    console.error("[Stage Error]:", err);
    alert("Connection error during invoice staging: " + err.message);
  }
}

/**
 * Render staged invoice preview card
 * @param {object} data
 */
function renderStagedPreview(data) {
  const card = data.previewCard || {};
  previewBuyerName.textContent = card.buyerDisplayName || "Overseas Buyer";
  previewBuyerDetails.textContent = `${card.buyerToken || ""} • ${card.buyerCompany || ""} • ${card.buyerCountry || ""}`;
  previewAmount.textContent = card.amountFormatted || `$${card.rawAmount} ${card.currency}`;
  previewInr.textContent = card.estInrFormatted || "~₹17,370 INR";
  previewItem.textContent = card.item || "Export Deliverable";
  previewQuantity.textContent = card.quantity || "1 Milestone";

  previewRbi.textContent = `RBI Export Code: ${card.rbiPurposeCode || "P0802"} (${card.rbiDescription || "Software Consultancy"})`;
  previewLut.textContent = card.lutStatus || "GST LUT: Rule 96A Zero-Rated (No IGST)";
  previewHash.textContent = `SHA-256: ${(card.payloadHash || "").slice(0, 16)}...`;

  // 4-Tier Dynamic Risk Assessment Meter
  const score = card.riskScore !== undefined ? card.riskScore : 25;
  const tier = card.riskTier || "LEVEL_2";
  const label = card.levelLabel || "Level 2 (Standard Risk)";

  if (previewRiskScore) previewRiskScore.textContent = `Score: ${score}/100`;
  if (previewRiskBar) {
    previewRiskBar.style.width = `${Math.min(100, Math.max(5, score))}%`;
    if (score <= 30) {
      previewRiskBar.style.background = "#10b981"; // Green
    } else if (score <= 75) {
      previewRiskBar.style.background = "#f59e0b"; // Amber/Orange
    } else {
      previewRiskBar.style.background = "#ef4444"; // Red
    }
  }

  if (previewRiskBadge) {
    previewRiskBadge.textContent = label;
    if (tier === "LEVEL_1") {
      previewRiskBadge.style.background = "#ecfdf5";
      previewRiskBadge.style.color = "#047857";
    } else if (tier === "LEVEL_2") {
      previewRiskBadge.style.background = "#dcfce7";
      previewRiskBadge.style.color = "#15803d";
    } else if (tier === "LEVEL_3") {
      previewRiskBadge.style.background = "#fef3c7";
      previewRiskBadge.style.color = "#b45309";
    } else {
      previewRiskBadge.style.background = "#fee2e2";
      previewRiskBadge.style.color = "#b91c1c";
    }
  }

  // Lookalike indicator
  if (previewLookalikePill) {
    if (card.lookalikeStatus === "SPOOFING_DETECTED") {
      previewLookalikePill.textContent = "⚠️ Lookalike Name: Spoofing Flagged";
      previewLookalikePill.className = "risk-sub-pill pill-danger";
    } else {
      previewLookalikePill.textContent = "✅ Lookalike Name: Authentic Allowlist";
      previewLookalikePill.className = "risk-sub-pill pill-ok";
    }
  }

  // Amount deviation indicator
  if (previewDeviationPill) {
    if (card.amountDeviationWarning) {
      previewDeviationPill.textContent = `⚠️ Amount Deviation: ${card.deviationRatio || ">2"}x Baseline`;
      previewDeviationPill.className = "risk-sub-pill pill-warn";
    } else {
      previewDeviationPill.textContent = "✅ Amount Deviation: Normal Baseline";
      previewDeviationPill.className = "risk-sub-pill pill-ok";
    }
  }

  stagedCard.style.display = "block";
  stagedCard.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

/**
 * Execute Invoice with Hardware Passkey (Atomic DRAFT -> SENT)
 */
async function executeInvoiceWithPasskey() {
  if (!currentStagedInvoice) {
    alert("No invoice is currently staged.");
    return;
  }

  const { stageId, webauthn } = currentStagedInvoice;
  btnExecutePasskey.disabled = true;
  btnExecutePasskey.innerHTML = `<span>⏳ Verifying Biometric Passkey...</span>`;

  try {
    // 1. Sign staged invoice with FIDO2 / WebCrypto passkey
    const assertion = await signStagedInvoiceWithPasskey({
      challengeId: webauthn.challengeId,
      challenge: webauthn.challenge,
      payloadHash: webauthn.payloadHash,
    });

    btnExecutePasskey.innerHTML = `<span>⚡ Dispatching to PayPal Sandbox...</span>`;

    // 2. Execute via Backend Gateway (Atomic DRAFT -> SENT)
    const autoSettle = checkAutoSettle.checked ? 5 : 0;
    const res = await fetch("/api/invoices/execute", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        stageId,
        challengeId: webauthn.challengeId,
        assertion,
        expectedPayloadHash: webauthn.payloadHash,
        autoSettleSeconds: autoSettle,
      }),
    });

    const result = await res.json();

    if (!res.ok || !result.success) {
      if (res.status === 423 || result.error === "AGENT_FROZEN_BY_KILL_SWITCH") {
        updateKillSwitchUI(true, result.details || "Agent frozen");
        throw new Error(`🚨 AGENT FROZEN: ${result.details || "Kill switch engaged. Execution blocked."}`);
      }
      throw new Error(result.details || result.error || "Failed to execute invoice");
    }

    currentActiveInvoiceId = result.invoiceId;
    updateTimelineStatus("SENT");
    btnExecutePasskey.innerHTML = `<span>✅ Dispatched to ${currentStagedInvoice.stagedPayload.buyerName}!</span>`;

    // Start auto-polling fallback if auto-settle enabled
    if (autoSettle > 0) {
      startInvoicePoller(result.invoiceId);
    }

    // Refresh ledger and CFO metrics
    loadAuditLedger();
    loadCfoMetrics();

  } catch (err) {
    console.error("[Execution Error]:", err);
    alert("Passkey execution failed: " + err.message);
    btnExecutePasskey.disabled = false;
    btnExecutePasskey.innerHTML = `<span>🔐 Authorize & Send Invoice with Biometric Passkey</span>`;
  }
}

/**
 * Poller fallback for watching active invoice status
 * @param {string} invoiceId
 */
function startInvoicePoller(invoiceId) {
  if (pollingInterval) clearInterval(pollingInterval);

  pollingInterval = setInterval(async () => {
    try {
      const res = await fetch(`/api/invoices/${invoiceId}/status`);
      if (res.ok) {
        const data = await res.json();
        if (data.status === "PAID") {
          updateTimelineStatus("PAID");
          clearInterval(pollingInterval);
          loadAuditLedger();
          loadCfoMetrics();
        }
      }
    } catch {
      // Ignore polling connection error
    }
  }, 2000);
}

/**
 * Connect to Server-Sent Events (SSE) live stream
 */
function initSseStream() {
  if (!window.EventSource) return;

  try {
    sseConnection = new EventSource("/api/invoices/stream");

    sseConnection.addEventListener("invoice_staged", (e) => {
      console.log("[SSE] Staged:", e.data);
    });

    sseConnection.addEventListener("invoice_sent", (e) => {
      const data = JSON.parse(e.data);
      if (data.invoiceId === currentActiveInvoiceId) {
        updateTimelineStatus("SENT");
      }
    });

    sseConnection.addEventListener("invoice_paid", (e) => {
      const data = JSON.parse(e.data);
      if (data.invoiceId === currentActiveInvoiceId || !currentActiveInvoiceId) {
        updateTimelineStatus("PAID");
        loadAuditLedger();
        loadCfoMetrics();
      }
    });
  } catch (e) {
    console.warn("[SSE Note]:", e.message);
  }
}

/**
 * Load CFO Intelligence Metrics from Backend
 */
async function loadCfoMetrics() {
  try {
    const res = await fetch("/api/transactions");
    if (!res.ok) return;
    const data = await res.json();
    const cfo = data.cfoInsights || {};

    if (cfo.totalGrossUsd !== undefined) {
      document.getElementById("cfo-gross-val").textContent = `$${cfo.totalGrossUsd.toFixed(2)}`;
    }
    if (cfo.totalEstimatedFeesUsd !== undefined) {
      document.getElementById("cfo-fee-val").textContent = `$${cfo.totalEstimatedFeesUsd.toFixed(2)}`;
    }
    if (cfo.formattedInrRealization) {
      document.getElementById("cfo-inr-val").textContent = cfo.formattedInrRealization;
    }
    if (cfo.opgspLimit?.remainingAllowanceUsd !== undefined) {
      document.getElementById("cfo-cap-val").textContent = `$${cfo.opgspLimit.remainingAllowanceUsd.toFixed(2)}`;
    }
  } catch (err) {
    console.warn("[CFO Metrics Error]:", err.message);
  }
}

/**
 * Load Pre-Seeded International Buyers from Vault
 */
async function loadBuyers() {
  try {
    const res = await fetch("/api/vault/buyers");
    if (!res.ok) return;
    const data = await res.json();
    const buyers = data.buyers || [];

    buyerGrid.innerHTML = "";
    buyers.forEach((b) => {
      const card = document.createElement("div");
      card.className = "buyer-card";
      card.innerHTML = `
        <div class="buyer-card-top">
          <div>
            <h4>${b.displayName}</h4>
            <p>${b.buyerToken} • ${b.company || "International Client"}</p>
          </div>
          <span class="badge-tag" style="background:#e0f2fe; color:#0284c7; font-size:11px;">${b.country}</span>
        </div>
        <p style="font-size:12px; color:var(--text-muted);">${b.maskedEmail}</p>
        <div class="buyer-default-pill">
          Contract: <strong>${b.defaultItem || "Cloud API Development"}</strong> (${b.defaultAmount || 200} ${b.currency})
        </div>
        <button class="btn-bill-client" data-token="${b.buyerToken}" data-name="${b.displayName}">
          ⚡ Bill ${b.displayName.split(" ")[0]} (${b.defaultAmount || 200} ${b.currency})
        </button>
      `;
      buyerGrid.appendChild(card);
    });

    // Wire "Bill Client" quick action
    document.querySelectorAll(".btn-bill-client").forEach((btn) => {
      btn.addEventListener("click", () => {
        const token = btn.getAttribute("data-token");
        const name = btn.getAttribute("data-name");
        const phrase = activeLanguage === "mr"
          ? `${name.split(" ")[0]} ला इनव्हॉईस पाठवा`
          : activeLanguage === "hi"
          ? `${name.split(" ")[0]} को इनवॉइस भेजो`
          : `Send invoice to ${name}`;
        transcriptInput.value = phrase;
        handleVoiceCommand(phrase);
      });
    });
  } catch (err) {
    console.warn("[Buyers Load Error]:", err.message);
  }
}

/**
 * Load and display recent Sequential Audit Ledger entries
 */
async function loadAuditLedger() {
  try {
    const res = await fetch("/api/audit-ledger");
    if (!res.ok) return;
    const data = await res.json();
    const ledger = data.ledger || [];

    auditStreamBox.innerHTML = "";
    ledger.slice(-10).reverse().forEach((row) => {
      const line = document.createElement("div");
      line.className = "audit-row";
      const timeStr = row.timestamp ? new Date(row.timestamp).toLocaleTimeString() : "";
      const hashShort = (row.rowHash || row.payloadHash || "").slice(0, 16);
      line.innerHTML = `
        <span class="time">[${timeStr}]</span>
        <span class="action">${row.status || row.event || "LOG"}</span>
        <span class="hash">Hash: ${hashShort}...</span>
      `;
      auditStreamBox.appendChild(line);
    });
  } catch (err) {
    console.warn("[Audit Ledger Error]:", err.message);
  }
}

/**
 * Download Encrypted Statement PDF
 */
async function downloadEncryptedStatement() {
  try {
    btnDownloadPdf.disabled = true;
    btnDownloadPdf.innerHTML = `<span>Generating AES Encrypted PDF...</span>`;

    const res = await fetch("/api/statements/export-pdf", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        dateRange: "Last 30 Days",
        userPassword: "PAYVOICE2026",
      }),
    });

    if (!res.ok) {
      throw new Error(`Failed to export PDF (${res.statusText})`);
    }

    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `PayVoice_Export_Statement_Last_30_Days.pdf`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    a.remove();

    btnDownloadPdf.disabled = false;
    btnDownloadPdf.innerHTML = `<span>Download Encrypted Statement (PDF)</span><span>🔒</span>`;
  } catch (err) {
    alert("Error downloading statement: " + err.message);
    btnDownloadPdf.disabled = false;
    btnDownloadPdf.innerHTML = `<span>Download Encrypted Statement (PDF)</span><span>🔒</span>`;
  }
}

/**
 * Verify Audit Ledger Integrity
 */
async function verifyAuditLedger() {
  try {
    const res = await fetch("/api/audit-ledger/verify");
    const data = await res.json();
    if (data.verified) {
      alert(`🛡️ Cryptographic Audit Ledger Verified PRISTINE!\n• Checked: ${data.totalEntries} sequential entries\n• Merkle Genesis Chain: Intact\n• Tampering Detected: ZERO`);
    } else {
      alert(`⚠️ Ledger Verification Alert: ${data.message || "Chain discrepancy detected"}`);
    }
  } catch (err) {
    alert("Ledger check error: " + err.message);
  }
}

/**
 * Check Kill Switch State from Backend
 */
async function checkKillSwitchState() {
  try {
    const res = await fetch("/api/security/kill-switch");
    const data = await res.json();
    if (data.success) {
      isAgentFrozenState = !!data.agentFrozen;
      updateKillSwitchUI(isAgentFrozenState, data.reason);
    }
  } catch (err) {
    console.warn("[Kill Switch Check Failed]:", err);
  }
}

/**
 * Update UI according to freeze status
 */
function updateKillSwitchUI(frozen, reason) {
  isAgentFrozenState = frozen;
  if (btnKillSwitch) {
    if (frozen) {
      btnKillSwitch.classList.add("frozen");
      btnKillSwitch.textContent = "❄️ Resume Agent";
      btnKillSwitch.title = "Click to resume agent operations";
    } else {
      btnKillSwitch.classList.remove("frozen");
      btnKillSwitch.textContent = "🛑 Freeze Agent";
      btnKillSwitch.title = "Emergency Kill Switch: Freeze or Resume Agent";
    }
  }
  if (freezeAlertBanner) {
    freezeAlertBanner.style.display = frozen ? "flex" : "none";
    if (frozen && reason) {
      const bannerSpan = freezeAlertBanner.querySelector("span");
      if (bannerSpan) {
        bannerSpan.innerHTML = `🚨 <strong>EMERGENCY KILL SWITCH ENGAGED:</strong> The PayVoice agent is FROZEN (${reason}). All invoice creation, staging, and dispatching are suspended.`;
      }
    }
  }
}

/**
 * Toggle Kill Switch
 */
async function toggleKillSwitch(freeze, reason = "Manual UI toggle") {
  try {
    const res = await fetch("/api/security/kill-switch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        freeze,
        reason: reason || (freeze ? "Emergency freeze requested by merchant" : "Merchant resumed agent"),
      }),
    });
    const data = await res.json();
    if (data.success) {
      updateKillSwitchUI(data.agentFrozen, data.reason);
      alert(data.agentFrozen ? "🛑 Agent has been FROZEN! All invoice staging and execution are halted." : "🟢 Agent operations RESUMED.");
    } else {
      alert("Failed to update Kill Switch: " + (data.error || "Unknown error"));
    }
  } catch (err) {
    alert("Kill Switch request error: " + err.message);
  }
}

/**
 * Standalone QR Code SVG Matrix Generator for Mobile Biometric Handoff
 * Encodes URL to QR Code Version 4 (33x33) with Reed-Solomon Error Correction Level L
 * @param {string} text
 * @returns {string} SVG XML markup
 */
function generateQrSvg(text) {
  try {
    const GF_EXP = new Uint8Array(512);
    const GF_LOG = new Uint8Array(256);
    let x = 1;
    for (let i = 0; i < 255; i++) {
      GF_EXP[i] = x;
      GF_LOG[x] = i;
      x <<= 1;
      if (x & 256) x ^= 0x11d;
    }
    for (let i = 255; i < 512; i++) {
      GF_EXP[i] = GF_EXP[i - 255];
    }

    function gfMul(a, b) {
      if (a === 0 || b === 0) return 0;
      return GF_EXP[GF_LOG[a] + GF_LOG[b]];
    }

    function rsGenPoly(n) {
      let poly = [1];
      for (let i = 0; i < n; i++) {
        const next = new Array(poly.length + 1).fill(0);
        for (let j = 0; j < poly.length; j++) {
          next[j] ^= gfMul(poly[j], GF_EXP[i]);
          next[j + 1] ^= poly[j];
        }
        poly = next;
      }
      return poly;
    }

    function rsEncode(data, ecCount) {
      const gen = rsGenPoly(ecCount);
      const res = new Uint8Array(data.length + ecCount);
      res.set(data);
      for (let i = 0; i < data.length; i++) {
        const coef = res[i];
        if (coef !== 0) {
          for (let j = 0; j < gen.length; j++) {
            res[i + j] ^= gfMul(gen[j], coef);
          }
        }
      }
      return res.slice(data.length);
    }

    const dataBytes = new TextEncoder().encode(text.slice(0, 76));
    const maxDataCodewords = 80;

    let bits = "0100" + dataBytes.length.toString(2).padStart(8, "0");
    for (const b of dataBytes) {
      bits += b.toString(2).padStart(8, "0");
    }
    bits += "0000".slice(0, Math.min(4, maxDataCodewords * 8 - bits.length));
    while (bits.length % 8 !== 0) bits += "0";

    const codewords = [];
    for (let i = 0; i < bits.length; i += 8) {
      codewords.push(parseInt(bits.slice(i, i + 8), 2));
    }
    let padToggle = false;
    while (codewords.length < maxDataCodewords) {
      codewords.push(padToggle ? 0x11 : 0xec);
      padToggle = !padToggle;
    }

    const ecCodewords = rsEncode(new Uint8Array(codewords), 20);
    const allCodewords = [...codewords, ...ecCodewords];

    const size = 33;
    const matrix = Array.from({ length: size }, () => Array(size).fill(null));
    const reserved = Array.from({ length: size }, () => Array(size).fill(false));

    function placeFinder(row, col) {
      for (let r = -1; r <= 7; r++) {
        for (let c = -1; c <= 7; c++) {
          const nr = row + r;
          const nc = col + c;
          if (nr >= 0 && nr < size && nc >= 0 && nc < size) {
            reserved[nr][nc] = true;
            if (r >= 0 && r <= 6 && c >= 0 && c <= 6) {
              const isBorder = (r === 0 || r === 6 || c === 0 || c === 6);
              const isCenter = (r >= 2 && r <= 4 && c >= 2 && c <= 4);
              matrix[nr][nc] = (isBorder || isCenter) ? 1 : 0;
            } else {
              matrix[nr][nc] = 0;
            }
          }
        }
      }
    }

    placeFinder(0, 0);
    placeFinder(0, size - 7);
    placeFinder(size - 7, 0);

    for (let r = -2; r <= 2; r++) {
      for (let c = -2; c <= 2; c++) {
        reserved[26 + r][26 + c] = true;
        matrix[26 + r][26 + c] = (Math.abs(r) === 2 || Math.abs(c) === 2 || (r === 0 && c === 0)) ? 1 : 0;
      }
    }

    for (let i = 8; i < size - 8; i++) {
      if (!reserved[6][i]) {
        matrix[6][i] = (i % 2 === 0) ? 1 : 0;
        reserved[6][i] = true;
      }
      if (!reserved[i][6]) {
        matrix[i][6] = (i % 2 === 0) ? 1 : 0;
        reserved[i][6] = true;
      }
    }

    matrix[size - 8][8] = 1;
    reserved[size - 8][8] = true;

    for (let i = 0; i <= 8; i++) {
      reserved[8][i] = true;
      reserved[i][8] = true;
      reserved[8][size - 1 - i] = true;
      reserved[size - 1 - i][8] = true;
    }

    let bitIndex = 0;
    const bitString = allCodewords.map(c => c.toString(2).padStart(8, "0")).join("");

    let right = size - 1;
    let upwards = true;
    while (right > 0) {
      if (right === 6) right--;
      const cols = [right, right - 1];
      const rowList = [];
      if (upwards) {
        for (let r = size - 1; r >= 0; r--) rowList.push(r);
      } else {
        for (let r = 0; r < size; r++) rowList.push(r);
      }

      for (const r of rowList) {
        for (const c of cols) {
          if (!reserved[r][c]) {
            let bit = 0;
            if (bitIndex < bitString.length) {
              bit = bitString[bitIndex] === "1" ? 1 : 0;
              bitIndex++;
            }
            const mask = ((r + c) % 2 === 0) ? 1 : 0;
            matrix[r][c] = bit ^ mask;
          }
        }
      }
      right -= 2;
      upwards = !upwards;
    }

    const formatBits = "111011111000100";
    const formatCoordsTopLeft = [
      [8, 0], [8, 1], [8, 2], [8, 3], [8, 4], [8, 5],
      [8, 7], [8, 8], [7, 8], [5, 8], [4, 8], [3, 8], [2, 8], [1, 8], [0, 8]
    ];
    for (let i = 0; i < 15; i++) {
      const val = formatBits[14 - i] === "1" ? 1 : 0;
      const [r, c] = formatCoordsTopLeft[i];
      matrix[r][c] = val;
    }
    for (let i = 0; i < 7; i++) {
      matrix[size - 1 - i][8] = formatBits[14 - i] === "1" ? 1 : 0;
    }
    for (let i = 0; i < 8; i++) {
      matrix[8][size - 8 + i] = formatBits[7 - i] === "1" ? 1 : 0;
    }

    const padding = 2;
    const total = size + padding * 2;
    let paths = "";
    for (let r = 0; r < size; r++) {
      for (let c = 0; c < size; c++) {
        if (matrix[r][c] === 1) {
          paths += `M${c + padding},${r + padding}h1v1h-1z `;
        }
      }
    }
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${total} ${total}" width="160" height="160" shape-rendering="crispEdges">
      <rect width="${total}" height="${total}" fill="#ffffff"/>
      <path d="${paths.trim()}" fill="#0f172a"/>
    </svg>`;
  } catch (err) {
    console.error("[QR Gen Error]:", err);
    return `<div style="padding:20px; font-size:12px; color:#ef4444;">Unable to render QR code</div>`;
  }
}

/**
 * Open Mobile QR Handoff Modal
 */
function openQrHandoffModal() {
  if (!currentStagedInvoice) {
    alert("No invoice is currently staged.");
    return;
  }
  const stageId = currentStagedInvoice.stageId || "STAGE_DEMO";
  const challengeId = currentStagedInvoice.webauthn?.challengeId || "CHALLENGE_DEMO";
  const handoffUrl = `${window.location.origin}/auth/mobile?stageId=${encodeURIComponent(stageId)}&challengeId=${encodeURIComponent(challengeId)}`;

  if (qrUrlDisplay) {
    qrUrlDisplay.innerHTML = `<code>${handoffUrl}</code>`;
  }
  if (qrGraphicBox) {
    qrGraphicBox.innerHTML = generateQrSvg(handoffUrl);
  }
  if (qrHandoffModal) {
    qrHandoffModal.style.display = "flex";
  }
}

/**
 * Close Mobile QR Handoff Modal
 */
function closeQrHandoffModal() {
  if (qrHandoffModal) {
    qrHandoffModal.style.display = "none";
  }
}

// Event Listeners
micButton.addEventListener("click", () => {
  if (recognition) {
    try {
      recognition.start();
    } catch {
      recognition.stop();
    }
  }
});

btnProcessTranscript.addEventListener("click", () => {
  handleVoiceCommand(transcriptInput.value);
});

transcriptInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    handleVoiceCommand(transcriptInput.value);
  }
});

btnExecutePasskey.addEventListener("click", executeInvoiceWithPasskey);

btnSpeechRepeat.addEventListener("click", () => {
  if (currentStagedInvoice) {
    const text = currentStagedInvoice.readBackMessages?.[activeLanguage] || currentStagedInvoice.readBackMessages?.en;
    playAudioReadBack(text, activeLanguage);
  }
});

btnManualSettle.addEventListener("click", async () => {
  if (!currentActiveInvoiceId) return;
  try {
    const res = await fetch(`/api/invoices/${currentActiveInvoiceId}/simulate-payment`, { method: "POST" });
    const data = await res.json();
    if (data.success) {
      updateTimelineStatus("PAID");
      loadAuditLedger();
      loadCfoMetrics();
    }
  } catch (err) {
    alert("Settlement error: " + err.message);
  }
});

btnDownloadPdf.addEventListener("click", downloadEncryptedStatement);
btnVerifyLedger.addEventListener("click", verifyAuditLedger);

// Language Switcher
document.querySelectorAll(".lang-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".lang-btn").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    activeLanguage = btn.getAttribute("data-lang");
    const labelMap = { mr: "Marathi (मराठी)", hi: "Hindi (हिंदी)", en: "English (US/UK)" };
    activeLangBadge.textContent = labelMap[activeLanguage];
    if (recognition) {
      const langMap = { mr: "mr-IN", hi: "hi-IN", en: "en-US" };
      recognition.lang = langMap[activeLanguage];
    }
  });
});

// Demo Chips Listener
document.querySelectorAll(".demo-chip").forEach((chip) => {
  chip.addEventListener("click", () => {
    const text = chip.getAttribute("data-text");
    const lang = chip.getAttribute("data-lang");
    if (lang) {
      const matchingBtn = document.querySelector(`.lang-btn[data-lang="${lang}"]`);
      if (matchingBtn) matchingBtn.click();
    }
    transcriptInput.value = text;
    handleVoiceCommand(text);
  });
});

// Kill Switch & Mobile QR Listeners
if (btnKillSwitch) {
  btnKillSwitch.addEventListener("click", () => {
    toggleKillSwitch(!isAgentFrozenState);
  });
}

if (btnUnfreezeBanner) {
  btnUnfreezeBanner.addEventListener("click", () => {
    toggleKillSwitch(false, "Merchant clicked Resume in alert banner");
  });
}

if (btnQrHandoff) {
  btnQrHandoff.addEventListener("click", openQrHandoffModal);
}

if (btnCloseQr) {
  btnCloseQr.addEventListener("click", closeQrHandoffModal);
}

// App Initialization
window.addEventListener("DOMContentLoaded", () => {
  initSpeechRecognition();
  initSseStream();
  loadCfoMetrics();
  loadBuyers();
  loadAuditLedger();
  checkKillSwitchState();
});
