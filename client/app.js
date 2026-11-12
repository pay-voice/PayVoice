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

// App Initialization
window.addEventListener("DOMContentLoaded", () => {
  initSpeechRecognition();
  initSseStream();
  loadCfoMetrics();
  loadBuyers();
  loadAuditLedger();
});
