/**
 * Page 2: Voice Assistant (Signature Feature)
 * Multilingual Voice Operations (Marathi, Hindi, English) with:
 * - Real Web Speech API & Web Audio API live waveform (never fakes speech recognition)
 * - Graceful permission-denied / unsupported browser handling + editable transcript fallback
 * - All 10 explicit interaction states
 * - Extracted Intent display & deterministic Node.js staging/validation
 * - Visual/audible read-back + Invoice Preview & WebAuthn Passkey Modal
 * - Live 6-step Lifecycle Tracker
 */

import { api } from "../api.js";
import { store } from "../store.js";
import { navigateTo } from "../router.js";
import { openInvoicePreviewModal } from "../components/invoicePreviewModal.js";
import { openPasskeyAuthModal } from "../components/passkeyModal.js";
import {
  escapeHtml,
  formatCurrency,
  getStatusBadgeClass,
  speakReadBack,
  stopReadBack,
  showToast,
  truncateHash,
} from "../utils.js";

const VOICE_STATES = [
  { id: "idle", label: "1. Idle" },
  { id: "listening", label: "2. Listening" },
  { id: "transcribing", label: "3. Transcribing" },
  { id: "understanding", label: "4. Understanding" },
  { id: "validating", label: "5. Validating" },
  { id: "awaiting_confirmation", label: "6. Awaiting Confirmation" },
  { id: "passkey_auth", label: "7. Passkey Auth" },
  { id: "executing", label: "8. Executing" },
  { id: "completed", label: "9. Completed" },
  { id: "failed", label: "10. Failed" },
];

const DEMO_COMMANDS = [
  { lang: "mr", label: "Marathi (Devanagari)", text: "राहुलला २०० डॉलर्सचा सॉफ्टवेअर प्रोजेक्ट इनव्हॉईस पाठवा" },
  { lang: "mr", label: "Marathi (Romanized)", text: "Rahul la 200 dollars cha software project invoice pathav" },
  { lang: "hi", label: "Hindi", text: "राहुल को 200 डॉलर का क्लाउड एपीआई बिल भेजो" },
  { lang: "en", label: "English (EUR)", text: "Bill Elena 450 EUR for UI/UX Design Sprint" },
  { lang: "en", label: "English (GBP)", text: "Bill Oliver 350 GBP for Security Penetration Audit" },
  { lang: "en", label: "Statement Query", text: "Show my last 30 days encrypted statement" },
  { lang: "en", label: "Status Lookup", text: "What is the status of my recent invoices?" },
  { lang: "en", label: "Send Reminder", text: "Send a reminder to Rahul for his invoice" },
];

// Persistent controller state across view renders
let currentState = "idle";
let transcriptText = "";
let extractedIntent = null;
let lastError = null;
let nonInvoiceResult = null;
let activeExecutedInvoice = null;

// Audio & Speech handles
let recognition = null;
let isListening = false;
let audioCtx = null;
let analyser = null;
let micStream = null;
let waveformRaf = null;
let timerInterval = null;
let recordSeconds = 0;

function stopMediaAudio() {
  if (waveformRaf) {
    cancelAnimationFrame(waveformRaf);
    waveformRaf = null;
  }
  if (timerInterval) {
    clearInterval(timerInterval);
    timerInterval = null;
  }
  if (micStream) {
    micStream.getTracks().forEach((t) => {
      try {
        t.stop();
      } catch { }
    });
    micStream = null;
  }
  if (audioCtx) {
    try {
      audioCtx.close();
    } catch { }
    audioCtx = null;
  }
  analyser = null;
  isListening = false;
}

function drawWaveform(canvas) {
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const w = (canvas.width = canvas.offsetWidth || 600);
  const h = (canvas.height = 64);

  const renderFrame = () => {
    ctx.clearRect(0, 0, w, h);
    const barCount = 48;
    const gap = 4;
    const barW = Math.max(3, (w - gap * (barCount - 1)) / barCount);

    if (analyser && isListening) {
      const freqData = new Uint8Array(analyser.frequencyBinCount);
      analyser.getByteFrequencyData(freqData);
      ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue("--color-brand-secondary").trim() || "#0070ba";

      for (let i = 0; i < barCount; i++) {
        const idx = Math.floor((i / barCount) * freqData.length * 0.65);
        const amp = freqData[idx] / 255;
        const barH = Math.max(4, amp * (h - 14));
        const x = i * (barW + gap);
        const y = (h - barH) / 2;
        ctx.beginPath();
        ctx.roundRect(x, y, barW, barH, 2);
        ctx.fill();
      }
      waveformRaf = requestAnimationFrame(renderFrame);
    } else {
      ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue("--color-border-strong").trim() || "#cbd5e1";
      for (let i = 0; i < barCount; i++) {
        const x = i * (barW + gap);
        const y = h / 2 - 2;
        ctx.beginPath();
        ctx.roundRect(x, y, barW, 4, 2);
        ctx.fill();
      }
    }
  };

  renderFrame();
}

export function renderVoiceAssistantPage(mount) {
  const state = store.getState();
  const activeLang = state.language || "mr";
  const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
  const speechSupported = Boolean(SpeechRecognition);
  const staged = state.currentStaged;

  // Determine active state index for stepper highlighting
  const stateOrder = VOICE_STATES.map((s) => s.id);
  const activeIdx = stateOrder.indexOf(currentState);

  const formatTimer = (sec) => {
    const m = String(Math.floor(sec / 60)).padStart(2, "0");
    const s = String(sec % 60).padStart(2, "0");
    return `${m}:${s}`;
  };

  // Determine lifecycle timeline steps
  const invStatus = activeExecutedInvoice?.status || (staged ? "STAGED" : null);
  const stepStates = {
    voice: Boolean(staged || activeExecutedInvoice),
    policy: Boolean(staged || activeExecutedInvoice),
    auth: Boolean(activeExecutedInvoice),
    draft: Boolean(activeExecutedInvoice),
    sent: activeExecutedInvoice?.status === "SENT" || activeExecutedInvoice?.status === "PAID",
    paid: activeExecutedInvoice?.status === "PAID",
  };

  mount.innerHTML = `
    <div class="page-header">
      <div class="page-header-copy">
        <h1>Voice Assistant</h1>
        <p>Speak naturally in Marathi, Hindi, or English — AI extracts intent, Node.js validates, Passkey authorizes</p>
      </div>
      <div class="page-header-actions">
        <div class="segmented-control" role="group" aria-label="Select voice language">
          <button type="button" class="seg-btn ${activeLang === "mr" ? "active" : ""}" data-voice-lang="mr">मराठी (Marathi)</button>
          <button type="button" class="seg-btn ${activeLang === "hi" ? "active" : ""}" data-voice-lang="hi">हिंदी (Hindi)</button>
          <button type="button" class="seg-btn ${activeLang === "en" ? "active" : ""}" data-voice-lang="en">English</button>
        </div>
      </div>
    </div>

    <!-- 10-Stage State Machine Strip -->
    <div class="card" style="padding:14px 18px;">
      <div class="voice-state-strip" role="status" aria-live="polite" aria-label="Voice pipeline state">
        ${VOICE_STATES.map((st, idx) => {
    let cls = "voice-state-pill";
    if (currentState === "failed" && st.id === "failed") cls += " error";
    else if (st.id === currentState) cls += " active";
    else if (currentState !== "failed" && idx < activeIdx && st.id !== "failed") cls += " done";
    return `<span class="${cls}">${escapeHtml(st.label)}</span>`;
  }).join("")}
      </div>
    </div>

    <div class="grid-12-7-5">
      <!-- Left: Capture, Transcript, Extracted Intent & Preview -->
      <div style="display:flex;flex-direction:column;gap:20px;">
        <div class="card">
          <div class="card-header">
            <div>
              <h2 class="card-title">Multilingual Speech & Command Console</h2>
              <div class="card-subtitle">Voice captures intent only — zero autonomous execution</div>
            </div>
            <span class="badge ${speechSupported ? "badge-success" : "badge-warning"}">
              ${speechSupported ? "Web Speech API Ready" : "Speech API Unavailable (Manual Input Active)"}
            </span>
          </div>

          <div class="voice-capture-stage ${isListening ? "is-listening" : ["transcribing", "understanding", "validating", "executing"].includes(currentState) ? "is-processing" : ""}">
            <div class="mic-trigger-row">
              <button
                type="button"
                id="va-mic-btn"
                class="mic-btn-hero ${isListening ? "recording" : ""}"
                aria-label="${isListening ? "Stop voice recording" : "Start voice recording"}"
                aria-pressed="${isListening ? "true" : "false"}"
                ${!speechSupported ? "disabled title='Speech recognition unsupported in this browser'" : ""}
              >
                <svg width="30" height="30" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
                  ${isListening
      ? `<rect x="6" y="6" width="12" height="12" rx="2"/>`
      : `<path d="M12 14c1.66 0 3-1.34 3-3V5c0-1.66-1.34-3-3-3S9 3.34 9 5v6c0 1.66 1.34 3 3 3z"/><path d="M17 11c0 2.76-2.24 5-5 5s-5-2.24-5-5H5c0 3.53 2.61 6.43 6 6.92V21h2v-3.08c3.39-.49 6-3.39 6-6.92h-2z"/>`
    }
                </svg>
              </button>
              <div class="mic-meta">
                <div class="mic-timer" id="va-timer">${formatTimer(recordSeconds)}</div>
                <div class="voice-status-label" id="va-status-text">
                  ${isListening
      ? `Listening in ${activeLang === "mr" ? "Marathi" : activeLang === "hi" ? "Hindi" : "English"}... Tap to stop`
      : speechSupported
        ? "Tap microphone to speak or type/edit your command below"
        : "Browser SpeechRecognition unavailable — use the editable command box below"
    }
                </div>
              </div>
            </div>

            <div class="waveform-box" aria-hidden="true">
              <canvas id="va-waveform" class="waveform-canvas"></canvas>
            </div>

            <div class="transcript-composer">
              <label class="form-label" for="va-transcript-input">Live / Editable Transcript (Review before processing)</label>
              <textarea
                id="va-transcript-input"
                class="transcript-textarea"
                placeholder="e.g., Rahul la 200 dollars cha software project invoice pathav"
              >${escapeHtml(transcriptText)}</textarea>
              <div class="toolbar">
                <span class="form-hint">Edit any words before running AI intent extraction & deterministic checks.</span>
                <div class="toolbar-group">
                  <button type="button" class="btn btn-ghost btn-sm" id="va-clear-btn">Clear</button>
                  <button type="button" class="btn btn-primary" id="va-process-btn" ${["understanding", "validating", "executing"].includes(currentState) ? "disabled" : ""}>
                    ${["understanding", "validating"].includes(currentState) ? `<span class="spinner"></span> Processing...` : "Analyze & Stage"}
                  </button>
                </div>
              </div>
            </div>
          </div>

          <div>
            <div class="form-label" style="margin-bottom:8px;">Quick Multilingual Test Commands</div>
            <div class="demo-utterances-grid">
              ${DEMO_COMMANDS.map(
      (cmd) => `
                <button type="button" class="utterance-chip" data-demo-lang="${cmd.lang}" data-demo-text="${escapeHtml(cmd.text)}">
                  <strong>${escapeHtml(cmd.label)}:</strong> "${escapeHtml(cmd.text)}"
                </button>`
    ).join("")}
            </div>
          </div>
        </div>

        ${lastError
      ? `
          <div class="alert alert-error" role="alert">
            <div class="alert-content">
              <span class="alert-title">${escapeHtml(lastError.title || "Operation Blocked")}</span>
              <span>${escapeHtml(lastError.message)}</span>
            </div>
          </div>`
      : ""
    }

        ${extractedIntent
      ? `
          <div class="card">
            <div class="card-header">
              <div>
                <h2 class="card-title">Extracted Structured Intent</h2>
                <div class="card-subtitle">Parsed by ${escapeHtml(extractedIntent.source || "payvoice-parser")} &bull; Confidence: ${Math.round((extractedIntent.confidence || 0.98) * 100)}%</div>
              </div>
              <span class="badge badge-info">${escapeHtml(extractedIntent.action)}</span>
            </div>
            <div class="intent-grid">
              <div class="intent-field"><label>Action</label><strong>${escapeHtml(extractedIntent.action)}</strong></div>
              <div class="intent-field"><label>Language Detected</label><strong>${escapeHtml((extractedIntent.language || activeLang).toUpperCase())}</strong></div>
              ${extractedIntent.buyer_token
        ? `<div class="intent-field"><label>Buyer Token (Opaque PII)</label><strong style="font-family:var(--font-mono);">${escapeHtml(extractedIntent.buyer_token)}</strong></div>`
        : ""
      }
              ${extractedIntent.amount
        ? `<div class="intent-field"><label>Amount & Currency</label><strong class="tabular-nums">${formatCurrency(extractedIntent.amount, extractedIntent.currency)}</strong></div>`
        : ""
      }
              ${extractedIntent.item
        ? `<div class="intent-field"><label>Service Deliverable</label><strong>${escapeHtml(extractedIntent.item)}</strong></div>`
        : ""
      }
              ${extractedIntent.quantity
        ? `<div class="intent-field"><label>Quantity / Milestone</label><strong>${escapeHtml(extractedIntent.quantity)}</strong></div>`
        : ""
      }
              ${extractedIntent.date_range
        ? `<div class="intent-field"><label>Requested Date Range</label><strong>${escapeHtml(extractedIntent.date_range)}</strong></div>`
        : ""
      }
            </div>
          </div>`
      : ""
    }

        ${staged
      ? `
          <div class="card" id="va-staged-card">
            <div class="card-header">
              <div>
                <h2 class="card-title">Staged Invoice & Deterministic Validation</h2>
                <div class="card-subtitle">All Node.js Money Guide policy checks passed &bull; Challenge bound</div>
              </div>
              <span class="badge badge-warning">Awaiting Confirmation</span>
            </div>

            <div class="invoice-sheet">
              <div class="invoice-sheet-head">
                <div>
                  <h3>${escapeHtml(staged.previewCard.buyerDisplayName)}</h3>
                  <p class="text-sm text-muted">${escapeHtml(staged.previewCard.buyerToken)} &bull; ${escapeHtml(staged.previewCard.buyerCompany)} (${escapeHtml(staged.previewCard.buyerCountry)})</p>
                </div>
                <div class="invoice-total-amount">
                  <div>${escapeHtml(staged.previewCard.amountFormatted)}</div>
                  <div class="text-xs text-success" style="font-weight:600;">${escapeHtml(staged.previewCard.estInrFormatted)}</div>
                </div>
              </div>

              <div class="invoice-service-strip">
                <div>
                  <strong>${escapeHtml(staged.previewCard.item)}</strong>
                  <div class="text-xs text-muted">${escapeHtml(staged.previewCard.quantity)} &bull; RBI Purpose Code: ${escapeHtml(staged.previewCard.rbiPurposeCode)}</div>
                </div>
                <span class="badge badge-purple">${escapeHtml(staged.previewCard.rbiPurposeCode)}</span>
              </div>

              <div class="mono-box">Payload SHA-256: ${escapeHtml(staged.previewCard.payloadHash)}</div>

              <div class="toolbar">
                <div class="toolbar-group">
                  <button type="button" class="btn btn-secondary btn-sm" id="va-readback-play">Play Read-Back</button>
                  <button type="button" class="btn btn-ghost btn-sm" id="va-readback-stop">Stop Audio</button>
                </div>
                <div class="toolbar-group">
                  <button type="button" class="btn btn-ghost btn-sm" id="va-cancel-staged">Cancel</button>
                  <button type="button" class="btn btn-secondary" id="va-review-modal-btn">Inspect & Edit</button>
                  <button type="button" class="btn btn-success" id="va-authorize-btn">Authorize with Passkey</button>
                </div>
              </div>
            </div>
          </div>`
      : ""
    }

        ${nonInvoiceResult
      ? `
          <div class="card">
            <div class="card-header">
              <h2 class="card-title">${escapeHtml(nonInvoiceResult.title)}</h2>
              <span class="badge badge-success">Completed</span>
            </div>
            <div>${nonInvoiceResult.html}</div>
          </div>`
      : ""
    }
      </div>

      <!-- Right: Live Lifecycle Timeline Tracker -->
      <div style="display:flex;flex-direction:column;gap:20px;">
        <div class="card">
          <div class="card-header">
            <div>
              <h2 class="card-title">Live Invoicing Lifecycle</h2>
              <div class="card-subtitle">${activeExecutedInvoice ? `Tracking ${escapeHtml(activeExecutedInvoice.invoiceId)}` : "Standby for voice staging"}</div>
            </div>
            <span class="badge ${invStatus ? getStatusBadgeClass(invStatus) : "badge-neutral"}">${escapeHtml(invStatus || "STANDBY")}</span>
          </div>

          <div class="timeline">
            <div class="timeline-item ${stepStates.voice ? "completed" : ""}">
              <div class="timeline-dot">1</div>
              <div class="timeline-body">
                <h4>Voice Capture & PII Tokenization</h4>
                <p>Speech mapped to opaque BUYER_* vault token</p>
              </div>
            </div>
            <div class="timeline-item ${stepStates.policy ? "completed" : ""}">
              <div class="timeline-dot">2</div>
              <div class="timeline-body">
                <h4>Deterministic Money Guide Validation</h4>
                <p>Allowlist, $2,500 OPGSP cap, currency & duplicate check</p>
              </div>
            </div>
            <div class="timeline-item ${stepStates.auth ? "completed" : staged ? "active" : ""}">
              <div class="timeline-dot">3</div>
              <div class="timeline-body">
                <h4>WebAuthn Hardware Passkey Assertion</h4>
                <p>Single-use challenge bound to payload SHA-256</p>
              </div>
            </div>
            <div class="timeline-item ${stepStates.draft ? "completed" : ""}">
              <div class="timeline-dot">4</div>
              <div class="timeline-body">
                <h4>PayPal Sandbox DRAFT Created</h4>
                <p>Guarded @paypal/agent-toolkit create_invoice</p>
              </div>
            </div>
            <div class="timeline-item ${stepStates.sent ? "completed" : ""}">
              <div class="timeline-dot">5</div>
              <div class="timeline-body">
                <h4>Dispatched to Buyer (SENT)</h4>
                <p>Guarded send_invoice emailed payment link</p>
              </div>
            </div>
            <div class="timeline-item ${stepStates.paid ? "completed" : activeExecutedInvoice?.status === "SENT" ? "active" : ""}">
              <div class="timeline-dot">6</div>
              <div class="timeline-body">
                <h4>Inward Remittance Settled (PAID)</h4>
                <p>OPGSP webhook / sandbox settlement & e-FIRC ready</p>
              </div>
            </div>
          </div>

          ${activeExecutedInvoice && activeExecutedInvoice.status === "SENT"
      ? `
            <button type="button" class="btn btn-success" id="va-simulate-paid-btn" style="width:100%;">
              Simulate Buyer Settlement (Transition to PAID)
            </button>`
      : ""
    }
        </div>

        <div class="card">
          <div class="card-header">
            <h2 class="card-title">Security Guarantee</h2>
            <span class="badge badge-purple">NIST / FIDO2</span>
          </div>
          <p class="section-desc">
            Voice is strictly an intent-capture interface. PayVoice never accepts spoken passwords and never allows the LLM to execute PayPal writes without deterministic Node.js validation, visual/audible read-back, and WebAuthn passkey verification.
          </p>
        </div>
      </div>
    </div>
  `;

  // Draw waveform on canvas
  const canvas = document.getElementById("va-waveform");
  drawWaveform(canvas);

  // Wire language tabs
  mount.querySelectorAll("[data-voice-lang]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const lang = btn.getAttribute("data-voice-lang");
      store.setState({ language: lang });
      const topSel = document.getElementById("topbar-lang-select");
      if (topSel) topSel.value = lang;
      renderVoiceAssistantPage(mount);
    });
  });

  // Wire transcript input edits
  const textarea = document.getElementById("va-transcript-input");
  textarea?.addEventListener("input", (e) => {
    transcriptText = e.target.value;
  });

  // Wire clear button
  document.getElementById("va-clear-btn")?.addEventListener("click", () => {
    stopReadBack();
    transcriptText = "";
    extractedIntent = null;
    lastError = null;
    nonInvoiceResult = null;
    currentState = "idle";
    store.setState({ currentStaged: null });
    renderVoiceAssistantPage(mount);
  });

  // Wire demo chips
  mount.querySelectorAll("[data-demo-text]").forEach((chip) => {
    chip.addEventListener("click", () => {
      const txt = chip.getAttribute("data-demo-text");
      const lang = chip.getAttribute("data-demo-lang");
      if (lang) store.setState({ language: lang });
      transcriptText = txt;
      processTranscript(mount, txt);
    });
  });

  // Wire mic toggle
  document.getElementById("va-mic-btn")?.addEventListener("click", async () => {
    if (!speechSupported) return;

    if (isListening && recognition) {
      try {
        recognition.stop();
      } catch { }
      stopMediaAudio();
      currentState = "transcribing";
      renderVoiceAssistantPage(mount);
      return;
    }

    lastError = null;
    nonInvoiceResult = null;
    recordSeconds = 0;

    try {
      // Request microphone stream for live waveform visualization (handles permission denial explicitly)
      if (navigator.mediaDevices?.getUserMedia) {
        micStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
        const AudioContextCls = window.AudioContext || window.webkitAudioContext;
        if (AudioContextCls) {
          audioCtx = new AudioContextCls();
          const source = audioCtx.createMediaStreamSource(micStream);
          analyser = audioCtx.createAnalyser();
          analyser.fftSize = 128;
          source.connect(analyser);
        }
      }

      recognition = new SpeechRecognition();
      recognition.continuous = false;
      recognition.interimResults = true;
      const langMap = { mr: "mr-IN", hi: "hi-IN", en: "en-US" };
      recognition.lang = langMap[store.getState().language] || "mr-IN";

      recognition.onstart = () => {
        isListening = true;
        currentState = "listening";
        timerInterval = setInterval(() => {
          recordSeconds++;
          const el = document.getElementById("va-timer");
          if (el) el.textContent = formatTimer(recordSeconds);
        }, 1000);
        renderVoiceAssistantPage(mount);
      };

      recognition.onresult = (event) => {
        const latest = Array.from(event.results)
          .map((r) => r[0].transcript)
          .join(" ");
        transcriptText = latest;
        const box = document.getElementById("va-transcript-input");
        if (box) box.value = latest;

        const isFinal = event.results[event.results.length - 1]?.isFinal;
        if (isFinal) {
          stopMediaAudio();
          currentState = "transcribing";
          renderVoiceAssistantPage(mount);
          processTranscript(mount, latest);
        }
      };

      recognition.onerror = (event) => {
        stopMediaAudio();
        currentState = "failed";
        const denied = event.error === "not-allowed" || event.error === "service-not-allowed";
        lastError = {
          title: denied ? "Microphone Permission Denied" : "Speech Recognition Error",
          message: denied
            ? "Microphone access was blocked by the browser. Allow microphone permissions in site settings or type/edit your command in the transcript box below."
            : `Speech capture error (${event.error}). You can retry or enter your command manually below.`,
        };
        renderVoiceAssistantPage(mount);
      };

      recognition.onend = () => {
        if (isListening) {
          stopMediaAudio();
          if (currentState === "listening") {
            currentState = "idle";
            renderVoiceAssistantPage(mount);
          }
        }
      };

      recognition.start();
    } catch (err) {
      stopMediaAudio();
      currentState = "failed";
      const isPerm = err.name === "NotAllowedError" || err.name === "PermissionDeniedError";
      lastError = {
        title: isPerm ? "Microphone Permission Denied" : "Microphone Unavailable",
        message: isPerm
          ? "Microphone permission was denied. Please grant mic access or use the manual text command box below."
          : err.message || "Could not access microphone device. Use the manual text command box below.",
      };
      renderVoiceAssistantPage(mount);
    }
  });

  // Wire manual Analyze & Stage
  document.getElementById("va-process-btn")?.addEventListener("click", () => {
    const val = document.getElementById("va-transcript-input")?.value || transcriptText;
    transcriptText = val;
    processTranscript(mount, val);
  });

  // Wire staged preview actions
  document.getElementById("va-readback-play")?.addEventListener("click", () => {
    const lang = store.getState().language || "en";
    const msg = staged?.readBackMessages?.[lang] || staged?.readBackMessages?.en;
    const res = speakReadBack(msg, lang);
    if (!res.supported) showToast({ title: "SpeechSynthesis Unsupported", type: "warning" });
  });
  document.getElementById("va-readback-stop")?.addEventListener("click", stopReadBack);
  document.getElementById("va-cancel-staged")?.addEventListener("click", () => {
    stopReadBack();
    store.setState({ currentStaged: null });
    currentState = "idle";
    renderVoiceAssistantPage(mount);
  });
  document.getElementById("va-review-modal-btn")?.addEventListener("click", () => {
    openInvoicePreviewModal(staged, {
      onRestaged: (updated) => {
        store.setState({ currentStaged: updated });
        renderVoiceAssistantPage(mount);
      },
      onExecuted: (res) => handleExecutionSuccess(mount, res),
    });
  });
  document.getElementById("va-authorize-btn")?.addEventListener("click", () => {
    currentState = "passkey_auth";
    renderVoiceAssistantPage(mount);
    openPasskeyAuthModal(staged, {
      onSuccess: (res) => handleExecutionSuccess(mount, res),
      onCancel: () => {
        currentState = "awaiting_confirmation";
        renderVoiceAssistantPage(mount);
      },
    });
  });

  // Manual payment settlement for active SENT invoice
  document.getElementById("va-simulate-paid-btn")?.addEventListener("click", async () => {
    if (!activeExecutedInvoice) return;
    const btn = document.getElementById("va-simulate-paid-btn");
    btn.disabled = true;
    btn.textContent = "Settling...";
    try {
      const res = await api.simulateInvoicePayment(activeExecutedInvoice.invoiceId);
      activeExecutedInvoice = res.invoice;
      const list = store.getState().invoices || [];
      store.setState({
        invoices: list.map((inv) => (inv.invoiceId === res.invoiceId ? res.invoice : inv)),
      });
      renderVoiceAssistantPage(mount);
      showToast({ title: "Invoice Paid", message: `${res.invoiceId} settled via OPGSP.`, type: "success" });
    } catch (err) {
      showToast({ title: "Settlement Error", message: err.message, type: "error" });
      btn.disabled = false;
      btn.textContent = "Simulate Buyer Settlement (Transition to PAID)";
    }
  });

  // Non-invoice quick actions
  document.getElementById("va-noninv-pdf-btn")?.addEventListener("click", async () => {
    const btn = document.getElementById("va-noninv-pdf-btn");
    btn.disabled = true;
    btn.textContent = "Encrypting PDF...";
    try {
      const dateRange = extractedIntent?.date_range || "Last 30 Days";
      const result = await api.generateStatementPdf({ dateRange });
      const url = URL.createObjectURL(result.blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = result.filename;
      document.body.appendChild(a);
      a.click();
      URL.revokeObjectURL(url);
      a.remove();
      showToast({ title: "Encrypted Statement Downloaded", message: `SHA-256: ${truncateHash(result.checksum, 16)}`, type: "success" });
    } catch (err) {
      showToast({ title: "Export Failed", message: err.message, type: "error" });
    } finally {
      btn.disabled = false;
      btn.textContent = "Download Encrypted Statement (PDF)";
    }
  });

  document.getElementById("va-noninv-reminder-btn")?.addEventListener("click", () => {
    navigateTo("invoices");
  });
}

async function processTranscript(mount, rawText) {
  const text = String(rawText || "").trim();
  if (!text) {
    showToast({ title: "Empty Command", message: "Speak or type a voice command first.", type: "warning" });
    return;
  }

  lastError = null;
  nonInvoiceResult = null;
  activeExecutedInvoice = null;
  currentState = "understanding";
  renderVoiceAssistantPage(mount);

  try {
    const lang = store.getState().language || "mr";
    const parseRes = await api.parseIntent({ transcript: text, language: lang });
    extractedIntent = parseRes.intent;

    if (extractedIntent.action === "create_invoice") {
      currentState = "validating";
      renderVoiceAssistantPage(mount);

      const staged = await api.stageInvoice({
        transcript: text,
        language: lang,
        intent: extractedIntent,
      });

      store.setState({ currentStaged: staged });
      currentState = "awaiting_confirmation";
      renderVoiceAssistantPage(mount);

      if (store.getState().autoReadBack) {
        const msg = staged.readBackMessages?.[lang] || staged.readBackMessages?.en;
        speakReadBack(msg, lang);
      }
      return;
    }

    // Handle non-invoice voice commands cleanly
    currentState = "validating";
    renderVoiceAssistantPage(mount);

    if (extractedIntent.action === "export_pdf_statement") {
      currentState = "completed";
      nonInvoiceResult = {
        title: `Encrypted Statement Ready (${extractedIntent.date_range || "Last 30 Days"})`,
        html: `
          <p class="section-desc" style="margin-block-end:0.75rem;">Your request for an encrypted CA/GST Rule 96A accounting statement (${escapeHtml(extractedIntent.date_range || "Last 30 Days")}) is validated and ready to generate.</p>
          <div style="display:flex;gap:10px;flex-wrap:wrap;">
            <button type="button" class="btn btn-primary" id="va-noninv-pdf-btn">Download Encrypted Statement (PDF)</button>
            <button type="button" class="btn btn-secondary" onclick="window.location.hash='#statements'">Open Statements Page</button>
          </div>
        `,
      };
    } else if (extractedIntent.action === "check_status") {
      const [invRes, txRes] = await Promise.all([api.listInvoices(), api.getTransactions()]);
      store.setState({
        invoices: invRes.invoices || [],
        transactions: txRes.transactions || [],
      });
      currentState = "completed";
      const invs = invRes.invoices || [];
      const txs = txRes.transactions || [];
      nonInvoiceResult = {
        title: "Live Payment & Invoice Status Lookup",
        html: `
          <p class="section-desc" style="margin-block-end:0.625rem;">Found <strong>${invs.length}</strong> session invoice(s) and <strong>${txs.length}</strong> settled sandbox transaction(s).</p>
          <div style="display:flex;flex-direction:column;gap:8px;">
            ${invs
            .slice(0, 3)
            .map(
              (i) => `
              <div class="policy-check-row">
                <span><strong>${escapeHtml(i.invoiceId)}</strong> &bull; ${escapeHtml(i.buyerName)} (${formatCurrency(i.amount, i.currency)})</span>
                <span class="badge ${getStatusBadgeClass(i.status)}">${escapeHtml(i.status)}</span>
              </div>`
            )
            .join("")}
            ${txs
            .slice(0, 3)
            .map(
              (t) => `
              <div class="policy-check-row">
                <span><strong>${escapeHtml(t.invoiceId)}</strong> &bull; ${escapeHtml(t.buyerName)} (${formatCurrency(t.grossAmount, t.currency)})</span>
                <span class="badge ${getStatusBadgeClass(t.status)}">${escapeHtml(t.status)}</span>
              </div>`
            )
            .join("")}
          </div>
        `,
      };
    } else if (extractedIntent.action === "send_reminder") {
      const invRes = await api.listInvoices();
      const eligible = (invRes.invoices || []).filter(
        (i) => i.status === "SENT" && (!extractedIntent.buyer_token || i.buyerToken === extractedIntent.buyer_token)
      );
      currentState = "completed";
      nonInvoiceResult = {
        title: "Payment Reminder Eligibility Check",
        html: eligible.length
          ? `<p class="section-desc" style="margin-block-end:0.625rem;">Found ${eligible.length} unpaid SENT invoice(s) eligible for a polite payment reminder (24h cooldown enforced).</p>
             <button type="button" class="btn btn-primary" id="va-noninv-reminder-btn">Review & Send in Invoices</button>`
          : `<div class="alert alert-warning"><div class="alert-content"><span class="alert-title">No Eligible Unpaid Invoices</span><span>Only SENT (unpaid) invoices can receive payment reminders. PAID and DRAFT invoices are deterministically blocked.</span></div></div>`,
      };
    } else if (extractedIntent.action === "financial_insight") {
      const txRes = await api.getTransactions();
      const cfo = txRes.cfoInsights;
      currentState = "completed";
      nonInvoiceResult = {
        title: "Verified Money Guide CFO Summary",
        html: `
          <div class="kv-grid">
            <div class="kv-item"><div class="kv-label">Total Gross (USD Eq.)</div><div class="kv-val">$${Number(cfo?.totalGrossUsd || 0).toFixed(2)}</div></div>
            <div class="kv-item"><div class="kv-label">Net INR Realization</div><div class="kv-val">${escapeHtml(cfo?.formattedInrRealization || "—")}</div></div>
            <div class="kv-item"><div class="kv-label">PayPal Fees</div><div class="kv-val">$${Number(cfo?.totalEstimatedFeesUsd || 0).toFixed(2)} (${cfo?.effectiveFeeRatePercent}%)</div></div>
            <div class="kv-item"><div class="kv-label">OPGSP Remaining Cap</div><div class="kv-val">$${Number(cfo?.opgspLimit?.remainingAllowanceUsd || 2500).toFixed(2)}</div></div>
          </div>
        `,
      };
    }

    renderVoiceAssistantPage(mount);
  } catch (err) {
    currentState = "failed";
    if (err.status === 423 || err.code === "AGENT_FROZEN_BY_KILL_SWITCH") {
      api.getKillSwitch().then((ks) => {
        store.setState({ killSwitch: { frozen: Boolean(ks.frozen), reason: ks.reason || "", frozenAt: ks.frozenAt || null } });
      }).catch(() => {
        store.setState({ killSwitch: { frozen: true, reason: err.message, frozenAt: new Date().toISOString() } });
      });
    }
    lastError = {
      title: err.code || "Voice Staging Blocked",
      message: err.message || "Validation or firewall policy blocked this request.",
    };
    renderVoiceAssistantPage(mount);
    showToast({ title: lastError.title, message: lastError.message, type: "error" });
  }
}

async function handleExecutionSuccess(mount, execResult) {
  currentState = "completed";
  activeExecutedInvoice = execResult.invoiceRecord || {
    invoiceId: execResult.invoiceId,
    status: execResult.status || "SENT",
  };
  renderVoiceAssistantPage(mount);

  // Sync audit ledger & transactions in background
  try {
    const [ledgerRes, txRes] = await Promise.all([api.getAuditLedger(), api.getTransactions()]);
    store.setState({
      auditLedger: ledgerRes.ledger || [],
      transactions: txRes.transactions || [],
      cfoInsights: txRes.cfoInsights || null,
    });
  } catch { }
}

// Listen for SSE invoice status transitions to update timeline live
store.subscribe((state, patch) => {
  if (state.route === "voice" && patch.invoices && activeExecutedInvoice) {
    const updated = state.invoices.find((i) => i.invoiceId === activeExecutedInvoice.invoiceId);
    if (updated && updated.status !== activeExecutedInvoice.status) {
      activeExecutedInvoice = updated;
      const mount = document.getElementById("page-mount");
      if (mount) renderVoiceAssistantPage(mount);
    }
  }
});

