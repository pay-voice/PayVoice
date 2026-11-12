/**
 * PayVoice Shared Utilities
 * Formatting, XSS-safe escaping, SVG Charts, Native <dialog> Modals, Toasts, and Speech Read-Back.
 */

export function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function formatCurrency(amount, currency = "USD") {
  const num = Number(amount || 0);
  const curr = String(currency || "USD").toUpperCase();
  const sym = curr === "EUR" ? "€" : curr === "GBP" ? "£" : curr === "INR" ? "₹" : "$";
  if (curr === "JPY" || curr === "HUF" || curr === "TWD") {
    return `${sym}${Math.round(num).toLocaleString("en-US")} ${curr}`;
  }
  return `${sym}${num.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })} ${curr}`;
}

export function formatDate(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return String(iso);
  return d.toLocaleDateString("en-IN", { day: "2-digit", month: "short", year: "numeric" });
}

export function formatDateTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return String(iso);
  return d.toLocaleString("en-IN", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function truncateHash(hash, len = 14) {
  if (!hash) return "—";
  const s = String(hash);
  return s.length > len ? `${s.slice(0, len)}...` : s;
}

export function getStatusBadgeClass(status = "") {
  const s = String(status).toUpperCase();
  if (["PAID", "COMPLETED", "APPROVED", "VERIFIED", "PASS", "VALID", "ALLOWLISTED"].includes(s)) {
    return "badge-success";
  }
  if (["SENT", "ACTIVE", "AUTHENTICATED", "DRAFT"].includes(s)) {
    return "badge-info";
  }
  if (["STAGED", "PENDING", "AWAITING_CONFIRMATION", "WARNING"].includes(s)) {
    return "badge-warning";
  }
  if (["BLOCKED", "FAILED", "REJECTED", "FIREWALL_BLOCKED", "POLICY_VIOLATION", "WEBAUTHN_REJECTED", "BLOCKED_ATTACK"].includes(s)) {
    return "badge-danger";
  }
  return "badge-neutral";
}

export function debounce(fn, wait = 200) {
  let t;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), wait);
  };
}

/**
 * Audible Read-Back using Web SpeechSynthesis API
 */
export function speakReadBack(text, lang = "en") {
  if (!window.speechSynthesis || !text) {
    return { supported: false };
  }
  try {
    window.speechSynthesis.cancel();
    const utterance = new SpeechSynthesisUtterance(text);
    const langMap = { mr: "mr-IN", hi: "hi-IN", en: "en-US" };
    utterance.lang = langMap[lang] || "en-US";
    utterance.rate = 1.0;
    utterance.pitch = 1.0;
    window.speechSynthesis.speak(utterance);
    return { supported: true, utterance };
  } catch (err) {
    return { supported: false, error: err.message };
  }
}

export function stopReadBack() {
  if (window.speechSynthesis) {
    try {
      window.speechSynthesis.cancel();
    } catch {
      // ignore
    }
  }
}

/**
 * Toast Notification System
 */
export function showToast({ title, message = "", type = "info", duration = 4200 }) {
  const container = document.getElementById("toast-container");
  if (!container) return;

  const normalizedType = ["success", "error", "warning", "info"].includes(type) ? type : "info";
  const toast = document.createElement("div");
  toast.className = `toast toast-${normalizedType}`;
  toast.setAttribute("role", "status");
  toast.innerHTML = `
    <div class="toast-body">
      <strong class="toast-title">${escapeHtml(title)}</strong>
      ${message ? `<div class="toast-message">${escapeHtml(message)}</div>` : ""}
    </div>
    <button type="button" class="toast-close" aria-label="Dismiss notification">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
        <path d="M18 6 6 18M6 6l12 12" />
      </svg>
    </button>
  `;

  const closeBtn = toast.querySelector("button");
  const remove = () => {
    if (toast.parentNode) toast.remove();
  };
  closeBtn.addEventListener("click", remove);
  container.appendChild(toast);

  if (duration > 0) {
    setTimeout(remove, duration);
  }
}

/**
 * Accessible Native <dialog> Modal Manager (Escape, closedby="any" + Safari fallback, smooth top-layer exit)
 */
let activeModalCloseHandler = null;
let modalCloseTimer = null;

function canTransitionDisplay() {
  return (
    typeof CSS !== "undefined" &&
    typeof CSS.supports === "function" &&
    CSS.supports("transition-behavior", "allow-discrete") &&
    !window.matchMedia("(prefers-reduced-motion: reduce)").matches
  );
}

function finalizeDialogClose(dialog) {
  dialog.removeAttribute("data-closing");
  if (modalCloseTimer) {
    clearTimeout(modalCloseTimer);
    modalCloseTimer = null;
  }
  if (dialog.open) {
    dialog.close();
  }
}

export function openModal({ title, bodyHtml, footerHtml = "", size = "md", onMount = null, onClose = null }) {
  const dialog = document.getElementById("modal-dialog");
  const panel = document.getElementById("modal-panel");
  const titleEl = document.getElementById("modal-title");
  const bodyEl = document.getElementById("modal-body");
  const footerEl = document.getElementById("modal-footer");

  if (!dialog || !panel) return;

  if (modalCloseTimer) {
    clearTimeout(modalCloseTimer);
    modalCloseTimer = null;
  }
  dialog.removeAttribute("data-closing");

  activeModalCloseHandler = onClose;

  const normalizedSize = ["sm", "md", "lg", "xl"].includes(size) ? size : "md";
  panel.className = `modal-panel modal-${normalizedSize}`;
  titleEl.textContent = title;
  bodyEl.innerHTML = bodyHtml;

  if (footerHtml) {
    footerEl.innerHTML = footerHtml;
    footerEl.style.display = "flex";
  } else {
    footerEl.innerHTML = "";
    footerEl.style.display = "none";
  }

  if (!dialog.open) {
    dialog.showModal();
  }

  if (typeof onMount === "function") {
    onMount({ dialog, backdrop: dialog, panel, bodyEl, footerEl, close: closeModal });
  }
}

export function closeModal() {
  const dialog = document.getElementById("modal-dialog");
  if (!dialog || !dialog.open || dialog.hasAttribute("data-closing")) return;

  if (!canTransitionDisplay()) {
    dialog.close();
    return;
  }

  dialog.setAttribute("data-closing", "");
  const panel = document.getElementById("modal-panel");
  const onEnd = () => finalizeDialogClose(dialog);
  panel?.addEventListener("transitionend", onEnd, { once: true });
  modalCloseTimer = setTimeout(() => {
    panel?.removeEventListener("transitionend", onEnd);
    finalizeDialogClose(dialog);
  }, 260);
}

export function initModalListeners() {
  const dialog = document.getElementById("modal-dialog");
  const closeBtn = document.getElementById("modal-close-btn");

  if (!dialog) return;

  if (closeBtn) {
    closeBtn.addEventListener("click", closeModal);
  }

  dialog.addEventListener("cancel", (e) => {
    if (canTransitionDisplay()) {
      e.preventDefault();
      closeModal();
    }
  });

  dialog.addEventListener("close", () => {
    dialog.removeAttribute("data-closing");
    if (modalCloseTimer) {
      clearTimeout(modalCloseTimer);
      modalCloseTimer = null;
    }
    if (typeof activeModalCloseHandler === "function") {
      const handler = activeModalCloseHandler;
      activeModalCloseHandler = null;
      try {
        handler();
      } catch {
        // ignore modal callback cleanup errors
      }
    }
  });

  // Coordinate-based light-dismiss fallback when closedby is unsupported (e.g. Safari)
  if (!("closedBy" in HTMLDialogElement.prototype)) {
    dialog.addEventListener("click", (e) => {
      if (e.target !== dialog) return;
      const rect = dialog.getBoundingClientRect();
      const clickedInDialog =
        rect.top <= e.clientY &&
        e.clientY <= rect.top + rect.height &&
        rect.left <= e.clientX &&
        e.clientX <= rect.left + rect.width;
      if (!clickedInDialog) closeModal();
    });
  }
}

/**
 * SVG Charts (Theme-aware via CSS Custom Properties)
 */
export function renderAreaBarChartSvg(points = [], { height = 210, valuePrefix = "$" } = {}) {
  if (!points.length) {
    return `<div class="empty-state"><p>No activity data available for chart.</p></div>`;
  }

  const width = 560;
  const padL = 52;
  const padR = 16;
  const padT = 18;
  const padB = 34;
  const plotW = width - padL - padR;
  const plotH = height - padT - padB;
  const maxVal = Math.max(...points.map((p) => Number(p.value || 0)), 100);

  const barW = Math.min(38, Math.max(16, plotW / points.length - 18));
  const stepX = plotW / points.length;

  const gridLines = [0, 0.25, 0.5, 0.75, 1]
    .map((ratio) => {
      const y = padT + plotH - ratio * plotH;
      const val = Math.round(maxVal * ratio);
      return `
        <line x1="${padL}" y1="${y}" x2="${width - padR}" y2="${y}" stroke="var(--color-chart-grid)" stroke-dasharray="${ratio === 0 ? "none" : "3 3"}" stroke-width="1" />
        <text x="${padL - 8}" y="${y + 4}" text-anchor="end" fill="var(--color-text-tertiary)" font-size="11" font-family="var(--font-mono)">${valuePrefix}${val}</text>
      `;
    })
    .join("");

  const bars = points
    .map((p, i) => {
      const val = Number(p.value || 0);
      const barH = Math.max(4, (val / maxVal) * plotH);
      const x = padL + i * stepX + (stepX - barW) / 2;
      const y = padT + plotH - barH;
      return `
        <g class="pv-bar-group">
          <title>${escapeHtml(p.label)}: ${valuePrefix}${val.toFixed(2)}</title>
          <rect class="pv-bar" x="${x}" y="${y}" width="${barW}" height="${barH}" rx="6" fill="url(#pv-bar-grad)" />
          <text x="${x + barW / 2}" y="${height - 10}" text-anchor="middle" fill="var(--color-text-secondary)" font-size="11" font-weight="500">${escapeHtml(p.label)}</text>
        </g>
      `;
    })
    .join("");

  return `
    <div class="chart-svg-wrap">
      <svg class="chart-svg" viewBox="0 0 ${width} ${height}" role="img" aria-label="Export transaction revenue chart">
        <defs>
          <linearGradient id="pv-bar-grad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="var(--color-chart-1)" stop-opacity="0.96" />
            <stop offset="100%" stop-color="var(--color-chart-2)" stop-opacity="0.68" />
          </linearGradient>
        </defs>
        ${gridLines}
        ${bars}
      </svg>
    </div>
  `;
}

export function renderDonutChartSvg(segments = [], { size = 156, centerLabel = "", centerSub = "" } = {}) {
  const total = segments.reduce((sum, s) => sum + Number(s.value || 0), 0);
  const r = 56;
  const cx = size / 2;
  const cy = size / 2;
  const circumference = 2 * Math.PI * r;
  const palette = ["var(--color-chart-1)", "var(--color-chart-2)", "var(--color-chart-3)", "var(--color-chart-4)", "var(--color-chart-5)"];

  let offset = 0;
  const arcs =
    total > 0
      ? segments
          .map((seg, idx) => {
            const val = Number(seg.value || 0);
            const frac = val / total;
            const dash = frac * circumference;
            const strokeColor = seg.color || palette[idx % palette.length];
            const el = `
              <circle
                cx="${cx}" cy="${cy}" r="${r}"
                fill="none"
                stroke="${strokeColor}"
                stroke-width="18"
                stroke-dasharray="${dash} ${circumference - dash}"
                stroke-dashoffset="${-offset}"
                transform="rotate(-90 ${cx} ${cy})"
              >
                <title>${escapeHtml(seg.label)}: ${val.toFixed(2)} (${(frac * 100).toFixed(1)}%)</title>
              </circle>
            `;
            offset += dash;
            return el;
          })
          .join("")
      : `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="var(--color-border)" stroke-width="18" />`;

  return `
    <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" role="img" aria-label="Distribution chart" style="flex-shrink:0;">
      ${arcs}
      <text x="${cx}" y="${cy - 2}" text-anchor="middle" fill="var(--color-text-primary)" font-size="16" font-weight="800" font-family="var(--font-sans)">${escapeHtml(centerLabel)}</text>
      <text x="${cx}" y="${cy + 15}" text-anchor="middle" fill="var(--color-text-tertiary)" font-size="11">${escapeHtml(centerSub)}</text>
    </svg>
  `;
}
