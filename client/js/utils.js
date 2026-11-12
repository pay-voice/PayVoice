/**
 * PayVoice Shared Utilities
 * Formatting, XSS-safe escaping, SVG Charts, Modals, Toasts, and Speech Read-Back.
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
    return "badge-error";
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

  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.setAttribute("role", "status");
  toast.innerHTML = `
    <div class="toast-body">
      <strong class="toast-title">${escapeHtml(title)}</strong>
      ${message ? `<div class="toast-msg">${escapeHtml(message)}</div>` : ""}
    </div>
    <button type="button" class="btn-ghost btn-sm" aria-label="Dismiss notification" style="padding:2px 6px;min-height:24px;">✕</button>
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
 * Accessible Modal Manager (Escape to close, backdrop click, focus restoration)
 */
let lastFocusedBeforeModal = null;
let activeModalCloseHandler = null;

export function openModal({ title, bodyHtml, footerHtml = "", size = "md", onMount = null, onClose = null }) {
  const backdrop = document.getElementById("modal-backdrop");
  const panel = document.getElementById("modal-panel");
  const titleEl = document.getElementById("modal-title");
  const bodyEl = document.getElementById("modal-body");
  const footerEl = document.getElementById("modal-footer");

  if (!backdrop || !panel) return;

  lastFocusedBeforeModal = document.activeElement;
  activeModalCloseHandler = onClose;

  panel.className = `modal-panel ${size === "lg" ? "modal-lg" : ""}`;
  titleEl.textContent = title;
  bodyEl.innerHTML = bodyHtml;

  if (footerHtml) {
    footerEl.innerHTML = footerHtml;
    footerEl.style.display = "flex";
  } else {
    footerEl.innerHTML = "";
    footerEl.style.display = "none";
  }

  backdrop.classList.add("open");
  backdrop.setAttribute("aria-hidden", "false");
  document.body.style.overflow = "hidden";

  if (typeof onMount === "function") {
    onMount({ backdrop, panel, bodyEl, footerEl, close: closeModal });
  }

  const focusTarget = panel.querySelector("input, select, textarea, button:not(.modal-close)") || panel.querySelector(".modal-close");
  if (focusTarget) {
    requestAnimationFrame(() => focusTarget.focus());
  }
}

export function closeModal() {
  const backdrop = document.getElementById("modal-backdrop");
  if (!backdrop || !backdrop.classList.contains("open")) return;

  backdrop.classList.remove("open");
  backdrop.setAttribute("aria-hidden", "true");
  document.body.style.overflow = "";

  if (typeof activeModalCloseHandler === "function") {
    try {
      activeModalCloseHandler();
    } catch {
      // ignore
    }
    activeModalCloseHandler = null;
  }

  if (lastFocusedBeforeModal && typeof lastFocusedBeforeModal.focus === "function") {
    lastFocusedBeforeModal.focus();
  }
  lastFocusedBeforeModal = null;
}

export function initModalListeners() {
  const backdrop = document.getElementById("modal-backdrop");
  const closeBtn = document.getElementById("modal-close-btn");

  if (closeBtn) closeBtn.addEventListener("click", closeModal);
  if (backdrop) {
    backdrop.addEventListener("click", (e) => {
      if (e.target === backdrop) closeModal();
    });
  }
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeModal();
  });
}

/**
 * SVG Charts (Theme-aware via CSS Custom Properties, zero hardcoded theme breakage)
 */
export function renderAreaBarChartSvg(points = [], { height = 210, valuePrefix = "$" } = {}) {
  if (!points.length) {
    return `<div class="empty-state"><p>No activity data available for chart.</p></div>`;
  }

  const width = 560;
  const padL = 48;
  const padR = 16;
  const padT = 18;
  const padB = 32;
  const plotW = width - padL - padR;
  const plotH = height - padT - padB;
  const maxVal = Math.max(...points.map((p) => Number(p.value || 0)), 100);

  const barW = Math.min(40, Math.max(16, plotW / points.length - 18));
  const stepX = plotW / points.length;

  const gridLines = [0, 0.25, 0.5, 0.75, 1]
    .map((ratio) => {
      const y = padT + plotH - ratio * plotH;
      const val = Math.round(maxVal * ratio);
      return `
        <line x1="${padL}" y1="${y}" x2="${width - padR}" y2="${y}" stroke="var(--color-chart-grid)" stroke-dasharray="3 3" stroke-width="1" />
        <text x="${padL - 8}" y="${y + 4}" text-anchor="end" fill="var(--color-text-tertiary)" font-size="11" font-family="var(--font-mono)">${valuePrefix}${val}</text>
      `;
    })
    .join("");

  const bars = points
    .map((p, i) => {
      const val = Number(p.value || 0);
      const barH = Math.max(3, (val / maxVal) * plotH);
      const x = padL + i * stepX + (stepX - barW) / 2;
      const y = padT + plotH - barH;
      return `
        <g>
          <title>${escapeHtml(p.label)}: ${valuePrefix}${val.toFixed(2)}</title>
          <rect x="${x}" y="${y}" width="${barW}" height="${barH}" rx="5" fill="var(--color-chart-1)" opacity="0.88" />
          <text x="${x + barW / 2}" y="${height - 10}" text-anchor="middle" fill="var(--color-text-secondary)" font-size="11">${escapeHtml(p.label)}</text>
        </g>
      `;
    })
    .join("");

  return `
    <div class="chart-wrap">
      <svg class="chart-svg" viewBox="0 0 ${width} ${height}" role="img" aria-label="Export transaction revenue chart">
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

