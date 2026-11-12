/**
 * PayVoice Frontend Application Bootstrapper
 * Wires the Shell, Theme, Router, Notifications, SSE Stream, and all 9 Pages.
 */

import { api } from "./js/api.js";
import { store } from "./js/store.js";
import { initTheme, toggleTheme, getResolvedTheme } from "./js/theme.js";
import { registerPage, navigateTo, initRouter, renderCurrentRoute } from "./js/router.js";
import { initModalListeners, showToast, escapeHtml, formatDateTime } from "./js/utils.js";

// Pages
import { renderOverviewPage } from "./js/pages/overview.js";
import { renderVoiceAssistantPage } from "./js/pages/voiceAssistant.js";
import { renderInvoicesPage } from "./js/pages/invoices.js";
import { renderTransactionsPage } from "./js/pages/transactions.js";
import { renderMoneyGuidePage } from "./js/pages/moneyGuide.js";
import { renderStatementsPage } from "./js/pages/statements.js";
import { renderBuyersPage } from "./js/pages/buyers.js";
import { renderSecurityAuditPage } from "./js/pages/securityAudit.js";
import { renderSettingsPage } from "./js/pages/settings.js";

// Register all 9 application sections
registerPage("overview", renderOverviewPage);
registerPage("voice", renderVoiceAssistantPage);
registerPage("invoices", renderInvoicesPage);
registerPage("transactions", renderTransactionsPage);
registerPage("money-guide", renderMoneyGuidePage);
registerPage("statements", renderStatementsPage);
registerPage("buyers", renderBuyersPage);
registerPage("security", renderSecurityAuditPage);
registerPage("settings", renderSettingsPage);

function updateThemeIcons() {
  const resolved = getResolvedTheme();
  const sun = document.getElementById("theme-icon-sun");
  const moon = document.getElementById("theme-icon-moon");
  if (sun && moon) {
    sun.style.display = resolved === "dark" ? "none" : "block";
    moon.style.display = resolved === "dark" ? "block" : "none";
  }
}

function renderNotificationsPopover() {
  const listEl = document.getElementById("notif-list");
  const dotEl = document.getElementById("notif-dot");
  const items = store.getState().notifications || [];
  const unread = items.some((n) => !n.read);

  if (dotEl) dotEl.classList.toggle("hidden", !unread);
  if (!listEl) return;

  if (!items.length) {
    listEl.innerHTML = `<div class="empty-state" style="padding:20px;"><p>No notifications yet.</p></div>`;
    return;
  }

  listEl.innerHTML = items
    .map(
      (n) => `
    <div class="notif-item" style="${n.read ? "opacity:0.72;" : ""}">
      <strong>${escapeHtml(n.title)}</strong>
      <span>${escapeHtml(n.message)}</span>
      <time>${formatDateTime(n.timestamp)}</time>
    </div>`
    )
    .join("");
}

function initShellControls() {
  // Navigation clicks
  document.querySelectorAll(".nav-item[data-route]").forEach((btn) => {
    btn.addEventListener("click", () => {
      navigateTo(btn.getAttribute("data-route"));
    });
  });

  // Mobile sidebar drawer
  const sidebar = document.getElementById("sidebar");
  const backdrop = document.getElementById("sidebar-backdrop");
  const openBtn = document.getElementById("mobile-menu-btn");
  const closeBtn = document.getElementById("sidebar-close-btn");

  const closeDrawer = () => {
    sidebar?.classList.remove("open");
    backdrop?.classList.remove("open");
    openBtn?.setAttribute("aria-expanded", "false");
  };

  openBtn?.addEventListener("click", () => {
    sidebar?.classList.add("open");
    backdrop?.classList.add("open");
    openBtn?.setAttribute("aria-expanded", "true");
  });
  closeBtn?.addEventListener("click", closeDrawer);
  backdrop?.addEventListener("click", closeDrawer);

  // Theme toggle
  updateThemeIcons();
  document.getElementById("theme-toggle-btn")?.addEventListener("click", () => {
    const next = toggleTheme();
    updateThemeIcons();
    showToast({ title: `${next === "dark" ? "Dark" : "Light"} Theme Active`, duration: 2000 });
  });

  // Global language selector
  const langSelect = document.getElementById("topbar-lang-select");
  if (langSelect) {
    langSelect.value = store.getState().language || "mr";
    langSelect.addEventListener("change", (e) => {
      store.setState({ language: e.target.value });
      if (["voice", "settings"].includes(store.getState().route)) {
        renderCurrentRoute();
      }
    });
  }

  // Notifications popover
  const notifBtn = document.getElementById("notif-toggle-btn");
  const notifPopover = document.getElementById("notif-popover");
  renderNotificationsPopover();

  notifBtn?.addEventListener("click", (e) => {
    e.stopPropagation();
    const isOpen = notifPopover?.classList.toggle("open");
    notifBtn.setAttribute("aria-expanded", isOpen ? "true" : "false");
  });

  document.getElementById("notif-mark-read")?.addEventListener("click", () => {
    store.markAllNotificationsRead();
  });

  document.addEventListener("click", (e) => {
    if (notifPopover?.classList.contains("open") && !notifPopover.contains(e.target) && e.target !== notifBtn) {
      notifPopover.classList.remove("open");
      notifBtn?.setAttribute("aria-expanded", "false");
    }
  });

  // Subscribe to store updates for notifications & theme
  store.subscribe((_state, patch) => {
    if ("notifications" in patch) renderNotificationsPopover();
    if ("theme" in patch) updateThemeIcons();
  });
}

async function loadInitialData() {
  try {
    const [configRes, txRes, insRes, invRes, buyersRes, ledgerRes, verifyRes, killRes] = await Promise.all([
      api.getConfig().catch(() => null),
      api.getTransactions().catch(() => null),
      api.getMerchantInsights().catch(() => null),
      api.listInvoices().catch(() => null),
      api.getBuyers().catch(() => null),
      api.getAuditLedger().catch(() => null),
      api.verifyAuditLedger().catch(() => null),
      api.getKillSwitch().catch(() => null),
    ]);

    if (configRes) {
      const envEl = document.getElementById("env-indicator");
      if (envEl) {
        const isLive = configRes.environment === "live";
        envEl.classList.toggle("is-live", isLive);
        const shortEl = envEl.querySelector(".env-text-short");
        const fullEl = envEl.querySelector(".env-text-full");
        if (shortEl) shortEl.textContent = isLive ? "Live" : "Sandbox";
        if (fullEl) fullEl.textContent = isLive ? "PayPal Live" : "PayPal Sandbox";
      }
    }

    store.setState({
      config: configRes,
      transactions: txRes?.transactions || [],
      transactionTotals: txRes?.totals || null,
      cfoInsights: txRes?.cfoInsights || null,
      merchantInsights: insRes?.insights || null,
      invoices: invRes?.invoices || [],
      buyers: buyersRes?.buyers || [],
      auditLedger: ledgerRes?.ledger || [],
      ledgerVerification: verifyRes || null,
      killSwitch: killRes ? { frozen: Boolean(killRes.frozen), reason: killRes.reason || "", frozenAt: killRes.frozenAt || null } : { frozen: false, reason: "", frozenAt: null },
    });

    renderKillSwitchBanner();
    renderCurrentRoute();
  } catch (err) {
    showToast({
      title: "Backend Connection Warning",
      message: err.message || "Could not load initial workspace telemetry.",
      type: "error",
    });
  }
}

function renderKillSwitchBanner() {
  const main = document.getElementById("page-mount")?.parentElement;
  if (!main) return;
  let banner = document.getElementById("global-freeze-banner");
  const ks = store.getState().killSwitch;

  if (!ks?.frozen) {
    banner?.remove();
    return;
  }

  if (!banner) {
    banner = document.createElement("div");
    banner.id = "global-freeze-banner";
    banner.className = "alert alert-error";
    banner.setAttribute("role", "alert");
    main.insertBefore(banner, document.getElementById("page-mount"));
  }

  banner.innerHTML = `
    <div class="alert-content" style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;">
      <div>
        <span class="alert-title">Emergency Kill Switch Active ? Agent Frozen</span>
        <span>All invoice staging and execution requests are suspended${ks.reason ? ` (${escapeHtml(ks.reason)})` : ""}.</span>
      </div>
      <button type="button" class="btn btn-secondary btn-sm" id="global-resume-agent-btn">Resume Agent</button>
    </div>
  `;

  document.getElementById("global-resume-agent-btn")?.addEventListener("click", async () => {
    try {
      const res = await api.toggleKillSwitch(false, "Resumed by operator via emergency banner");
      const ledgerRes = await api.getAuditLedger().catch(() => null);
      store.setState({
        killSwitch: { frozen: Boolean(res.frozen), reason: res.reason || "", frozenAt: res.frozenAt || null },
        ...(ledgerRes ? { auditLedger: ledgerRes.ledger || [] } : {}),
      });
      renderKillSwitchBanner();
      if (store.getState().route === "security") renderCurrentRoute();
      showToast({ title: "Agent Resumed", message: "Normal PayVoice operations restored.", type: "success" });
    } catch (err) {
      showToast({ title: "Kill Switch Error", message: err.message, type: "error" });
    }
  });
}

store.subscribe((_state, patchObj) => {
  if ("killSwitch" in patchObj) {
    renderKillSwitchBanner();
  }
});

function initSseConnection() {
  api.subscribeInvoiceStream({
    onConnected: () => {
      store.setState({ sseConnected: true });
    },
    onSent: (data) => {
      if (data?.invoiceRecord) {
        const current = store.getState().invoices || [];
        store.setState({
          invoices: [data.invoiceRecord, ...current.filter((i) => i.invoiceId !== data.invoiceId)],
        });
      }
    },
    onPaid: (data) => {
      if (data?.invoiceRecord) {
        const current = store.getState().invoices || [];
        const updated = current.some((i) => i.invoiceId === data.invoiceId)
          ? current.map((i) => (i.invoiceId === data.invoiceId ? data.invoiceRecord : i))
          : [data.invoiceRecord, ...current];
        store.setState({ invoices: updated });
        store.addNotification({
          title: "OPGSP Remittance Settled (PAID)",
          message: `Invoice ${data.invoiceId} settled cleanly via PayPal.`,
          severity: "success",
        });
        showToast({
          title: "Invoice Paid",
          message: `${data.invoiceId} settled via OPGSP.`,
          type: "success",
        });
        api.getAuditLedger().then((res) => store.setState({ auditLedger: res.ledger || [] })).catch(() => {});
        if (["overview", "invoices", "security"].includes(store.getState().route)) {
          renderCurrentRoute();
        }
      }
    },
  });
}

window.addEventListener("DOMContentLoaded", () => {
  initTheme();
  initModalListeners();
  initShellControls();
  initRouter();
  initSseConnection();
  loadInitialData();
});
