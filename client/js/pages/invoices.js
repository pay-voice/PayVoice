/**
 * Page 3: Invoice Management
 * Search, filter, sort, pagination, staged/draft/sent/paid lifecycle view,
 * reminder cooldown enforcement, and guarded invoice creation.
 */

import { api } from "../api.js";
import { store } from "../store.js";
import { navigateTo } from "../router.js";
import { openInvoicePreviewModal } from "../components/invoicePreviewModal.js";
import { openPasskeyAuthModal } from "../components/passkeyModal.js";
import {
  escapeHtml,
  formatCurrency,
  formatDate,
  formatDateTime,
  getStatusBadgeClass,
  openModal,
  closeModal,
  showToast,
} from "../utils.js";

let searchQuery = "";
let statusFilter = "ALL";
let sortField = "date_desc";
let currentPage = 1;
const PAGE_SIZE = 8;

const REMINDER_COOLDOWN_MS = 24 * 60 * 60 * 1000;

export function renderInvoicesPage(mount) {
  // Capture active search input focus to preserve caret position
  const activeEl = document.activeElement;
  const isSearchFocused = activeEl && activeEl.id === "inv-search-input";
  const searchCaretStart = isSearchFocused ? activeEl.selectionStart : null;
  const searchCaretEnd = isSearchFocused ? activeEl.selectionEnd : null;

  const state = store.getState();

  const sessionInvoices = (state.invoices || []).map((inv) => ({
    ...inv,
    sourceLabel: "LIVE SESSION",
    date: inv.createdAt || inv.date || new Date().toISOString(),
  }));

  const stagedItem = state.currentStaged
    ? [
        {
          invoiceId: state.currentStaged.stageId,
          buyerToken: state.currentStaged.stagedPayload?.buyerToken || "BUYER_UNKNOWN",
          buyerName: state.currentStaged.stagedPayload?.buyerName || "Overseas Buyer",
          buyerCompany: state.currentStaged.stagedPayload?.buyerCompany || "International Client",
          item: state.currentStaged.stagedPayload?.item || "Service Deliverable",
          quantity: state.currentStaged.stagedPayload?.quantity || "1 Milestone",
          amount: state.currentStaged.stagedPayload?.amount || 0,
          currency: state.currentStaged.stagedPayload?.currency || "USD",
          rbiPurposeCode: state.currentStaged.stagedPayload?.rbiPurposeCode || "P0802",
          lutStatus: state.currentStaged.stagedPayload?.lutStatus || "Export under LUT without payment of IGST",
          status: "STAGED",
          date: state.currentStaged.stagedPayload?.stagedAt || new Date().toISOString(),
          sourceLabel: "AWAITING AUTH",
          _stagedRef: state.currentStaged,
          timeline: [
            {
              status: "STAGED",
              label: "Validated by Money Guide AI & bound to WebAuthn challenge",
              timestamp: state.currentStaged.stagedPayload?.stagedAt || new Date().toISOString(),
            },
          ],
        },
      ]
    : [];

  // Include sandbox historical invoices derived from settled transactions
  const sessionIds = new Set(sessionInvoices.map((i) => i.invoiceId));
  const stagedIds = new Set(stagedItem.map((i) => i.invoiceId));

  const historicalInvoices = (state.transactions || [])
    .filter((tx) => {
      const invId = tx.invoiceId || tx.id;
      return !sessionIds.has(invId) && !stagedIds.has(invId);
    })
    .map((tx) => ({
      invoiceId: tx.invoiceId || tx.id,
      buyerToken: tx.buyerToken || "BUYER_UNKNOWN",
      buyerName: tx.buyerName || "Overseas Buyer",
      buyerCompany: "Sandbox Export Contract",
      item: tx.item || "Export Deliverable",
      quantity: "1 Contract",
      amount: tx.grossAmount || tx.amount || 200,
      currency: tx.currency || "USD",
      rbiPurposeCode: "P0802",
      status: tx.status === "COMPLETED" ? "PAID" : tx.status || "PAID",
      date: tx.date || new Date().toISOString(),
      sourceLabel: "SANDBOX RECORD",
      timeline: [
        { status: "DRAFT", label: "Sandbox Invoice Created", timestamp: tx.date },
        { status: "SENT", label: "Sent to Buyer", timestamp: tx.date },
        { status: "PAID", label: "Inward Remittance Settled via OPGSP", timestamp: tx.date },
      ],
    }));

  const allInvoices = [...stagedItem, ...sessionInvoices, ...historicalInvoices];

  // Filter
  const filtered = allInvoices.filter((inv) => {
    const matchesStatus = statusFilter === "ALL" || String(inv.status).toUpperCase() === statusFilter;
    const q = searchQuery.toLowerCase().trim();
    const matchesSearch =
      !q ||
      String(inv.invoiceId || "").toLowerCase().includes(q) ||
      String(inv.buyerName || "").toLowerCase().includes(q) ||
      String(inv.buyerToken || "").toLowerCase().includes(q) ||
      String(inv.item || "").toLowerCase().includes(q);
    return matchesStatus && matchesSearch;
  });

  // Sort
  filtered.sort((a, b) => {
    if (sortField === "amount_desc") return Number(b.amount || 0) - Number(a.amount || 0);
    if (sortField === "amount_asc") return Number(a.amount || 0) - Number(b.amount || 0);
    if (sortField === "date_asc") return new Date(a.date) - new Date(b.date);
    return new Date(b.date) - new Date(a.date);
  });

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  if (currentPage > totalPages) currentPage = totalPages;
  const pageItems = filtered.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);

  mount.innerHTML = `
    <div class="page-header">
      <div class="page-header-copy">
        <h1>Invoices</h1>
        <p>Manage staged, draft, sent, and paid cross-border PayPal invoices</p>
      </div>
      <div class="page-header-actions">
        <button type="button" class="btn btn-secondary" id="inv-refresh-btn">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true" style="margin-right:6px;"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
          Sync Invoices
        </button>
        <button type="button" class="btn btn-primary" id="inv-new-btn">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true" style="margin-right:6px;"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
          Create Invoice
        </button>
      </div>
    </div>

    <div class="kpi-grid">
      <div class="metric-card">
        <div class="metric-label">Total Invoices</div>
        <div class="metric-value tabular-nums">${allInvoices.length}</div>
        <div class="metric-foot">${sessionInvoices.length} live session &bull; ${historicalInvoices.length} sandbox</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Awaiting Confirmation</div>
        <div class="metric-value warning tabular-nums">${stagedItem.length}</div>
        <div class="metric-foot">Requires WebAuthn passkey signature</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Sent (Unpaid)</div>
        <div class="metric-value brand tabular-nums">${allInvoices.filter((i) => i.status === "SENT").length}</div>
        <div class="metric-foot">Eligible for payment reminders</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Paid / Settled</div>
        <div class="metric-value success tabular-nums">${allInvoices.filter((i) => i.status === "PAID").length}</div>
        <div class="metric-foot">OPGSP e-FIRC compliant</div>
      </div>
    </div>

    <div class="card">
      <div class="toolbar">
        <div class="search-input-wrap">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>
          <input type="search" id="inv-search-input" placeholder="Search invoice ID, buyer, or service..." value="${escapeHtml(searchQuery)}" aria-label="Search invoices" />
        </div>
        <div class="toolbar-group">
          <select id="inv-status-filter" class="filter-select" aria-label="Filter by invoice status">
            <option value="ALL" ${statusFilter === "ALL" ? "selected" : ""}>All Statuses</option>
            <option value="STAGED" ${statusFilter === "STAGED" ? "selected" : ""}>Staged (Awaiting Auth)</option>
            <option value="DRAFT" ${statusFilter === "DRAFT" ? "selected" : ""}>Draft</option>
            <option value="SENT" ${statusFilter === "SENT" ? "selected" : ""}>Sent (Unpaid)</option>
            <option value="PAID" ${statusFilter === "PAID" ? "selected" : ""}>Paid</option>
          </select>
          <select id="inv-sort-select" class="filter-select" aria-label="Sort invoices">
            <option value="date_desc" ${sortField === "date_desc" ? "selected" : ""}>Newest First</option>
            <option value="date_asc" ${sortField === "date_asc" ? "selected" : ""}>Oldest First</option>
            <option value="amount_desc" ${sortField === "amount_desc" ? "selected" : ""}>Highest Amount</option>
            <option value="amount_asc" ${sortField === "amount_asc" ? "selected" : ""}>Lowest Amount</option>
          </select>
        </div>
      </div>

      ${
        pageItems.length
          ? `
        <div class="table-responsive" tabindex="0" role="region" aria-label="Export invoices table">
          <table>
            <thead>
              <tr>
                <th>Invoice ID</th>
                <th>Buyer</th>
                <th>Deliverable</th>
                <th>Created</th>
                <th>Status</th>
                <th style="text-align:right;">Amount</th>
                <th style="text-align:right;">Actions</th>
              </tr>
            </thead>
            <tbody>
              ${pageItems
                .map(
                  (inv) => `
                <tr>
                  <td>
                    <div class="text-xs-mono" style="font-weight:600;">${escapeHtml(inv.invoiceId)}</div>
                    <span class="badge badge-neutral text-2xs-mono" style="margin-block-start:0.1875rem;">${escapeHtml(inv.sourceLabel)}</span>
                  </td>
                  <td>
                    <div style="font-weight:600;">${escapeHtml(inv.buyerName)}</div>
                    <div class="text-xs-mono text-muted">${escapeHtml(inv.buyerToken)}</div>
                  </td>
                  <td>
                    <div>${escapeHtml(inv.item)}</div>
                    <div class="text-xs text-muted">${escapeHtml(inv.quantity || "1 Milestone")} &bull; RBI ${escapeHtml(inv.rbiPurposeCode || "P0802")}</div>
                  </td>
                  <td class="text-sm">${formatDate(inv.date)}</td>
                  <td><span class="badge ${getStatusBadgeClass(inv.status)}">${escapeHtml(inv.status)}</span></td>
                  <td style="text-align:right;font-weight:700;" class="tabular-nums">${formatCurrency(inv.amount, inv.currency)}</td>
                  <td style="text-align:right;">
                    <button type="button" class="btn btn-secondary btn-sm" data-inspect-inv="${escapeHtml(inv.invoiceId)}">Inspect</button>
                  </td>
                </tr>`
                )
                .join("")}
            </tbody>
          </table>
        </div>
        <div class="pagination">
          <span>Showing ${(currentPage - 1) * PAGE_SIZE + 1}–${Math.min(currentPage * PAGE_SIZE, filtered.length)} of ${filtered.length} invoices</span>
          <div class="pagination-controls">
            <button type="button" class="btn btn-secondary btn-sm" id="inv-prev-page" ${currentPage <= 1 ? "disabled" : ""}>Previous</button>
            <span>Page ${currentPage} of ${totalPages}</span>
            <button type="button" class="btn btn-secondary btn-sm" id="inv-next-page" ${currentPage >= totalPages ? "disabled" : ""}>Next</button>
          </div>
        </div>`
          : `
        <div class="empty-state">
          <p>No invoices match your current search or filter criteria.</p>
          <button type="button" class="btn btn-secondary btn-sm" id="inv-reset-filters">Reset Filters</button>
        </div>`
      }
    </div>
  `;

  // Restore search input focus smoothly
  if (isSearchFocused) {
    const searchInput = document.getElementById("inv-search-input");
    if (searchInput) {
      searchInput.focus();
      if (searchCaretStart !== null && searchCaretEnd !== null) {
        try {
          searchInput.setSelectionRange(searchCaretStart, searchCaretEnd);
        } catch {
          // ignore
        }
      }
    }
  }

  // Wire search and filter inputs
  document.getElementById("inv-search-input")?.addEventListener("input", (e) => {
    searchQuery = e.target.value;
    currentPage = 1;
    renderInvoicesPage(mount);
  });
  document.getElementById("inv-status-filter")?.addEventListener("change", (e) => {
    statusFilter = e.target.value;
    currentPage = 1;
    renderInvoicesPage(mount);
  });
  document.getElementById("inv-sort-select")?.addEventListener("change", (e) => {
    sortField = e.target.value;
    renderInvoicesPage(mount);
  });
  document.getElementById("inv-prev-page")?.addEventListener("click", () => {
    if (currentPage > 1) {
      currentPage--;
      renderInvoicesPage(mount);
    }
  });
  document.getElementById("inv-next-page")?.addEventListener("click", () => {
    if (currentPage < totalPages) {
      currentPage++;
      renderInvoicesPage(mount);
    }
  });
  document.getElementById("inv-reset-filters")?.addEventListener("click", () => {
    searchQuery = "";
    statusFilter = "ALL";
    currentPage = 1;
    renderInvoicesPage(mount);
  });

  document.getElementById("inv-refresh-btn")?.addEventListener("click", async () => {
    const btn = document.getElementById("inv-refresh-btn");
    if (btn) btn.disabled = true;
    try {
      const res = await api.listInvoices();
      store.setState({ invoices: res.invoices || [] });
      if (store.getState().route === "invoices") {
        renderInvoicesPage(mount);
      }
      showToast({ title: "Invoices Updated", message: `${res.invoices?.length || 0} invoices synced.`, type: "success" });
    } catch (err) {
      showToast({ title: "Refresh Failed", message: err.message, type: "error" });
      if (btn) btn.disabled = false;
    }
  });

  document.getElementById("inv-new-btn")?.addEventListener("click", () => openCreateInvoiceModal(mount));

  mount.querySelectorAll("[data-inspect-inv]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = btn.getAttribute("data-inspect-inv");
      const found = allInvoices.find((i) => i.invoiceId === id);
      if (found) openInvoiceDetailModal(found, mount);
    });
  });
}

function openCreateInvoiceModal(mount) {
  const buyers = store.getState().buyers || [];
  openModal({
    title: "Create Cross-Border Invoice",
    bodyHtml: `
      <div class="alert alert-info">
        <div class="alert-content">
          <span class="alert-title">Deterministic Guardrail &amp; Passkey Flow</span>
          <span>All manual invoices pass through Money Guide policy validation ($2,500 USD cap, allowlist, duplicate window) and require WebAuthn passkey authorization before dispatch.</span>
        </div>
      </div>
      <form id="create-invoice-form" class="settings-section">
        <div class="form-group">
          <label class="form-label" for="ci-buyer">Allowlisted Buyer</label>
          <select id="ci-buyer" required>
            ${
              buyers.length
                ? buyers
                    .map(
                      (b) =>
                        `<option value="${escapeHtml(b.buyerToken)}">${escapeHtml(b.displayName)} (${escapeHtml(b.buyerToken)}) — ${escapeHtml(b.currency)}</option>`
                    )
                    .join("")
                : `<option value="BUYER_RAHUL_01">Rahul Mehta (BUYER_RAHUL_01) — USD</option>
                   <option value="BUYER_ELENA_02">Elena Rostova (BUYER_ELENA_02) — EUR</option>
                   <option value="BUYER_OLIVER_03">Oliver Grant (BUYER_OLIVER_03) — GBP</option>`
            }
          </select>
        </div>
        <div class="grid-2" style="gap:12px;">
          <div class="form-group">
            <label class="form-label" for="ci-amount">Amount</label>
            <input id="ci-amount" type="number" step="0.01" min="0.01" value="200.00" required />
          </div>
          <div class="form-group">
            <label class="form-label" for="ci-currency">Currency</label>
            <select id="ci-currency">
              <option value="USD">USD — US Dollar</option>
              <option value="EUR">EUR — Euro</option>
              <option value="GBP">GBP — British Pound</option>
              <option value="AUD">AUD — Australian Dollar</option>
              <option value="CAD">CAD — Canadian Dollar</option>
              <option value="SGD">SGD — Singapore Dollar</option>
              <option value="JPY">JPY — Japanese Yen</option>
              <option value="INR">INR — Indian Rupee (Will Be Blocked by OPGSP Rule)</option>
            </select>
          </div>
        </div>
        <div class="grid-2" style="gap:12px;">
          <div class="form-group">
            <label class="form-label" for="ci-item">Service / Deliverable</label>
            <input id="ci-item" type="text" value="Cloud API Development" required />
          </div>
          <div class="form-group">
            <label class="form-label" for="ci-qty">Quantity / Milestone</label>
            <input id="ci-qty" type="text" value="1 Milestone" required />
          </div>
        </div>
        <div id="ci-error-box"></div>
      </form>
    `,
    footerHtml: `
      <button type="button" class="btn btn-secondary" id="ci-cancel">Cancel</button>
      <button type="button" class="btn btn-primary" id="ci-stage-btn">Validate &amp; Stage Invoice</button>
    `,
    onMount: () => {
      document.getElementById("ci-cancel")?.addEventListener("click", closeModal);
      document.getElementById("ci-stage-btn")?.addEventListener("click", async () => {
        const btn = document.getElementById("ci-stage-btn");
        const errBox = document.getElementById("ci-error-box");
        const buyerEl = document.getElementById("ci-buyer");
        const amountEl = document.getElementById("ci-amount");
        const currencyEl = document.getElementById("ci-currency");
        const itemEl = document.getElementById("ci-item");
        const qtyEl = document.getElementById("ci-qty");

        const buyerToken = buyerEl?.value || "BUYER_RAHUL_01";
        const amount = Number(amountEl?.value || 0);
        const currency = currencyEl?.value || "USD";
        const item = itemEl?.value?.trim() || "Cloud API Development";
        const quantity = qtyEl?.value?.trim() || "1 Milestone";

        if (btn) {
          btn.disabled = true;
          btn.textContent = "Validating...";
        }
        if (errBox) errBox.innerHTML = "";

        try {
          const staged = await api.stageInvoice({
            transcript: `Invoice ${buyerToken} ${amount} ${currency} for ${item}`,
            language: store.getState().language,
            intent: { action: "create_invoice", buyer_token: buyerToken, item, amount, currency, quantity },
          });
          store.setState({ currentStaged: staged });
          closeModal();
          openInvoicePreviewModal(staged, {
            onExecuted: () => {
              if (store.getState().route === "invoices") {
                renderInvoicesPage(mount);
              }
            },
          });
        } catch (err) {
          if (btn) {
            btn.disabled = false;
            btn.textContent = "Validate & Stage Invoice";
          }
          if (errBox) {
            errBox.innerHTML = `<div class="alert alert-error" style="margin-block-start:0.75rem;"><div class="alert-content"><span class="alert-title">${escapeHtml(err.code || "Policy Violation")}</span><span>${escapeHtml(err.message)}</span></div></div>`;
          }
        }
      });
    },
  });
}

function openInvoiceDetailModal(inv, mount) {
  const remindersSent = store.getState().remindersSent || {};
  const lastRem = remindersSent[inv.invoiceId];
  const inCooldown = lastRem && Date.now() - lastRem < REMINDER_COOLDOWN_MS;
  const isSent = inv.status === "SENT";
  const isStaged = inv.status === "STAGED";
  const isPaid = inv.status === "PAID";

  openModal({
    title: `Invoice ${inv.invoiceId}`,
    size: "lg",
    bodyHtml: `
      <div class="invoice-sheet">
        <div class="invoice-sheet-head">
          <div>
            <span class="badge ${getStatusBadgeClass(inv.status)}" style="margin-bottom:6px;">${escapeHtml(inv.status)}</span>
            <h3>${escapeHtml(inv.buyerName)}</h3>
            <p class="text-sm text-muted">${escapeHtml(inv.buyerToken)} &bull; ${escapeHtml(inv.buyerCompany || "International Client")}</p>
          </div>
          <div class="invoice-total-amount">${formatCurrency(inv.amount, inv.currency)}</div>
        </div>

        <div class="kv-grid">
          <div class="kv-item"><div class="kv-label">Deliverable</div><div class="kv-val">${escapeHtml(inv.item)}</div></div>
          <div class="kv-item"><div class="kv-label">Quantity</div><div class="kv-val">${escapeHtml(inv.quantity || "1 Milestone")}</div></div>
          <div class="kv-item"><div class="kv-label">Created</div><div class="kv-val">${formatDateTime(inv.date)}</div></div>
          <div class="kv-item"><div class="kv-label">RBI Purpose Code</div><div class="kv-val">${escapeHtml(inv.rbiPurposeCode || "P0802")}</div></div>
        </div>

        ${
          inv.assertionId
            ? `<div><div class="form-label" style="margin-bottom:4px;">Verified WebAuthn Assertion ID</div><div class="mono-box">${escapeHtml(inv.assertionId)}</div></div>`
            : ""
        }

        <div>
          <div class="form-label" style="margin-bottom:8px;">Lifecycle Timeline</div>
          <div class="timeline">
            ${(inv.timeline || [])
              .map(
                (step, idx) => `
              <div class="timeline-item completed">
                <div class="timeline-dot">${idx + 1}</div>
                <div class="timeline-body">
                  <h4>${escapeHtml(step.status)}</h4>
                  <p>${escapeHtml(step.label)}</p>
                  <time>${formatDateTime(step.timestamp)}</time>
                </div>
              </div>`
              )
              .join("")}
          </div>
        </div>
      </div>
    `,
    footerHtml: `
      <button type="button" class="btn btn-secondary" id="inv-det-copy">Copy Invoice ID</button>
      ${
        isPaid
          ? `<button type="button" class="btn btn-secondary" id="inv-det-stmt">Generate Statement</button>`
          : ""
      }
      <button type="button" class="btn btn-secondary" id="inv-det-close">Close</button>
      ${
        isStaged
          ? `<button type="button" class="btn btn-success" id="inv-det-auth">Authorize with Passkey</button>`
          : ""
      }
      ${
        isSent
          ? `
        <button type="button" class="btn btn-secondary" id="inv-det-remind" ${inCooldown ? "disabled" : ""}>
          ${inCooldown ? "Reminder Cooldown (24h)" : "Send Payment Reminder"}
        </button>
        <button type="button" class="btn btn-success" id="inv-det-settle">Simulate Settlement (PAID)</button>`
          : ""
      }
    `,
    onMount: () => {
      document.getElementById("inv-det-close")?.addEventListener("click", closeModal);
      document.getElementById("inv-det-copy")?.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(inv.invoiceId);
          showToast({ title: "Copied", message: `Invoice ID ${inv.invoiceId} copied to clipboard.`, type: "success" });
        } catch {
          showToast({ title: "Invoice ID", message: inv.invoiceId, type: "info" });
        }
      });
      document.getElementById("inv-det-stmt")?.addEventListener("click", () => {
        closeModal();
        navigateTo("statements");
      });
      document.getElementById("inv-det-auth")?.addEventListener("click", () => {
        closeModal();
        openPasskeyAuthModal(inv._stagedRef, {
          onSuccess: () => {
            if (store.getState().route === "invoices") {
              renderInvoicesPage(mount);
            }
          },
        });
      });
      document.getElementById("inv-det-remind")?.addEventListener("click", () => {
        const current = store.getState().remindersSent || {};
        store.setState({
          remindersSent: { ...current, [inv.invoiceId]: Date.now() },
        });
        store.addNotification({
          title: "Payment Reminder Logged",
          message: `Reminder queued for ${inv.invoiceId} (${inv.buyerName}). 24-hour cooldown active.`,
          severity: "info",
        });
        showToast({ title: "Reminder Sent", message: `24h cooldown engaged for ${inv.invoiceId}.`, type: "success" });
        closeModal();
        if (store.getState().route === "invoices") {
          renderInvoicesPage(mount);
        }
      });
      document.getElementById("inv-det-settle")?.addEventListener("click", async () => {
        const btn = document.getElementById("inv-det-settle");
        if (btn) {
          btn.disabled = true;
          btn.textContent = "Settling...";
        }
        try {
          const res = await api.simulateInvoicePayment(inv.invoiceId);
          const settledInvoice = res.invoice || { ...inv, status: "PAID" };
          const list = store.getState().invoices || [];
          const exists = list.some((item) => item.invoiceId === inv.invoiceId);
          const updatedInvoices = exists
            ? list.map((item) => (item.invoiceId === inv.invoiceId ? settledInvoice : item))
            : [settledInvoice, ...list];
          store.setState({ invoices: updatedInvoices });
          showToast({ title: "Invoice Paid", message: `${inv.invoiceId} transitioned to PAID via OPGSP.`, type: "success" });
          closeModal();
          if (store.getState().route === "invoices") {
            renderInvoicesPage(mount);
          }
        } catch (err) {
          showToast({ title: "Settlement Error", message: err.message, type: "error" });
          if (btn) {
            btn.disabled = false;
            btn.textContent = "Simulate Settlement (PAID)";
          }
        }
      });
    },
  });
}
