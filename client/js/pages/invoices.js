/**
 * Page 3: Invoice Management
 * Search, filter, sort, pagination, staged/draft/sent/paid lifecycle view,
 * reminder cooldown enforcement, and guarded invoice creation.
 */

import { api } from "../api.js";
import { store } from "../store.js";
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
  const state = store.getState();
  const sessionInvoices = (state.invoices || []).map((inv) => ({
    ...inv,
    sourceLabel: "LIVE SESSION",
    date: inv.createdAt,
  }));

  const stagedItem = state.currentStaged
    ? [
        {
          invoiceId: state.currentStaged.stageId,
          buyerToken: state.currentStaged.stagedPayload.buyerToken,
          buyerName: state.currentStaged.stagedPayload.buyerName,
          buyerCompany: state.currentStaged.stagedPayload.buyerCompany,
          item: state.currentStaged.stagedPayload.item,
          quantity: state.currentStaged.stagedPayload.quantity,
          amount: state.currentStaged.stagedPayload.amount,
          currency: state.currentStaged.stagedPayload.currency,
          rbiPurposeCode: state.currentStaged.stagedPayload.rbiPurposeCode,
          lutStatus: state.currentStaged.stagedPayload.lutStatus,
          status: "STAGED",
          date: state.currentStaged.stagedPayload.stagedAt,
          sourceLabel: "AWAITING AUTH",
          _stagedRef: state.currentStaged,
          timeline: [
            {
              status: "STAGED",
              label: "Validated by Money Guide AI & bound to WebAuthn challenge",
              timestamp: state.currentStaged.stagedPayload.stagedAt,
            },
          ],
        },
      ]
    : [];

  // Include sandbox historical invoices derived from settled transactions
  const historicalInvoices = (state.transactions || []).map((tx) => ({
    invoiceId: tx.invoiceId,
    buyerToken: tx.buyerToken,
    buyerName: tx.buyerName,
    buyerCompany: "Sandbox Export Contract",
    item: tx.item,
    quantity: "1 Contract",
    amount: tx.grossAmount || tx.amount,
    currency: tx.currency,
    rbiPurposeCode: "P0802",
    status: tx.status === "COMPLETED" ? "PAID" : tx.status,
    date: tx.date,
    sourceLabel: "SANDBOX RECORD",
    timeline: [
      { status: "DRAFT", label: "Sandbox Invoice Created", timestamp: tx.date },
      { status: "SENT", label: "Sent to Buyer", timestamp: tx.date },
      { status: "PAID", label: "Inward Remittance Settled", timestamp: tx.date },
    ],
  }));

  const allInvoices = [...stagedItem, ...sessionInvoices, ...historicalInvoices];

  // Filter
  const filtered = allInvoices.filter((inv) => {
    const matchesStatus = statusFilter === "ALL" || String(inv.status).toUpperCase() === statusFilter;
    const q = searchQuery.toLowerCase();
    const matchesSearch =
      !q ||
      String(inv.invoiceId).toLowerCase().includes(q) ||
      String(inv.buyerName).toLowerCase().includes(q) ||
      String(inv.buyerToken).toLowerCase().includes(q) ||
      String(inv.item).toLowerCase().includes(q);
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
        <button type="button" class="btn btn-secondary" id="inv-refresh-btn">Sync Invoices</button>
        <button type="button" class="btn btn-primary" id="inv-new-btn">Create Invoice</button>
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
        <div class="table-responsive">
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
                    <div style="font-family:var(--font-mono);font-size:12px;font-weight:600;">${escapeHtml(inv.invoiceId)}</div>
                    <span class="badge badge-neutral" style="margin-top:3px;font-size:10px;">${escapeHtml(inv.sourceLabel)}</span>
                  </td>
                  <td>
                    <div style="font-weight:600;">${escapeHtml(inv.buyerName)}</div>
                    <div style="font-size:12px;color:var(--color-text-tertiary);font-family:var(--font-mono);">${escapeHtml(inv.buyerToken)}</div>
                  </td>
                  <td>
                    <div>${escapeHtml(inv.item)}</div>
                    <div style="font-size:12px;color:var(--color-text-tertiary);">${escapeHtml(inv.quantity || "1 Milestone")} &bull; RBI ${escapeHtml(inv.rbiPurposeCode || "P0802")}</div>
                  </td>
                  <td style="font-size:13px;">${formatDate(inv.date)}</td>
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
    try {
      const res = await api.listInvoices();
      store.setState({ invoices: res.invoices || [] });
      renderInvoicesPage(mount);
      showToast({ title: "Invoices Updated", type: "success" });
    } catch (err) {
      showToast({ title: "Refresh Failed", message: err.message, type: "error" });
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
          <span class="alert-title">Deterministic Guardrail & Passkey Flow</span>
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
                : `<option value="BUYER_RAHUL_01">Rahul Mehta (BUYER_RAHUL_01)</option>`
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
              <option value="INR">INR — Indian Rupee (Will Be Blocked by OPGSP)</option>
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
      <button type="button" class="btn btn-primary" id="ci-stage-btn">Validate & Stage Invoice</button>
    `,
    onMount: () => {
      document.getElementById("ci-cancel")?.addEventListener("click", closeModal);
      document.getElementById("ci-stage-btn")?.addEventListener("click", async () => {
        const btn = document.getElementById("ci-stage-btn");
        const errBox = document.getElementById("ci-error-box");
        const buyerToken = document.getElementById("ci-buyer").value;
        const amount = Number(document.getElementById("ci-amount").value);
        const currency = document.getElementById("ci-currency").value;
        const item = document.getElementById("ci-item").value.trim();
        const quantity = document.getElementById("ci-qty").value.trim();

        btn.disabled = true;
        btn.textContent = "Validating...";
        errBox.innerHTML = "";

        try {
          const staged = await api.stageInvoice({
            transcript: `Invoice ${buyerToken} ${amount} ${currency} for ${item}`,
            language: store.getState().language,
            intent: { action: "create_invoice", buyer_token: buyerToken, item, amount, currency, quantity },
          });
          store.setState({ currentStaged: staged });
          closeModal();
          openInvoicePreviewModal(staged, {
            onExecuted: () => renderInvoicesPage(mount),
          });
        } catch (err) {
          btn.disabled = false;
          btn.textContent = "Validate & Stage Invoice";
          errBox.innerHTML = `<div class="alert alert-error"><div class="alert-content"><span class="alert-title">${escapeHtml(err.code || "Policy Violation")}</span><span>${escapeHtml(err.message)}</span></div></div>`;
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

  openModal({
    title: `Invoice ${inv.invoiceId}`,
    size: "lg",
    bodyHtml: `
      <div class="invoice-sheet">
        <div class="invoice-sheet-head">
          <div>
            <span class="badge ${getStatusBadgeClass(inv.status)}" style="margin-bottom:6px;">${escapeHtml(inv.status)}</span>
            <h3>${escapeHtml(inv.buyerName)}</h3>
            <p style="font-size:13px;">${escapeHtml(inv.buyerToken)} &bull; ${escapeHtml(inv.buyerCompany || "International Client")}</p>
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
      document.getElementById("inv-det-auth")?.addEventListener("click", () => {
        closeModal();
        openPasskeyAuthModal(inv._stagedRef, { onSuccess: () => renderInvoicesPage(mount) });
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
        renderInvoicesPage(mount);
      });
      document.getElementById("inv-det-settle")?.addEventListener("click", async () => {
        const btn = document.getElementById("inv-det-settle");
        btn.disabled = true;
        btn.textContent = "Settling...";
        try {
          const res = await api.simulateInvoicePayment(inv.invoiceId);
          const list = store.getState().invoices || [];
          store.setState({
            invoices: list.map((item) => (item.invoiceId === inv.invoiceId ? res.invoice : item)),
          });
          showToast({ title: "Invoice Paid", message: `${inv.invoiceId} transitioned to PAID.`, type: "success" });
          closeModal();
          renderInvoicesPage(mount);
        } catch (err) {
          showToast({ title: "Settlement Error", message: err.message, type: "error" });
          btn.disabled = false;
          btn.textContent = "Simulate Settlement (PAID)";
        }
      });
    },
  });
}

