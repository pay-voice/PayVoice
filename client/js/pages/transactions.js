/**
 * Page 4: Transactions Dashboard
 * Displays backend transactions from GET /api/transactions with search, filtering,
 * sorting, pagination, deterministic totals, and transaction inspection modal.
 */

import { api } from "../api.js";
import { store } from "../store.js";
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
let currencyFilter = "ALL";
let statusFilter = "ALL";
let sortField = "date_desc";
let currentPage = 1;
const PAGE_SIZE = 8;

export function renderTransactionsPage(mount) {
  const state = store.getState();
  const txs = state.transactions || [];
  const totals = state.transactionTotals;
  const currencies = Array.from(new Set(txs.map((t) => String(t.currency || "USD").toUpperCase())));

  const filtered = txs.filter((tx) => {
    const q = searchQuery.toLowerCase();
    const matchSearch =
      !q ||
      String(tx.id).toLowerCase().includes(q) ||
      String(tx.invoiceId || "").toLowerCase().includes(q) ||
      String(tx.buyerName || "").toLowerCase().includes(q) ||
      String(tx.buyerToken || "").toLowerCase().includes(q) ||
      String(tx.item || "").toLowerCase().includes(q);
    const matchCurr = currencyFilter === "ALL" || String(tx.currency).toUpperCase() === currencyFilter;
    const matchStatus = statusFilter === "ALL" || String(tx.status).toUpperCase() === statusFilter;
    return matchSearch && matchCurr && matchStatus;
  });

  filtered.sort((a, b) => {
    const amtA = Number(a.grossAmount || a.amount || 0);
    const amtB = Number(b.grossAmount || b.amount || 0);
    if (sortField === "amount_desc") return amtB - amtA;
    if (sortField === "amount_asc") return amtA - amtB;
    if (sortField === "date_asc") return new Date(a.date) - new Date(b.date);
    return new Date(b.date) - new Date(a.date);
  });

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  if (currentPage > totalPages) currentPage = totalPages;
  const pageItems = filtered.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);

  mount.innerHTML = `
    <div class="page-header">
      <div class="page-header-copy">
        <h1>Transactions</h1>
        <p>Verified cross-border PayPal export settlements and fee reconciliation</p>
      </div>
      <div class="page-header-actions">
        <button type="button" class="btn btn-secondary" id="tx-refresh-btn">Refresh Ledger</button>
      </div>
    </div>

    <div class="kpi-grid">
      <div class="metric-card">
        <div class="metric-label">Verified Settlements</div>
        <div class="metric-value tabular-nums">${totals ? totals.count : txs.length}</div>
        <div class="metric-foot">Cross-border export records</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Total Gross (Native Sum)</div>
        <div class="metric-value tabular-nums">${totals ? formatCurrency(totals.totalGross, totals.currency) : "—"}</div>
        <div class="metric-foot">Computed deterministically by Node.js</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Total PayPal Fees</div>
        <div class="metric-value warning tabular-nums">${totals ? formatCurrency(totals.estimatedFees, totals.currency) : "—"}</div>
        <div class="metric-foot">Cross-border merchant fee</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Total Net Realized</div>
        <div class="metric-value success tabular-nums">${totals ? formatCurrency(totals.totalNet, totals.currency) : "—"}</div>
        <div class="metric-foot">Net payout before INR FX credit</div>
      </div>
    </div>

    <div class="card">
      <div class="toolbar">
        <div class="search-input-wrap">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>
          <input type="search" id="tx-search" placeholder="Search TX ID, invoice, buyer, or service..." value="${escapeHtml(searchQuery)}" aria-label="Search transactions" />
        </div>
        <div class="toolbar-group">
          <select id="tx-curr-filter" class="filter-select" aria-label="Filter by currency">
            <option value="ALL">All Currencies</option>
            ${currencies.map((c) => `<option value="${c}" ${currencyFilter === c ? "selected" : ""}>${c}</option>`).join("")}
          </select>
          <select id="tx-status-filter" class="filter-select" aria-label="Filter by status">
            <option value="ALL" ${statusFilter === "ALL" ? "selected" : ""}>All Statuses</option>
            <option value="COMPLETED" ${statusFilter === "COMPLETED" ? "selected" : ""}>Completed</option>
            <option value="REFUNDED" ${statusFilter === "REFUNDED" ? "selected" : ""}>Refunded</option>
          </select>
          <select id="tx-sort" class="filter-select" aria-label="Sort transactions">
            <option value="date_desc" ${sortField === "date_desc" ? "selected" : ""}>Newest First</option>
            <option value="date_asc" ${sortField === "date_asc" ? "selected" : ""}>Oldest First</option>
            <option value="amount_desc" ${sortField === "amount_desc" ? "selected" : ""}>Amount: High to Low</option>
            <option value="amount_asc" ${sortField === "amount_asc" ? "selected" : ""}>Amount: Low to High</option>
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
                <th>Date</th>
                <th>Transaction & Invoice</th>
                <th>Buyer</th>
                <th>Description</th>
                <th>Status</th>
                <th style="text-align:right;">Gross</th>
                <th style="text-align:right;">Fee</th>
                <th style="text-align:right;">Net</th>
              </tr>
            </thead>
            <tbody>
              ${pageItems
                .map(
                  (tx) => `
                <tr data-tx-id="${escapeHtml(tx.id)}" style="cursor:pointer;" tabindex="0" role="button" aria-label="Inspect transaction ${escapeHtml(tx.id)}">
                  <td>${formatDate(tx.date)}</td>
                  <td>
                    <div style="font-family:var(--font-mono);font-size:12px;font-weight:600;">${escapeHtml(tx.id)}</div>
                    <div style="font-size:11px;color:var(--color-text-tertiary);font-family:var(--font-mono);">${escapeHtml(tx.invoiceId || "—")}</div>
                  </td>
                  <td>
                    <div style="font-weight:600;">${escapeHtml(tx.buyerName || "Overseas Buyer")}</div>
                    <div style="font-size:11px;color:var(--color-text-tertiary);font-family:var(--font-mono);">${escapeHtml(tx.buyerToken || "")}</div>
                  </td>
                  <td>${escapeHtml(tx.item || tx.description)}</td>
                  <td><span class="badge ${getStatusBadgeClass(tx.status)}">${escapeHtml(tx.status)}</span></td>
                  <td style="text-align:right;font-weight:600;" class="tabular-nums">${formatCurrency(tx.grossAmount || tx.amount, tx.currency)}</td>
                  <td style="text-align:right;color:var(--color-text-tertiary);" class="tabular-nums">-${formatCurrency(tx.fee || 0, tx.currency)}</td>
                  <td style="text-align:right;font-weight:700;color:var(--color-success);" class="tabular-nums">${formatCurrency(tx.netAmount || 0, tx.currency)}</td>
                </tr>`
                )
                .join("")}
            </tbody>
          </table>
        </div>
        <div class="pagination">
          <span>Showing ${(currentPage - 1) * PAGE_SIZE + 1}–${Math.min(currentPage * PAGE_SIZE, filtered.length)} of ${filtered.length} transactions</span>
          <div class="pagination-controls">
            <button type="button" class="btn btn-secondary btn-sm" id="tx-prev" ${currentPage <= 1 ? "disabled" : ""}>Previous</button>
            <span>Page ${currentPage} of ${totalPages}</span>
            <button type="button" class="btn btn-secondary btn-sm" id="tx-next" ${currentPage >= totalPages ? "disabled" : ""}>Next</button>
          </div>
        </div>`
          : `
        <div class="empty-state">
          <p>No transactions match the selected filters.</p>
          <button type="button" class="btn btn-secondary btn-sm" id="tx-reset">Reset Filters</button>
        </div>`
      }
    </div>
  `;

  document.getElementById("tx-search")?.addEventListener("input", (e) => {
    searchQuery = e.target.value;
    currentPage = 1;
    renderTransactionsPage(mount);
  });
  document.getElementById("tx-curr-filter")?.addEventListener("change", (e) => {
    currencyFilter = e.target.value;
    currentPage = 1;
    renderTransactionsPage(mount);
  });
  document.getElementById("tx-status-filter")?.addEventListener("change", (e) => {
    statusFilter = e.target.value;
    currentPage = 1;
    renderTransactionsPage(mount);
  });
  document.getElementById("tx-sort")?.addEventListener("change", (e) => {
    sortField = e.target.value;
    renderTransactionsPage(mount);
  });
  document.getElementById("tx-prev")?.addEventListener("click", () => {
    if (currentPage > 1) {
      currentPage--;
      renderTransactionsPage(mount);
    }
  });
  document.getElementById("tx-next")?.addEventListener("click", () => {
    if (currentPage < totalPages) {
      currentPage++;
      renderTransactionsPage(mount);
    }
  });
  document.getElementById("tx-reset")?.addEventListener("click", () => {
    searchQuery = "";
    currencyFilter = "ALL";
    statusFilter = "ALL";
    currentPage = 1;
    renderTransactionsPage(mount);
  });

  document.getElementById("tx-refresh-btn")?.addEventListener("click", async () => {
    try {
      const res = await api.getTransactions();
      store.setState({
        transactions: res.transactions || [],
        transactionTotals: res.totals || null,
        cfoInsights: res.cfoInsights || null,
      });
      renderTransactionsPage(mount);
      showToast({ title: "Transactions Synced", type: "success" });
    } catch (err) {
      showToast({ title: "Sync Error", message: err.message, type: "error" });
    }
  });

  const openTxDetail = (tx) => {
    openModal({
      title: `Transaction ${tx.id}`,
      bodyHtml: `
        <div class="invoice-sheet">
          <div class="invoice-sheet-head">
            <div>
              <span class="badge ${getStatusBadgeClass(tx.status)}" style="margin-bottom:6px;">${escapeHtml(tx.status)}</span>
              <h3>${escapeHtml(tx.buyerName || "Overseas Buyer")}</h3>
              <p style="font-size:13px;">Token: <code>${escapeHtml(tx.buyerToken || "—")}</code></p>
            </div>
            <div class="invoice-total-amount">${formatCurrency(tx.grossAmount || tx.amount, tx.currency)}</div>
          </div>
          <div class="kv-grid">
            <div class="kv-item"><div class="kv-label">Associated Invoice</div><div class="kv-val" style="font-family:var(--font-mono);">${escapeHtml(tx.invoiceId || "N/A")}</div></div>
            <div class="kv-item"><div class="kv-label">Timestamp</div><div class="kv-val">${formatDateTime(tx.date)}</div></div>
            <div class="kv-item"><div class="kv-label">PayPal Fee</div><div class="kv-val">${formatCurrency(tx.fee || 0, tx.currency)}</div></div>
            <div class="kv-item"><div class="kv-label">Net Settlement</div><div class="kv-val" style="color:var(--color-success);">${formatCurrency(tx.netAmount || 0, tx.currency)}</div></div>
          </div>
          <div class="kv-item">
            <div class="kv-label">Service / Export Line Item</div>
            <div class="kv-val">${escapeHtml(tx.item || tx.description)}</div>
          </div>
        </div>
      `,
      footerHtml: `<button type="button" class="btn btn-primary" id="tx-modal-close">Close</button>`,
      onMount: () => document.getElementById("tx-modal-close")?.addEventListener("click", closeModal),
    });
  };

  mount.querySelectorAll("tr[data-tx-id]").forEach((row) => {
    const id = row.getAttribute("data-tx-id");
    const tx = txs.find((t) => t.id === id);
    if (!tx) return;
    row.addEventListener("click", () => openTxDetail(tx));
    row.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        openTxDetail(tx);
      }
    });
  });
}

