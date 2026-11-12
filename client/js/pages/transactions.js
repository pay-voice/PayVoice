/**
 * Page 4: Transactions Dashboard
 * Displays backend transactions from GET /api/transactions with search, filtering,
 * sorting, pagination, deterministic totals, CSV ledger export, and transaction inspection modal.
 */

import { api } from "../api.js";
import { store } from "../store.js";
import { navigateTo } from "../router.js";
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

/**
 * Sanitize CSV cell values to prevent spreadsheet formula injection attacks
 */
function sanitizeCsvCell(val) {
  let str = String(val ?? "");
  if (/^[=\+\-@\t\r]/.test(str)) {
    str = `'${str}`;
  }
  if (/[",\n\r]/.test(str)) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

/**
 * Deterministically export transactions to a clean, formula-injection-safe CSV file
 */
function exportTransactionsCsv(transactions = []) {
  if (!transactions.length) {
    showToast({ title: "No Transactions", message: "No records to export.", type: "warning" });
    return;
  }

  const headers = [
    "Transaction ID",
    "Invoice ID",
    "Date",
    "Buyer Name",
    "Buyer Token",
    "Deliverable",
    "Currency",
    "Gross Amount",
    "PayPal Fee",
    "Net Amount",
    "Status",
  ];

  const rows = transactions.map((tx) => [
    sanitizeCsvCell(tx.id),
    sanitizeCsvCell(tx.invoiceId || ""),
    sanitizeCsvCell(tx.date),
    sanitizeCsvCell(tx.buyerName || "Overseas Buyer"),
    sanitizeCsvCell(tx.buyerToken || ""),
    sanitizeCsvCell(tx.item || tx.description || ""),
    sanitizeCsvCell(tx.currency || "USD"),
    Number(tx.grossAmount || tx.amount || 0).toFixed(2),
    Number(tx.fee || 0).toFixed(2),
    Number(tx.netAmount || 0).toFixed(2),
    sanitizeCsvCell(tx.status || "COMPLETED"),
  ]);

  const csvContent = [headers.join(","), ...rows.map((r) => r.join(","))].join("\r\n");
  const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `payvoice-transactions-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(a);
  a.click();
  URL.revokeObjectURL(url);
  a.remove();

  showToast({
    title: "CSV Ledger Exported",
    message: `${transactions.length} verified records saved to CSV.`,
    type: "success",
  });
}

/**
 * Compute fallback totals client-side when backend totals are not yet populated
 */
function getEffectiveTotals(txs, backendTotals) {
  if (backendTotals && typeof backendTotals.totalGross === "number") {
    return backendTotals;
  }
  let totalGross = 0;
  let estimatedFees = 0;
  const currency = txs[0]?.currency || "USD";
  for (const t of txs) {
    const gross = Number(t.grossAmount || t.amount || 0);
    if (!isNaN(gross) && gross > 0) {
      totalGross += gross;
      const fee = Number(t.fee || (gross * 0.0349 + 0.49).toFixed(2));
      estimatedFees += fee;
    }
  }
  return {
    count: txs.length,
    currency,
    totalGross: Number(totalGross.toFixed(2)),
    estimatedFees: Number(estimatedFees.toFixed(2)),
    totalNet: Number(Math.max(0, totalGross - estimatedFees).toFixed(2)),
  };
}

export function renderTransactionsPage(mount) {
  // Capture active search focus state to preserve cursor across re-renders
  const activeEl = document.activeElement;
  const isSearchFocused = activeEl && activeEl.id === "tx-search";
  const searchCaretStart = isSearchFocused ? activeEl.selectionStart : null;
  const searchCaretEnd = isSearchFocused ? activeEl.selectionEnd : null;

  const state = store.getState();
  const txs = state.transactions || [];
  const totals = getEffectiveTotals(txs, state.transactionTotals);

  // Derive dynamic filter lists
  const currencies = Array.from(new Set(txs.map((t) => String(t.currency || "USD").toUpperCase())));
  const allKnownStatuses = Array.from(
    new Set(["COMPLETED", "PAID", "REFUNDED", "PENDING", ...txs.map((t) => String(t.status || "").toUpperCase())].filter(Boolean))
  );

  const filtered = txs.filter((tx) => {
    const q = searchQuery.toLowerCase().trim();
    const matchSearch =
      !q ||
      String(tx.id || "").toLowerCase().includes(q) ||
      String(tx.invoiceId || "").toLowerCase().includes(q) ||
      String(tx.buyerName || "").toLowerCase().includes(q) ||
      String(tx.buyerToken || "").toLowerCase().includes(q) ||
      String(tx.item || "").toLowerCase().includes(q) ||
      String(tx.description || "").toLowerCase().includes(q);
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
        <button type="button" class="btn btn-secondary" id="tx-export-csv-btn">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true" style="margin-right:6px;"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
          Export CSV Ledger
        </button>
        <button type="button" class="btn btn-secondary" id="tx-refresh-btn">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true" style="margin-right:6px;"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
          Refresh Ledger
        </button>
      </div>
    </div>

    <div class="kpi-grid">
      <div class="metric-card">
        <div class="metric-label">Verified Settlements</div>
        <div class="metric-value tabular-nums">${totals.count}</div>
        <div class="metric-foot">Cross-border export records</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Total Gross (Native Sum)</div>
        <div class="metric-value tabular-nums">${formatCurrency(totals.totalGross, totals.currency)}</div>
        <div class="metric-foot">Computed deterministically by Node.js</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Total PayPal Fees</div>
        <div class="metric-value warning tabular-nums">${formatCurrency(totals.estimatedFees, totals.currency)}</div>
        <div class="metric-foot">Cross-border merchant fee</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Total Net Realized</div>
        <div class="metric-value success tabular-nums">${formatCurrency(totals.totalNet, totals.currency)}</div>
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
            ${allKnownStatuses.map((s) => `<option value="${s}" ${statusFilter === s ? "selected" : ""}>${s}</option>`).join("")}
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
        <div class="table-responsive" tabindex="0" role="region" aria-label="Cross-border export transactions table">
          <table>
            <thead>
              <tr>
                <th>Date</th>
                <th>Transaction &amp; Invoice</th>
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
                    <div class="text-xs-mono" style="font-weight:600;">${escapeHtml(tx.id)}</div>
                    <div class="text-2xs-mono text-muted">${escapeHtml(tx.invoiceId || "—")}</div>
                  </td>
                  <td>
                    <div style="font-weight:600;">${escapeHtml(tx.buyerName || "Overseas Buyer")}</div>
                    <div class="text-2xs-mono text-muted">${escapeHtml(tx.buyerToken || "")}</div>
                  </td>
                  <td>${escapeHtml(tx.item || tx.description || "Export Contract")}</td>
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

  // Restore search input focus smoothly if it was active
  if (isSearchFocused) {
    const searchInput = document.getElementById("tx-search");
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

  // Export CSV Ledger
  document.getElementById("tx-export-csv-btn")?.addEventListener("click", () => {
    exportTransactionsCsv(filtered.length ? filtered : txs);
  });

  // Refresh Ledger
  document.getElementById("tx-refresh-btn")?.addEventListener("click", async () => {
    const btn = document.getElementById("tx-refresh-btn");
    if (btn) btn.disabled = true;
    try {
      const res = await api.getTransactions();
      store.setState({
        transactions: res.transactions || [],
        transactionTotals: res.totals || null,
        cfoInsights: res.cfoInsights || null,
      });
      if (store.getState().route === "transactions") {
        renderTransactionsPage(mount);
      }
      showToast({ title: "Transactions Synced", message: `${res.transactions?.length || 0} records updated.`, type: "success" });
    } catch (err) {
      showToast({ title: "Sync Error", message: err.message, type: "error" });
      if (btn) btn.disabled = false;
    }
  });

  // Modal inspection dialog
  const openTxDetail = (tx) => {
    openModal({
      title: `Transaction ${tx.id}`,
      bodyHtml: `
        <div class="invoice-sheet">
          <div class="invoice-sheet-head">
            <div>
              <span class="badge ${getStatusBadgeClass(tx.status)}" style="margin-bottom:6px;">${escapeHtml(tx.status)}</span>
              <h3>${escapeHtml(tx.buyerName || "Overseas Buyer")}</h3>
              <p class="text-sm text-muted">Token: <code>${escapeHtml(tx.buyerToken || "—")}</code></p>
            </div>
            <div class="invoice-total-amount">${formatCurrency(tx.grossAmount || tx.amount, tx.currency)}</div>
          </div>
          <div class="kv-grid">
            <div class="kv-item"><div class="kv-label">Associated Invoice</div><div class="kv-val" style="font-family:var(--font-mono);">${escapeHtml(tx.invoiceId || "N/A")}</div></div>
            <div class="kv-item"><div class="kv-label">Timestamp</div><div class="kv-val">${formatDateTime(tx.date)}</div></div>
            <div class="kv-item"><div class="kv-label">PayPal Fee</div><div class="kv-val">${formatCurrency(tx.fee || 0, tx.currency)}</div></div>
            <div class="kv-item"><div class="kv-label">Net Settlement</div><div class="kv-val" style="color:var(--color-success);">${formatCurrency(tx.netAmount || 0, tx.currency)}</div></div>
          </div>
          <div class="kv-item" style="margin-block-start:0.5rem;">
            <div class="kv-label">Service / Export Line Item</div>
            <div class="kv-val">${escapeHtml(tx.item || tx.description || "N/A")}</div>
          </div>
        </div>
      `,
      footerHtml: `
        <button type="button" class="btn btn-secondary" id="tx-modal-copy-id">Copy TX ID</button>
        ${
          tx.invoiceId
            ? `<button type="button" class="btn btn-secondary" id="tx-modal-view-inv">View Invoice</button>`
            : ""
        }
        <button type="button" class="btn btn-primary" id="tx-modal-close">Close</button>
      `,
      onMount: () => {
        document.getElementById("tx-modal-close")?.addEventListener("click", closeModal);
        document.getElementById("tx-modal-copy-id")?.addEventListener("click", async () => {
          try {
            await navigator.clipboard.writeText(tx.id);
            showToast({ title: "Copied", message: `TX ID ${tx.id} copied to clipboard.`, type: "success" });
          } catch {
            showToast({ title: "Copy", message: tx.id, type: "info" });
          }
        });
        document.getElementById("tx-modal-view-inv")?.addEventListener("click", () => {
          closeModal();
          navigateTo("invoices");
        });
      },
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
