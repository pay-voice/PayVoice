/**
 * Page 1: Overview Dashboard
 * Comprehensive cross-border merchant command center backed by deterministic Node.js metrics.
 */

import { api } from "../api.js";
import { store } from "../store.js";
import { navigateTo } from "../router.js";
import {
  escapeHtml,
  formatCurrency,
  formatDate,
  formatDateTime,
  truncateHash,
  getStatusBadgeClass,
  renderAreaBarChartSvg,
  renderDonutChartSvg,
  showToast,
} from "../utils.js";

export function renderOverviewPage(mount) {
  const state = store.getState();
  const txs = state.transactions || [];
  const cfo = state.cfoInsights;
  const totals = state.transactionTotals;
  const invoices = state.invoices || [];
  const ledger = state.auditLedger || [];
  const isConfigured = state.config?.isConfigured;

  // Deterministic derived counts from backend data
  const paidInvoicesCount =
    invoices.filter((i) => i.status === "PAID").length +
    txs.filter((t) => t.status === "COMPLETED" || t.status === "PAID").length;
  const pendingInvoices = invoices.filter((i) => i.status === "SENT" || i.status === "DRAFT");
  const stagedCount = state.currentStaged ? 1 : 0;
  const outstandingAmount = pendingInvoices.reduce((acc, inv) => acc + Number(inv.amount || 0), 0);
  const refundTxs = txs.filter((t) => t.type === "REFUND" || t.status === "REFUNDED" || Number(t.grossAmount || t.amount || 0) < 0);
  const totalRefundAmount = refundTxs.reduce((acc, t) => acc + Math.abs(Number(t.grossAmount || t.amount || 0)), 0);

  // Chart 1: Revenue by transaction (ordered chronologically)
  const chartPoints = [...txs]
    .sort((a, b) => new Date(a.date) - new Date(b.date))
    .map((tx) => ({
      label: formatDate(tx.date).replace(/\s20\d\d/, ""),
      value: Number(tx.grossAmount || tx.amount || 0),
    }));

  // Chart 2: Currency distribution from backend cfoInsights
  const currencyMap = cfo?.inflowsByCurrency || {};
  const currencySegments = Object.entries(currencyMap).map(([curr, val]) => ({
    label: curr,
    value: Number(val || 0),
  }));

  // Chart 3: Invoice lifecycle distribution
  const lifecycleCounts = [
    { label: "Paid / Settled", value: paidInvoicesCount, color: "var(--color-success)" },
    { label: "Sent (Unpaid)", value: pendingInvoices.length, color: "var(--color-info)" },
    { label: "Staged (Pending Auth)", value: stagedCount, color: "var(--color-warning)" },
  ];

  // Security alerts / abnormal activity
  const blockedEvents = ledger.filter((r) =>
    ["FIREWALL_BLOCKED", "POLICY_VIOLATION", "WEBAUTHN_REJECTED", "BLOCKED_ATTACK", "BLOCKED_UNVERIFIED_TOOL_CALL", "BLOCKED_AUDIO_REPLAY"].includes(
      r.status
    )
  );

  mount.innerHTML = `
    <div class="page-header">
      <div class="page-header-copy">
        <h1>Merchant Overview</h1>
        <p>Cross-border PayPal OPGSP analytics, voice operations & cryptographic audit status</p>
      </div>
      <div class="page-header-actions">
        <button type="button" class="btn btn-secondary" id="ov-refresh-btn">Refresh Data</button>
        <button type="button" class="btn btn-primary" id="ov-voice-btn">New Voice Invoice</button>
      </div>
    </div>

    ${
      !isConfigured
        ? `
      <div class="alert alert-info" role="status">
        <div class="alert-content">
          <span class="alert-title">Sandbox Demonstration Dataset Active</span>
          <span>PayPal Sandbox OAuth keys are running in local demonstration mode. Transactions shown below reflect verified deterministic backend sandbox records plus live invoices executed in this session.</span>
        </div>
      </div>`
        : ""
    }

    <section aria-label="Key Financial Metrics" class="kpi-grid">
      <div class="metric-card">
        <div class="metric-header">
          <span class="metric-label">Total Gross Revenue (USD Eq.)</span>
          <span class="badge badge-info">OPGSP</span>
        </div>
        <div class="metric-value tabular-nums">${cfo ? `$${Number(cfo.totalGrossUsd).toLocaleString("en-US", { minimumFractionDigits: 2 })}` : "—"}</div>
        <div class="metric-foot">
          <span>Net INR Realization:</span>
          <strong style="color:var(--color-success);">${escapeHtml(cfo?.formattedInrRealization || "—")}</strong>
        </div>
      </div>

      <div class="metric-card">
        <div class="metric-header">
          <span class="metric-label">Total Transactions</span>
          <span class="badge badge-neutral">${txs.length} Records</span>
        </div>
        <div class="metric-value tabular-nums">${txs.length}</div>
        <div class="metric-foot">
          <span>Paid Invoices:</span>
          <strong>${paidInvoicesCount} Settled</strong>
        </div>
      </div>

      <div class="metric-card">
        <div class="metric-header">
          <span class="metric-label">Pending & Outstanding</span>
          <span class="badge ${pendingInvoices.length > 0 ? "badge-warning" : "badge-success"}">${pendingInvoices.length} Unpaid</span>
        </div>
        <div class="metric-value tabular-nums">${formatCurrency(outstandingAmount, "USD")}</div>
        <div class="metric-foot">
          <span>${stagedCount > 0 ? `${stagedCount} staged awaiting passkey` : "All staged invoices processed"}</span>
        </div>
      </div>

      <div class="metric-card">
        <div class="metric-header">
          <span class="metric-label">Refunds & Anomalies</span>
          <span class="badge ${refundTxs.length > 0 ? "badge-warning" : "badge-success"}">${refundTxs.length === 0 ? "0.0% Rate" : `${refundTxs.length} Refund(s)`}</span>
        </div>
        <div class="metric-value tabular-nums">${formatCurrency(totalRefundAmount, "USD")}</div>
        <div class="metric-foot">
          <span>OPGSP Cap Headroom:</span>
          <strong>${cfo?.opgspLimit ? `$${Number(cfo.opgspLimit.remainingAllowanceUsd).toFixed(2)}` : "$2,500.00"}</strong>
        </div>
      </div>
    </section>

    <div class="grid-12-7-5">
      <div class="card">
        <div class="card-header">
          <div>
            <h2 class="card-title">Export Revenue Trend</h2>
            <div class="card-subtitle">Verified gross inflows across recent cross-border settlements</div>
          </div>
          <button type="button" class="btn btn-ghost btn-sm" id="ov-to-moneyguide">Deep Analysis &rarr;</button>
        </div>
        ${renderAreaBarChartSvg(chartPoints)}
      </div>

      <div class="card">
        <div class="card-header">
          <div>
            <h2 class="card-title">Currency & Lifecycle Split</h2>
            <div class="card-subtitle">Multi-currency OPGSP corridors & invoice states</div>
          </div>
        </div>
        <div class="donut-layout">
          ${renderDonutChartSvg(currencySegments, {
            centerLabel: `${Object.keys(currencyMap).length || 0}`,
            centerSub: "Currencies",
          })}
          <div class="donut-list">
            ${
              currencySegments.length
                ? currencySegments
                    .map(
                      (s, idx) => `
                  <div class="donut-row">
                    <span class="legend-item">
                      <span class="legend-swatch" style="background:var(--color-chart-${(idx % 5) + 1});"></span>
                      <span>${escapeHtml(s.label)}</span>
                    </span>
                    <strong class="tabular-nums">${formatCurrency(s.value, s.label)}</strong>
                  </div>`
                    )
                    .join("")
                : `<p class="text-sm text-muted">No currency inflows recorded.</p>`
            }
            <hr style="border:none;border-top:1px solid var(--color-border-subtle);margin:4px 0;" />
            ${lifecycleCounts
              .map(
                (lc) => `
              <div class="donut-row">
                <span style="color:var(--color-text-secondary);">${escapeHtml(lc.label)}</span>
                <strong class="tabular-nums">${lc.value}</strong>
              </div>`
              )
              .join("")}
          </div>
        </div>
      </div>
    </div>

    <div class="grid-12-7-5">
      <div class="card">
        <div class="card-header">
          <div>
            <h2 class="card-title">Recent Transactions</h2>
            <div class="card-subtitle">PayPal cross-border export settlements</div>
          </div>
          <button type="button" class="btn btn-ghost btn-sm" id="ov-to-tx">View All &rarr;</button>
        </div>
        ${
          txs.length
            ? `
          <div class="table-responsive" tabindex="0" role="region" aria-label="Export activity table">
            <table>
              <thead>
                <tr>
                  <th>Transaction / Invoice</th>
                  <th>Buyer</th>
                  <th>Status</th>
                  <th style="text-align:right;">Gross</th>
                </tr>
              </thead>
              <tbody>
                ${txs
                  .slice(0, 5)
                  .map(
                    (tx) => `
                  <tr>
                    <td>
                      <div style="font-weight:600;">${escapeHtml(tx.item)}</div>
                      <div class="text-xs-mono text-muted">${escapeHtml(tx.id)}</div>
                    </td>
                    <td>
                      <div>${escapeHtml(tx.buyerName || tx.buyerToken)}</div>
                      <div class="text-xs text-muted">${formatDate(tx.date)}</div>
                    </td>
                    <td><span class="badge ${getStatusBadgeClass(tx.status)}">${escapeHtml(tx.status)}</span></td>
                    <td style="text-align:right;font-weight:700;" class="tabular-nums">${formatCurrency(tx.grossAmount || tx.amount, tx.currency)}</td>
                  </tr>`
                  )
                  .join("")}
              </tbody>
            </table>
          </div>`
            : `<div class="empty-state"><p>No transactions found.</p></div>`
        }
      </div>

      <div class="card">
        <div class="card-header">
          <div>
            <h2 class="card-title">Money Guide AI & Security Feed</h2>
            <div class="card-subtitle">Deterministic compliance & audit trail alerts</div>
          </div>
          <button type="button" class="btn btn-ghost btn-sm" id="ov-to-security">Audit Console &rarr;</button>
        </div>

        <div class="kv-grid">
          <div class="kv-item">
            <div class="kv-label">PayPal Effective Fee</div>
            <div class="kv-val tabular-nums">${cfo ? `${cfo.effectiveFeeRatePercent}% ($${cfo.totalEstimatedFeesUsd.toFixed(2)})` : "4.4% + $0.30"}</div>
          </div>
          <div class="kv-item">
            <div class="kv-label">Guardrail Events</div>
            <div class="kv-val">${blockedEvents.length} Blocked &bull; ${ledger.length} Total Entries</div>
          </div>
        </div>

        ${
          state.merchantInsights?.recommendation
            ? `<div class="alert alert-info">
                <div class="alert-content">
                  <span class="alert-title">Money Guide Recommendation</span>
                  <span>${escapeHtml(state.merchantInsights.recommendation)}</span>
                </div>
              </div>`
            : ""
        }

        <div style="display:flex;flex-direction:column;gap:8px;">
          ${ledger
            .slice(-4)
            .reverse()
            .map(
              (row) => `
            <div class="policy-check-row">
              <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;min-width:0;">
                <span class="badge ${getStatusBadgeClass(row.status)}">${escapeHtml(row.status)}</span>
                <span style="color:var(--color-text-secondary);">${escapeHtml(row.invoiceId && row.invoiceId !== "N/A" ? row.invoiceId : `Block #${row.index}`)}</span>
              </div>
              <span class="text-xs-mono text-muted" style="white-space:nowrap;">${escapeHtml(truncateHash(row.rowHash, 10))} &bull; ${formatDateTime(row.timestamp)}</span>
            </div>`
            )
            .join("")}
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <div>
          <h2 class="card-title">Recent Session Invoices</h2>
          <div class="card-subtitle">Live invoices staged or dispatched during this session via @paypal/agent-toolkit</div>
        </div>
        <button type="button" class="btn btn-secondary btn-sm" id="ov-to-invoices">Manage Invoices</button>
      </div>
      ${
        invoices.length
          ? `
        <div class="table-responsive" tabindex="0" role="region" aria-label="Export activity table">
          <table>
            <thead>
              <tr>
                <th>Invoice ID</th>
                <th>Buyer</th>
                <th>Deliverable</th>
                <th>Status</th>
                <th style="text-align:right;">Amount</th>
              </tr>
            </thead>
            <tbody>
              ${invoices
                .slice(0, 5)
                .map(
                  (inv) => `
                <tr>
                  <td class="text-xs-mono">${escapeHtml(inv.invoiceId)}</td>
                  <td>${escapeHtml(inv.buyerName)} <small>(${escapeHtml(inv.buyerToken)})</small></td>
                  <td>${escapeHtml(inv.item)}</td>
                  <td><span class="badge ${getStatusBadgeClass(inv.status)}">${escapeHtml(inv.status)}</span></td>
                  <td style="text-align:right;font-weight:700;" class="tabular-nums">${formatCurrency(inv.amount, inv.currency)}</td>
                </tr>`
                )
                .join("")}
            </tbody>
          </table>
        </div>`
          : `
        <div class="empty-state" style="padding:24px 16px;">
          <p>No live session invoices dispatched yet. Use the Voice Assistant to create, validate, and authorize an invoice with your passkey.</p>
          <button type="button" class="btn btn-primary btn-sm" id="ov-empty-voice-btn">Launch Voice Assistant</button>
        </div>`
      }
    </div>
  `;

  document.getElementById("ov-voice-btn")?.addEventListener("click", () => navigateTo("voice"));
  document.getElementById("ov-empty-voice-btn")?.addEventListener("click", () => navigateTo("voice"));
  document.getElementById("ov-to-moneyguide")?.addEventListener("click", () => navigateTo("money-guide"));
  document.getElementById("ov-to-tx")?.addEventListener("click", () => navigateTo("transactions"));
  document.getElementById("ov-to-security")?.addEventListener("click", () => navigateTo("security"));
  document.getElementById("ov-to-invoices")?.addEventListener("click", () => navigateTo("invoices"));
  document.getElementById("ov-refresh-btn")?.addEventListener("click", async () => {
    const btn = document.getElementById("ov-refresh-btn");
    btn.disabled = true;
    btn.textContent = "Refreshing...";
    try {
      const [txRes, invRes, ledgerRes, insRes] = await Promise.all([
        fetch("/api/transactions").then((r) => r.json()),
        fetch("/api/invoices").then((r) => r.json()),
        fetch("/api/audit-ledger").then((r) => r.json()),
        fetch("/api/transactions/insights").then((r) => r.json()),
      ]);
      store.setState({
        transactions: txRes.transactions || [],
        transactionTotals: txRes.totals || null,
        cfoInsights: txRes.cfoInsights || null,
        invoices: invRes.invoices || [],
        auditLedger: ledgerRes.ledger || [],
        merchantInsights: insRes.insights || null,
      });
      renderOverviewPage(mount);
      showToast({ title: "Dashboard Synced", message: "Latest backend metrics loaded.", type: "success" });
    } catch (err) {
      showToast({ title: "Sync Failed", message: err.message, type: "error" });
      btn.disabled = false;
      btn.textContent = "Refresh Data";
    }
  });
}
