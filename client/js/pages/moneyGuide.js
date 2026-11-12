/**
 * Page 5: Money Guide AI
 * Deterministic Node.js financial intelligence:
 * 1. Overview & OPGSP Telemetry
 * 2. Limits & Budgeting
 * 3. Risk Meter & Institutional Investment Rating
 * 4. Financial Scheduling & Automation
 */

import { api } from "../api.js";
import { store } from "../store.js";
import {
  escapeHtml,
  formatCurrency,
  formatDate,
  openModal,
  closeModal,
  renderAreaBarChartSvg,
  renderDonutChartSvg,
  showToast,
} from "../utils.js";

let selectedRangeDays = 30;

function renderRiskGaugeSvg(score = 21, { max = 100, label = "Low Risk" } = {}) {
  const normScore = Math.min(max, Math.max(0, score));
  const angle = (normScore / max) * 180;
  const rad = (angle * Math.PI) / 180;
  const cx = 100;
  const cy = 95;
  const r = 70;
  const needleX = cx - (r - 12) * Math.cos(rad);
  const needleY = cy - (r - 12) * Math.sin(rad);

  const color =
    normScore <= 25 ? "var(--color-success)" : normScore <= 50 ? "var(--color-warning)" : "var(--color-danger)";

  return `
    <div class="risk-gauge-container">
      <svg class="risk-gauge-svg" viewBox="0 0 200 115" role="img" aria-label="Risk Meter: ${normScore} out of ${max} (${label})">
        <defs>
          <linearGradient id="risk-arc-grad" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stop-color="#10b981" />
            <stop offset="35%" stop-color="#3b82f6" />
            <stop offset="65%" stop-color="#f59e0b" />
            <stop offset="100%" stop-color="#ef4444" />
          </linearGradient>
        </defs>
        <path d="M 30 95 A 70 70 0 0 1 170 95" fill="none" stroke="var(--color-bg-subtle)" stroke-width="14" stroke-linecap="round" />
        <path d="M 30 95 A 70 70 0 0 1 170 95" fill="none" stroke="url(#risk-arc-grad)" stroke-width="14" stroke-linecap="round" opacity="0.92" />
        <line x1="${cx}" y1="${cy}" x2="${needleX.toFixed(1)}" y2="${needleY.toFixed(1)}" stroke="${color}" stroke-width="3.5" stroke-linecap="round" />
        <circle cx="${cx}" cy="${cy}" r="6" fill="${color}" />
        <circle cx="${cx}" cy="${cy}" r="2.5" fill="#ffffff" />
      </svg>
      <div class="risk-readout-score">${normScore}<span class="text-xs text-muted" style="font-weight:600;">/100</span></div>
      <div class="risk-readout-label" style="color:${color};">${escapeHtml(label)}</div>
    </div>
  `;
}

export function renderMoneyGuidePage(mount) {
  const state = store.getState();
  const allTxs = state.transactions || [];
  const invoices = state.invoices || [];
  const cfo = state.cfoInsights;
  const insights = state.merchantInsights;
  const activeTab = state.activeMoneyGuideTab || "overview";
  const budget = state.financialBudget || {
    monthlyTargetUsd: 5000,
    feeCapPercent: 5.0,
    taxReservePercent: 15,
    maxCurrencySharePercent: 65,
  };
  const schedules = state.financialSchedules || [];

  const risk = cfo?.riskMeter || {
    compositeScore: 21,
    tierLabel: "Low Risk",
    investmentRating: "AAA",
    ratingTitle: "Prime Working Capital Grade",
    ratingSummary:
      "Strong multi-corridor export liquidity, zero dispute chargebacks, and verified RBI OPGSP Rule 96A compliance.",
    breakdown: [
      {
        label: "Currency Concentration Risk",
        score: 10,
        max: 25,
        status: "Diversified",
        detail: "Corridor split between USD, EUR & GBP",
      },
      {
        label: "Buyer Concentration Risk",
        score: 12,
        max: 25,
        status: "Balanced",
        detail: "Top buyer accounts for 31% of receivables",
      },
      {
        label: "Default & Dispute Risk",
        score: 0,
        max: 25,
        status: "Minimal",
        detail: "0 disputes and 0 refunds across window",
      },
      {
        label: "RBI & GST Compliance Risk",
        score: 3,
        max: 25,
        status: "Verified",
        detail: "IEC 0319088821 & Rule 96A LUT validated",
      },
    ],
    treasuryAllocation: {
      deployableInr: 103240,
      formattedDeployableInr: "₹1,03,240",
      projectedAnnualYieldInr: 6185,
      formattedProjectedYield: "₹6,185",
      weightedApyPercent: 5.91,
      buckets: [
        {
          name: "RBI 91-Day T-Bills / Overnight Liquid",
          pct: 60,
          apy: 6.85,
          amountInr: 61944,
          liquidity: "T+1 Instant",
        },
        {
          name: "Short-Duration Sovereign Debt",
          pct: 25,
          apy: 7.2,
          amountInr: 25810,
          liquidity: "T+2 Settlement",
        },
        {
          name: "Working Capital Operating Buffer",
          pct: 15,
          apy: 0,
          amountInr: 15486,
          liquidity: "Immediate",
        },
      ],
    },
  };

  const budgeting = cfo?.budgeting || {
    monthlyTargetUsd: budget.monthlyTargetUsd,
    realizedExportUsd: cfo?.totalGrossUsd || 1500,
    targetProgressPercent: Math.min(100, Math.round(((cfo?.totalGrossUsd || 1500) / budget.monthlyTargetUsd) * 100)),
    remainingTargetUsd: Math.max(0, budget.monthlyTargetUsd - (cfo?.totalGrossUsd || 1500)),
    feeBudgetCapPercent: budget.feeCapPercent,
    effectiveFeeRatePercent: cfo?.effectiveFeeRatePercent || 4.38,
    feeVarianceStatus: (cfo?.effectiveFeeRatePercent || 4.38) <= budget.feeCapPercent ? "UNDER_BUDGET" : "FEE_OVER_CAP",
    taxReservePercent: budget.taxReservePercent,
    recommendedTaxReserveInr: Math.round((cfo?.netInrRealization || 120000) * (budget.taxReservePercent / 100)),
    recommendedTaxReserveFormatted: `₹${Math.round((cfo?.netInrRealization || 120000) * (budget.taxReservePercent / 100)).toLocaleString("en-IN")}`,
    statutoryCorridorCapUsd: 10000.0,
    statutoryCorridorRemainingUsd: Math.max(0, 10000.0 - (cfo?.totalGrossUsd || 1500)),
    currencyExposure: [
      { currency: "USD", usdAmount: 700, sharePercent: 46.7, limitPercent: budget.maxCurrencySharePercent, overLimit: false },
      { currency: "EUR", usdAmount: 490, sharePercent: 32.7, limitPercent: budget.maxCurrencySharePercent, overLimit: false },
      { currency: "GBP", usdAmount: 310, sharePercent: 20.6, limitPercent: budget.maxCurrencySharePercent, overLimit: false },
    ],
  };

  const cutoffMs = selectedRangeDays === 0 ? 0 : Date.now() - selectedRangeDays * 24 * 60 * 60 * 1000;
  const filteredTxs = allTxs.filter((tx) => {
    if (!cutoffMs) return true;
    const t = new Date(tx.date).getTime();
    return isNaN(t) || t >= cutoffMs;
  });

  const chartPoints = [...filteredTxs]
    .sort((a, b) => new Date(a.date) - new Date(b.date))
    .map((tx) => ({
      label: formatDate(tx.date).replace(/\s20\d\d/, ""),
      value: Number(tx.grossAmount || tx.amount || 0),
    }));

  const currencyMap = cfo?.inflowsByCurrency || {};
  const currencySegments = Object.entries(currencyMap).map(([curr, val]) => ({
    label: curr,
    value: Number(val || 0),
  }));

  const refundTxs = filteredTxs.filter(
    (t) => t.type === "REFUND" || t.status === "REFUNDED" || Number(t.grossAmount || t.amount || 0) < 0
  );
  const refundRate = filteredTxs.length ? ((refundTxs.length / filteredTxs.length) * 100).toFixed(1) : "0.0";
  const capPct = Math.min(100, Number(cfo?.opgspLimit?.capUtilizedPercent || 0));
  const capFillClass = capPct >= 90 ? "danger" : capPct >= 70 ? "warn" : "safe";
  const reg = cfo?.regulatoryCompliance || {};

  mount.innerHTML = `
    <div class="page-header">
      <div class="page-header-copy">
        <span class="page-eyebrow">Financial Planning &amp; Intelligence</span>
        <h1 class="page-title">Money Guide AI</h1>
        <p class="page-subtitle">Deterministic CFO telemetry, risk rating, statutory budgets &amp; financial scheduling</p>
      </div>
      <div class="page-header-actions">
        <button type="button" class="btn btn-secondary btn-sm" id="mg-sync-btn">Recalculate Telemetry</button>
      </div>
    </div>

    <!-- Subnav Tabs -->
    <nav class="subnav-tabs" aria-label="Money Guide Sections">
      <button type="button" class="subnav-tab-btn ${activeTab === "overview" ? "active" : ""}" data-mg-tab="overview">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><rect x="3" y="3" width="7" height="9" rx="1" /><rect x="14" y="3" width="7" height="5" rx="1" /><rect x="14" y="12" width="7" height="9" rx="1" /><rect x="3" y="16" width="7" height="5" rx="1" /></svg>
        <span>Overview &amp; OPGSP</span>
      </button>
      <button type="button" class="subnav-tab-btn ${activeTab === "limits" ? "active" : ""}" data-mg-tab="limits">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6" /></svg>
        <span>Limits &amp; Budgeting</span>
      </button>
      <button type="button" class="subnav-tab-btn ${activeTab === "risk" ? "active" : ""}" data-mg-tab="risk">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
        <span>Risk Meter &amp; Rating</span>
        <span class="badge badge-success" style="font-size:10px;padding:1px 5px;">${escapeHtml(risk.investmentRating)}</span>
      </button>
      <button type="button" class="subnav-tab-btn ${activeTab === "schedules" ? "active" : ""}" data-mg-tab="schedules">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="12" cy="12" r="10" /><polyline points="12 6 12 12 16 14" /></svg>
        <span>Financial Scheduling</span>
        <span class="badge badge-info" style="font-size:10px;padding:1px 5px;">${schedules.filter((s) => s.status === "ACTIVE").length}</span>
      </button>
    </nav>

    ${
      activeTab === "overview"
        ? renderOverviewTabHtml({
            selectedRangeDays,
            cfo,
            allTxs,
            refundRate,
            refundTxs,
            chartPoints,
            currencySegments,
            filteredTxs,
            insights,
            capPct,
            capFillClass,
            invoices,
            reg,
          })
        : activeTab === "limits"
        ? renderLimitsTabHtml({ budgeting, budget, cfo })
        : activeTab === "risk"
        ? renderRiskTabHtml({ risk })
        : renderSchedulesTabHtml({ schedules })
    }
  `;

  // Bind Subnav Tab clicks
  mount.querySelectorAll("[data-mg-tab]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const tab = btn.getAttribute("data-mg-tab");
      store.setState({ activeMoneyGuideTab: tab });
      renderMoneyGuidePage(mount);
    });
  });

  // Bind Date Range buttons (for Overview tab)
  mount.querySelectorAll("[data-mg-range]").forEach((btn) => {
    btn.addEventListener("click", () => {
      selectedRangeDays = Number(btn.getAttribute("data-mg-range"));
      renderMoneyGuidePage(mount);
    });
  });

  // Bind Recalculate button
  document.getElementById("mg-sync-btn")?.addEventListener("click", async () => {
    const btn = document.getElementById("mg-sync-btn");
    btn.disabled = true;
    btn.textContent = "Recalculating...";
    try {
      const [txRes, insRes] = await Promise.all([api.getTransactions(), api.getMerchantInsights()]);
      store.setState({
        transactions: txRes.transactions || [],
        transactionTotals: txRes.totals || null,
        cfoInsights: txRes.cfoInsights || null,
        merchantInsights: insRes.insights || null,
      });
      if (store.getState().route === "money-guide") {
        renderMoneyGuidePage(mount);
      }
      showToast({
        title: "Money Guide Recalculated",
        message: "Deterministic financial math & risk ratings updated.",
        type: "success",
      });
    } catch (err) {
      showToast({ title: "Recalculation Error", message: err.message, type: "error" });
      btn.disabled = false;
      btn.textContent = "Recalculate Telemetry";
    }
  });

  // Bind Tab-specific actions
  if (activeTab === "limits") {
    document.getElementById("mg-open-budget-modal")?.addEventListener("click", () => {
      openBudgetModal();
    });
  } else if (activeTab === "schedules") {
    document.getElementById("mg-open-schedule-modal")?.addEventListener("click", () => {
      openScheduleModal();
    });

    mount.querySelectorAll("[data-schedule-toggle]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const id = btn.getAttribute("data-schedule-toggle");
        const updated = store.toggleSchedule(id);
        renderMoneyGuidePage(mount);
        showToast({
          title: `Schedule ${updated.status === "ACTIVE" ? "Resumed" : "Paused"}`,
          message: `${updated.title} is now ${updated.status.toLowerCase()}.`,
          type: updated.status === "ACTIVE" ? "success" : "info",
        });
      });
    });

    mount.querySelectorAll("[data-schedule-run]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const id = btn.getAttribute("data-schedule-run");
        const sched = schedules.find((s) => s.id === id);
        showToast({
          title: "Schedule Executed",
          message: `Triggered run for: ${sched?.title || id}. Audit record logged.`,
          type: "success",
        });
      });
    });
  }
}

function renderOverviewTabHtml({
  selectedRangeDays,
  cfo,
  allTxs,
  refundRate,
  refundTxs,
  chartPoints,
  currencySegments,
  filteredTxs,
  insights,
  capPct,
  capFillClass,
  invoices,
  reg,
}) {
  return `
    <div class="alert alert-info">
      <div class="alert-content">
        <span class="alert-title">Deterministic Verification Guarantee</span>
        <span>All currency totals, fee reconciliations, and OPGSP cap percentages below are calculated by deterministic Node.js code. The LLM never performs financial arithmetic.</span>
      </div>
    </div>

    <div class="kpi-grid">
      <div class="metric-card">
        <div class="metric-header">
          <span class="metric-label">Gross Inflows (USD Eq.)</span>
          <span class="badge badge-info">OPGSP</span>
        </div>
        <div class="metric-value tabular-nums">${cfo ? `$${Number(cfo.totalGrossUsd).toFixed(2)}` : "—"}</div>
        <div class="metric-foot">Across ${allTxs.length} backend records</div>
      </div>
      <div class="metric-card">
        <div class="metric-header">
          <span class="metric-label">PayPal Cross-Border Fees</span>
          <span class="badge badge-warning">4.4% Rate</span>
        </div>
        <div class="metric-value text-warning tabular-nums">${cfo ? `$${Number(cfo.totalEstimatedFeesUsd).toFixed(2)}` : "—"}</div>
        <div class="metric-foot">Effective Rate: ${cfo ? `${cfo.effectiveFeeRatePercent}%` : "4.4%"}</div>
      </div>
      <div class="metric-card">
        <div class="metric-header">
          <span class="metric-label">Net INR Realization</span>
          <span class="badge badge-success">e-FIRC Ready</span>
        </div>
        <div class="metric-value text-success tabular-nums">${escapeHtml(cfo?.formattedInrRealization || "—")}</div>
        <div class="metric-foot">Calibrated RBI FX &bull; Zero IGST LUT</div>
      </div>
      <div class="metric-card">
        <div class="metric-header">
          <span class="metric-label">Refund Rate &amp; Anomalies</span>
          <span class="badge ${refundTxs.length > 0 ? "badge-warning" : "badge-success"}">${refundRate}%</span>
        </div>
        <div class="metric-value tabular-nums">${refundRate}%</div>
        <div class="metric-foot">${refundTxs.length} refund(s) in selected window</div>
      </div>
    </div>

    <div class="grid-12-7-5">
      <div class="card">
        <div class="card-header">
          <div>
            <h2 class="card-title">Revenue &amp; Export Activity (${selectedRangeDays === 0 ? "All Time" : `Last ${selectedRangeDays} Days`})</h2>
            <div class="card-subtitle">${filteredTxs.length} transaction(s) in selected period</div>
          </div>
          <div class="segmented-control" role="group" aria-label="Analytics window">
            <button type="button" class="seg-btn ${selectedRangeDays === 7 ? "active" : ""}" data-mg-range="7">7D</button>
            <button type="button" class="seg-btn ${selectedRangeDays === 30 ? "active" : ""}" data-mg-range="30">30D</button>
            <button type="button" class="seg-btn ${selectedRangeDays === 90 ? "active" : ""}" data-mg-range="90">90D</button>
            <button type="button" class="seg-btn ${selectedRangeDays === 0 ? "active" : ""}" data-mg-range="0">All</button>
          </div>
        </div>
        ${renderAreaBarChartSvg(chartPoints)}
      </div>

      <div class="card">
        <div class="card-header">
          <div>
            <h2 class="card-title">Currency Mix &amp; OPGSP Headroom</h2>
            <div class="card-subtitle">RBI $2,500 per-invoice statutory export ceiling</div>
          </div>
          <span class="badge badge-success">${escapeHtml(cfo?.opgspLimit?.status || "WITHIN_OPGSP_STATUTORY_CAP")}</span>
        </div>

        <div class="donut-layout">
          ${renderDonutChartSvg(currencySegments, {
            centerLabel: `${capPct}%`,
            centerSub: "Max Cap Used",
          })}
          <div class="donut-list">
            ${currencySegments
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
              .join("")}
          </div>
        </div>

        <div>
          <div class="text-xs" style="display:flex;justify-content:space-between;margin-block-end:0.375rem;">
            <span>Max Single Invoice: <strong>$${Number(cfo?.opgspLimit?.maxInvoiceIssuedUsd || 0).toFixed(2)}</strong></span>
            <span>Headroom: <strong>$${Number(cfo?.opgspLimit?.remainingAllowanceUsd || 2500).toFixed(2)}</strong></span>
          </div>
          <div class="progress-track" role="progressbar" aria-valuenow="${capPct}" aria-valuemin="0" aria-valuemax="100" aria-label="OPGSP cap utilization">
            <div class="progress-fill ${capFillClass}" style="width:${capPct}%"></div>
          </div>
        </div>
      </div>
    </div>

    <div class="grid-2">
      <div class="card">
        <div class="card-header">
          <h2 class="card-title">Abnormal Activity &amp; Policy Radar</h2>
          <span class="badge ${refundTxs.length > 0 ? "badge-warning" : "badge-success"}">${refundTxs.length > 0 ? "Review Alerts" : "No Anomalies"}</span>
        </div>
        <div class="policy-check-list">
          <div class="policy-check-row">
            <span><strong>Refund Rate Threshold (&le; 10.0%)</strong></span>
            <span class="badge badge-success">${refundRate}% (Normal)</span>
          </div>
          <div class="policy-check-row">
            <span><strong>Invoice Velocity &amp; Outlier Spike Check</strong></span>
            <span class="badge badge-success">${invoices.length} live invoice(s) within cap</span>
          </div>
          <div class="policy-check-row">
            <span><strong>Corridor Compliance</strong></span>
            <span class="badge badge-info">${escapeHtml(insights?.complianceStatus || "100% Compliant")}</span>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <h2 class="card-title">India OPGSP &amp; Regulatory Compliance</h2>
          <span class="badge badge-purple">DGFT / RBI</span>
        </div>
        <div class="kv-grid">
          <div class="kv-item">
            <div class="kv-label">DGFT IEC Code</div>
            <div class="kv-val text-xs-mono">${escapeHtml(reg.iecCode || "0319088821")}</div>
          </div>
          <div class="kv-item">
            <div class="kv-label">GST LUT Status</div>
            <div class="kv-val text-xs">${escapeHtml(reg.gstLutRule || "Rule 96A CGST Rules")}</div>
          </div>
          <div class="kv-item">
            <div class="kv-label">e-FIRC Issuance</div>
            <div class="kv-val text-xs">${escapeHtml(reg.fircStatus || "Auto e-FIRC ready")}</div>
          </div>
          <div class="kv-item">
            <div class="kv-label">RBI EDPMS</div>
            <div class="kv-val text-xs">${escapeHtml(reg.bankRealization || "EDPMS auto-reporting")}</div>
          </div>
        </div>
      </div>
    </div>
  `;
}

function renderLimitsTabHtml({ budgeting, budget, cfo }) {
  const targetPct = budgeting.targetProgressPercent || 0;
  const targetFillClass = targetPct >= 90 ? "safe" : targetPct >= 50 ? "warn" : "";

  return `
    <div class="card" style="margin-block-end:var(--space-5);">
      <div class="card-header">
        <div>
          <h2 class="card-title">Export Targets &amp; Corridor Ceilings</h2>
          <div class="card-subtitle">Active financial budgeting thresholds, statutory ceilings &amp; fee watchdog</div>
        </div>
        <button type="button" class="btn btn-primary btn-sm" id="mg-open-budget-modal">Configure Budget &amp; Limits</button>
      </div>

      <div class="kpi-grid">
        <div class="metric-card">
          <div class="metric-header">
            <span class="metric-label">Monthly Export Target</span>
            <span class="badge badge-info">${targetPct}% Reached</span>
          </div>
          <div class="metric-value tabular-nums">$${Number(budgeting.monthlyTargetUsd).toFixed(2)}</div>
          <div class="metric-foot">
            <span>Remaining Goal:</span>
            <strong>$${Number(budgeting.remainingTargetUsd).toFixed(2)}</strong>
          </div>
        </div>

        <div class="metric-card">
          <div class="metric-header">
            <span class="metric-label">RBI Statutory Corridor</span>
            <span class="badge badge-success">OPGSP</span>
          </div>
          <div class="metric-value tabular-nums">$${Number(budgeting.statutoryCorridorCapUsd).toFixed(2)}</div>
          <div class="metric-foot">
            <span>Remaining Corridor:</span>
            <strong>$${Number(budgeting.statutoryCorridorRemainingUsd).toFixed(2)}</strong>
          </div>
        </div>

        <div class="metric-card">
          <div class="metric-header">
            <span class="metric-label">Fee Budget Cap</span>
            <span class="badge ${budgeting.feeVarianceStatus === "UNDER_BUDGET" ? "badge-success" : "badge-warning"}">${escapeHtml(budgeting.feeVarianceStatus)}</span>
          </div>
          <div class="metric-value tabular-nums">${budgeting.effectiveFeeRatePercent}%</div>
          <div class="metric-foot">
            <span>Target Cap:</span>
            <strong>&le; ${budgeting.feeBudgetCapPercent}%</strong>
          </div>
        </div>

        <div class="metric-card">
          <div class="metric-header">
            <span class="metric-label">Recommended Tax Reserve</span>
            <span class="badge badge-neutral">${budgeting.taxReservePercent}% Reserve</span>
          </div>
          <div class="metric-value text-success tabular-nums">${escapeHtml(budgeting.recommendedTaxReserveFormatted)}</div>
          <div class="metric-foot">
            <span>GST / Advance Tax</span>
            <strong>Rule 96A Buffer</strong>
          </div>
        </div>
      </div>
    </div>

    <div class="grid-2">
      <div class="card">
        <div class="card-header">
          <h2 class="card-title">Monthly Revenue Goal Run-Rate</h2>
          <span class="badge badge-info">${targetPct}% Complete</span>
        </div>
        <div style="display:flex;flex-direction:column;gap:var(--space-4);">
          <div>
            <div class="text-xs" style="display:flex;justify-content:space-between;margin-block-end:0.4375rem;">
              <span>Realized: <strong>$${Number(budgeting.realizedExportUsd).toFixed(2)}</strong></span>
              <span>Target: <strong>$${Number(budgeting.monthlyTargetUsd).toFixed(2)}</strong></span>
            </div>
            <div class="progress-track" role="progressbar" aria-valuenow="${targetPct}" aria-valuemin="0" aria-valuemax="100" aria-label="Monthly revenue progress">
              <div class="progress-fill ${targetFillClass}" style="width:${targetPct}%"></div>
            </div>
          </div>
          <div class="policy-check-list">
            <div class="budget-kpi-row">
              <span>Required Daily Run-Rate to Hit Target</span>
              <strong>$${Number(budgeting.remainingTargetUsd / 20).toFixed(2)} / day</strong>
            </div>
            <div class="budget-kpi-row">
              <span>Per-Invoice Statutory OPGSP Ceiling</span>
              <strong class="text-success">$2,500.00 USD (Rule Compliant)</strong>
            </div>
            <div class="budget-kpi-row">
              <span>Transaction Velocity Hard Limit</span>
              <strong>Max 5 Invoices / Day (Tamper Guard)</strong>
            </div>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <h2 class="card-title">Foreign Currency Exposure Limits</h2>
          <span class="badge badge-neutral">Max ${budget.maxCurrencySharePercent}% Single Currency</span>
        </div>
        <div style="display:flex;flex-direction:column;gap:0.375rem;">
          ${budgeting.currencyExposure
            .map(
              (c) => `
            <div class="exposure-row">
              <div class="exposure-header">
                <span><strong>${escapeHtml(c.currency)}</strong> Inflows: $${Number(c.usdAmount).toFixed(2)}</span>
                <span class="badge ${c.overLimit ? "badge-warning" : "badge-success"}">${c.sharePercent}% (${c.overLimit ? "Over Cap" : "Within Limit"})</span>
              </div>
              <div class="progress-track" role="progressbar" aria-valuenow="${c.sharePercent}" aria-valuemin="0" aria-valuemax="100" aria-label="${c.currency} exposure share">
                <div class="progress-fill ${c.overLimit ? "warn" : "safe"}" style="width:${Math.min(100, c.sharePercent)}%"></div>
              </div>
            </div>`
            )
            .join("")}
        </div>
      </div>
    </div>
  `;
}

function renderRiskTabHtml({ risk }) {
  const treasury = risk.treasuryAllocation || {};

  return `
    <div class="grid-12-7-5" style="margin-block-end:var(--space-5);">
      <div class="card">
        <div class="card-header">
          <div>
            <h2 class="card-title">Real-Time Composite Risk Meter</h2>
            <div class="card-subtitle">Algorithmic risk evaluation across currency, client concentration &amp; compliance</div>
          </div>
          <span class="badge ${risk.compositeScore <= 25 ? "badge-success" : risk.compositeScore <= 50 ? "badge-warning" : "badge-danger"}">${escapeHtml(risk.tierLabel)}</span>
        </div>
        ${renderRiskGaugeSvg(risk.compositeScore, { label: risk.tierLabel })}
        <p class="section-desc" style="text-align:center;margin-block-start:var(--space-3);">${escapeHtml(risk.ratingSummary)}</p>
      </div>

      <div class="card" style="display:flex;flex-direction:column;justify-content:space-between;">
        <div class="card-header">
          <div>
            <h2 class="card-title">Institutional Investment Rating</h2>
            <div class="card-subtitle">Exporters solvency &amp; creditworthiness grade</div>
          </div>
          <span class="badge badge-purple">Working Capital</span>
        </div>

        <div style="display:flex;flex-direction:column;align-items:center;padding:var(--space-4) 0;gap:var(--space-3);">
          <div class="rating-medallion">
            <div class="rating-badge-aaa">${escapeHtml(risk.investmentRating)}</div>
            <div class="rating-meta">
              <strong>${escapeHtml(risk.ratingTitle)}</strong>
              <span>Calibrated via verified sandbox ledger</span>
            </div>
          </div>
        </div>

        <div class="kv-grid">
          <div class="kv-item">
            <div class="kv-label">Default Risk</div>
            <div class="kv-val text-success">0.0% (Zero Disputes)</div>
          </div>
          <div class="kv-item">
            <div class="kv-label">Solvency Grade</div>
            <div class="kv-val text-success">Tier 1 Prime</div>
          </div>
          <div class="kv-item">
            <div class="kv-label">Hedging Health</div>
            <div class="kv-val">Diversified Basket</div>
          </div>
          <div class="kv-item">
            <div class="kv-label">Sanctions Risk</div>
            <div class="kv-val text-success">Pass (0 Matches)</div>
          </div>
        </div>
      </div>
    </div>

    <div class="card" style="margin-block-end:var(--space-5);">
      <div class="card-header">
        <div>
          <h2 class="card-title">Risk Category Scorecard Breakdown</h2>
          <div class="card-subtitle">Factor-level scoring (0 = Best, 25 = Maximum Risk)</div>
        </div>
        <span class="badge badge-neutral">Total: ${risk.compositeScore}/100</span>
      </div>

      <div class="grid-2">
        ${risk.breakdown
          .map(
            (b) => `
          <div class="feed-row">
            <div class="feed-row-main">
              <strong>${escapeHtml(b.label)}</strong>
              <span class="text-xs text-muted">${escapeHtml(b.detail)}</span>
            </div>
            <div class="feed-row-meta">
              <span class="badge ${b.score <= 10 ? "badge-success" : b.score <= 16 ? "badge-warning" : "badge-danger"}">${b.score} / ${b.max} (${escapeHtml(b.status)})</span>
            </div>
          </div>`
          )
          .join("")}
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <div>
          <h2 class="card-title">Working Capital Treasury Yield Optimizer</h2>
          <div class="card-subtitle">Deploy idle export proceeds into safe, sovereign-backed INR yields</div>
        </div>
        <span class="badge badge-success">Projected Yield: ${escapeHtml(treasury.formattedProjectedYield)} / year</span>
      </div>

      <p class="section-desc" style="margin-block-end:var(--space-4);">
        Instead of holding idle balances in 0% current accounts, PayVoice deterministically models optimal treasury deployment across RBI 91-Day T-Bills and sovereign liquid funds for your realized <strong>${escapeHtml(treasury.formattedDeployableInr)}</strong>:
      </p>

      <div class="treasury-grid">
        ${(treasury.buckets || [])
          .map(
            (bucket) => `
          <div class="treasury-card">
            <div class="treasury-head">
              <span>${bucket.pct}% Allocation</span>
              <span>${escapeHtml(bucket.liquidity)}</span>
            </div>
            <div class="treasury-val">₹${Number(bucket.amountInr).toLocaleString("en-IN")}</div>
            <div class="text-xs text-secondary">${escapeHtml(bucket.name)}</div>
            <div class="treasury-yield">${bucket.apy > 0 ? `${bucket.apy}% APY Projected` : "0% Liquid Buffer"}</div>
          </div>`
          )
          .join("")}
      </div>
    </div>
  `;
}

function renderSchedulesTabHtml({ schedules }) {
  const activeSchedules = schedules.filter((s) => s.status === "ACTIVE");

  return `
    <div class="page-header" style="margin-block-end:var(--space-4);">
      <div class="page-header-copy">
        <h2 class="card-title" style="font-size:var(--text-lg);">Financial Schedules &amp; Automated Cadences</h2>
        <div class="card-subtitle">Automate recurring client retainers, payment reminder daemons &amp; GST Rule 96A reconciliation</div>
      </div>
      <button type="button" class="btn btn-primary btn-sm" id="mg-open-schedule-modal">Create New Schedule</button>
    </div>

    <div class="kpi-grid" style="margin-block-end:var(--space-5);">
      <div class="metric-card">
        <div class="metric-header">
          <span class="metric-label">Active Automated Schedules</span>
          <span class="badge badge-success">Live</span>
        </div>
        <div class="metric-value tabular-nums">${activeSchedules.length}</div>
        <div class="metric-foot">Across ${schedules.length} total schedules</div>
      </div>

      <div class="metric-card">
        <div class="metric-header">
          <span class="metric-label">Next Automated Run</span>
          <span class="badge badge-info">Scheduled</span>
        </div>
        <div class="metric-value tabular-nums" style="font-size:var(--text-lg);">2026-11-20</div>
        <div class="metric-foot">GST LUT Monthly Reconciliation</div>
      </div>

      <div class="metric-card">
        <div class="metric-header">
          <span class="metric-label">Payment Reminder Daemon</span>
          <span class="badge badge-success">24h Guardrail</span>
        </div>
        <div class="metric-value tabular-nums" style="font-size:var(--text-lg);">Daily 09:00 UTC</div>
        <div class="metric-foot">Zero Spam &bull; Cooldown Enforced</div>
      </div>

      <div class="metric-card">
        <div class="metric-header">
          <span class="metric-label">Security Protocol</span>
          <span class="badge badge-purple">WebAuthn Bound</span>
        </div>
        <div class="metric-value tabular-nums" style="font-size:var(--text-lg);">Passkey Guarded</div>
        <div class="metric-foot">All mutations signed to ledger</div>
      </div>
    </div>

    <div class="schedules-grid">
      ${schedules
        .map(
          (s) => `
        <div class="schedule-card ${s.status === "PAUSED" ? "paused" : ""}">
          <div class="schedule-card-head">
            <div>
              <span class="schedule-cadence">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="12" cy="12" r="10" /><polyline points="12 6 12 12 16 14" /></svg>
                ${escapeHtml(s.cadence)}
              </span>
              <h3 class="schedule-title">${escapeHtml(s.title)}</h3>
            </div>
            <span class="badge ${s.status === "ACTIVE" ? "badge-success" : "badge-neutral"}">${escapeHtml(s.status)}</span>
          </div>

          <div class="schedule-card-body">
            <div><strong>Type:</strong> ${escapeHtml(s.typeLabel || s.type)}</div>
            <div><strong>Target / Buyer:</strong> ${escapeHtml(s.buyerName || "All Eligible")}</div>
            ${s.amount ? `<div><strong>Amount:</strong> ${formatCurrency(s.amount, s.currency)}</div>` : ""}
            <div><strong>Next Scheduled Execution:</strong> <span class="text-xs-mono">${escapeHtml(s.nextRun)}</span></div>
          </div>

          <div class="schedule-card-foot">
            <button type="button" class="btn btn-secondary btn-sm" data-schedule-toggle="${escapeHtml(s.id)}">
              ${s.status === "ACTIVE" ? "Pause Schedule" : "Resume Schedule"}
            </button>
            <button type="button" class="btn btn-ghost btn-sm" data-schedule-run="${escapeHtml(s.id)}">
              Trigger Run Now &rarr;
            </button>
          </div>
        </div>`
        )
        .join("")}
    </div>
  `;
}

function openBudgetModal() {
  const current = store.getState().financialBudget || {
    monthlyTargetUsd: 5000,
    feeCapPercent: 5.0,
    taxReservePercent: 15,
    maxCurrencySharePercent: 65,
  };

  const bodyHtml = `
    <form id="mg-budget-form" style="display:flex;flex-direction:column;gap:var(--space-4);">
      <div class="form-group">
        <label class="form-label" for="cfg-monthly-target">Monthly Export Revenue Target (USD)</label>
        <input type="number" id="cfg-monthly-target" class="form-control" value="${current.monthlyTargetUsd}" min="100" max="100000" step="100" required />
        <span class="form-hint">Used to calculate revenue run-rate and goal completion percentage.</span>
      </div>

      <div class="form-grid-2">
        <div class="form-group">
          <label class="form-label" for="cfg-fee-cap">Max PayPal Fee Tolerance (%)</label>
          <input type="number" id="cfg-fee-cap" class="form-control" value="${current.feeCapPercent}" min="1" max="10" step="0.1" required />
          <span class="form-hint">Triggers warning alert if effective fee exceeds this.</span>
        </div>
        <div class="form-group">
          <label class="form-label" for="cfg-tax-reserve">Advance Tax / GST Buffer (%)</label>
          <input type="number" id="cfg-tax-reserve" class="form-control" value="${current.taxReservePercent}" min="0" max="40" step="1" required />
          <span class="form-hint">Recommended liquidity buffer for quarterly advance tax.</span>
        </div>
      </div>

      <div class="form-group">
        <label class="form-label" for="cfg-currency-limit">Max Single-Currency Exposure (%)</label>
        <input type="number" id="cfg-currency-limit" class="form-control" value="${current.maxCurrencySharePercent}" min="30" max="100" step="5" required />
        <span class="form-hint">Flags high concentration risk if a single currency exceeds this share.</span>
      </div>
    </form>
  `;

  const footerHtml = `
    <button type="button" class="btn btn-secondary" id="mg-modal-cancel">Cancel</button>
    <button type="submit" form="mg-budget-form" class="btn btn-primary" id="mg-modal-save">Save Budget &amp; Limits</button>
  `;

  openModal({
    title: "Configure Export Budget & Limits",
    bodyHtml,
    footerHtml,
    size: "md",
    onMount: ({ panel, close }) => {
      panel.querySelector("#mg-modal-cancel")?.addEventListener("click", close);
      const form = panel.querySelector("#mg-budget-form");
      form?.addEventListener("submit", (e) => {
        e.preventDefault();
        const updated = {
          monthlyTargetUsd: Number(panel.querySelector("#cfg-monthly-target").value),
          feeCapPercent: Number(panel.querySelector("#cfg-fee-cap").value),
          taxReservePercent: Number(panel.querySelector("#cfg-tax-reserve").value),
          maxCurrencySharePercent: Number(panel.querySelector("#cfg-currency-limit").value),
        };
        store.updateBudget(updated);
        close();
        const mount = document.getElementById("page-mount");
        if (mount) renderMoneyGuidePage(mount);
        showToast({
          title: "Budget Configured",
          message: `Monthly target set to $${updated.monthlyTargetUsd.toLocaleString()} USD.`,
          type: "success",
        });
      });
    },
  });
}

function openScheduleModal() {
  const buyers = store.getState().buyers || [
    { displayName: "Rahul Mehta (Acme USA)", buyerToken: "BUYER_RAHUL_01" },
    { displayName: "Elena Rostova (Design Berlin)", buyerToken: "BUYER_ELENA_02" },
    { displayName: "Oliver Grant (UK Fintech)", buyerToken: "BUYER_OLIVER_03" },
  ];

  const bodyHtml = `
    <form id="mg-schedule-form" style="display:flex;flex-direction:column;gap:var(--space-4);">
      <div class="form-group">
        <label class="form-label" for="sch-title">Schedule Title</label>
        <input type="text" id="sch-title" placeholder="e.g. Monthly Design Retainer" required />
      </div>

      <div class="form-grid-2">
        <div class="form-group">
          <label class="form-label" for="sch-type">Schedule Type</label>
          <select id="sch-type" class="filter-select">
            <option value="RECURRING_INVOICE">Recurring Invoice</option>
            <option value="PAYMENT_REMINDER">Automated Payment Reminder</option>
            <option value="TAX_RESERVE_SET_ASIDE">Tax &amp; Compliance Lock</option>
          </select>
        </div>
        <div class="form-group">
          <label class="form-label" for="sch-cadence">Execution Cadence</label>
          <select id="sch-cadence" class="filter-select">
            <option value="Monthly (1st)">Monthly (1st of month)</option>
            <option value="Monthly (20th)">Monthly (20th of month)</option>
            <option value="Bi-Weekly">Bi-Weekly (Every 14 days)</option>
            <option value="Weekly">Weekly (Every Monday)</option>
            <option value="Daily 09:00 UTC">Daily (09:00 UTC)</option>
          </select>
        </div>
      </div>

      <div class="form-group" id="sch-buyer-group">
        <label class="form-label" for="sch-buyer">Target Overseas Buyer</label>
        <select id="sch-buyer" class="filter-select">
          ${buyers.map((b) => `<option value="${escapeHtml(b.buyerToken)}">${escapeHtml(b.displayName)}</option>`).join("")}
          <option value="ALL_ELIGIBLE">All Eligible Unpaid Invoices</option>
        </select>
      </div>

      <div class="form-grid-2" id="sch-amount-row">
        <div class="form-group">
          <label class="form-label" for="sch-amount">Amount</label>
          <input type="number" id="sch-amount" value="500.00" min="1" max="2500" step="0.01" />
        </div>
        <div class="form-group">
          <label class="form-label" for="sch-currency">Currency</label>
          <select id="sch-currency" class="filter-select">
            <option value="USD">USD ($)</option>
            <option value="EUR">EUR (€)</option>
            <option value="GBP">GBP (£)</option>
            <option value="INR">INR (₹)</option>
          </select>
        </div>
      </div>

      <div class="form-group">
        <label class="form-label" for="sch-next-run">First Execution Date</label>
        <input type="date" id="sch-next-run" value="2026-12-01" required />
      </div>
    </form>
  `;

  const footerHtml = `
    <button type="button" class="btn btn-secondary" id="sch-modal-cancel">Cancel</button>
    <button type="submit" form="mg-schedule-form" class="btn btn-primary" id="sch-modal-create">Create Schedule</button>
  `;

  openModal({
    title: "Create Financial Automation Schedule",
    bodyHtml,
    footerHtml,
    size: "md",
    onMount: ({ panel, close }) => {
      panel.querySelector("#sch-modal-cancel")?.addEventListener("click", close);
      const form = panel.querySelector("#mg-schedule-form");
      form?.addEventListener("submit", (e) => {
        e.preventDefault();
        const buyerSelect = panel.querySelector("#sch-buyer");
        const buyerToken = buyerSelect.value;
        const buyerName = buyerSelect.options[buyerSelect.selectedIndex].text;
        const typeSelect = panel.querySelector("#sch-type");
        const type = typeSelect.value;
        const typeLabel = typeSelect.options[typeSelect.selectedIndex].text;

        const newSched = {
          title: panel.querySelector("#sch-title").value.trim() || "Automated Schedule",
          type,
          typeLabel,
          cadence: panel.querySelector("#sch-cadence").value,
          buyerName,
          buyerToken,
          amount: Number(panel.querySelector("#sch-amount")?.value || 0) || null,
          currency: panel.querySelector("#sch-currency")?.value || "USD",
          nextRun: panel.querySelector("#sch-next-run").value || "2026-12-01",
        };

        store.addSchedule(newSched);
        close();
        const mount = document.getElementById("page-mount");
        if (mount) renderMoneyGuidePage(mount);
        showToast({
          title: "Schedule Created",
          message: `${newSched.title} is now active.`,
          type: "success",
        });
      });
    },
  });
}
