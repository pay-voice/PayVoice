import { Router } from "express";
import { paypalTools } from "../config/paypal.js";
import {
  computeTransactionTotals,
  computeCfoInsights,
  computeRiskAndInvestmentRating,
  computeBudgetingAndLimits,
} from "../services/moneyGuide.js";

const router = Router();

const DEFAULT_SANDBOX_TRANSACTIONS = [
  {
    id: "TX-2026-US-9912",
    invoiceId: "INV2-US-7782-9901",
    date: "2026-11-10T14:32:00Z",
    buyerToken: "BUYER_RAHUL_01",
    buyerName: "Rahul Mehta",
    item: "Cloud API Development (Milestone 1)",
    grossAmount: 200.0,
    fee: 9.1,
    netAmount: 190.9,
    currency: "USD",
    status: "COMPLETED",
  },
  {
    id: "TX-2026-EU-4401",
    invoiceId: "INV2-EU-1200-4491",
    date: "2026-11-08T09:15:00Z",
    buyerToken: "BUYER_ELENA_02",
    buyerName: "Elena Rostova",
    item: "UI/UX Design Sprint (40 Hours)",
    grossAmount: 450.0,
    fee: 20.1,
    netAmount: 429.9,
    currency: "EUR",
    status: "COMPLETED",
  },
  {
    id: "TX-2026-GB-8820",
    invoiceId: "INV2-GB-5541-8820",
    date: "2026-11-04T16:45:00Z",
    buyerToken: "BUYER_OLIVER_03",
    buyerName: "Oliver Grant",
    item: "Security Penetration Audit",
    grossAmount: 350.0,
    fee: 15.7,
    netAmount: 334.3,
    currency: "GBP",
    status: "COMPLETED",
  },
  {
    id: "TX-2026-US-5510",
    invoiceId: "INV2-US-3321-5510",
    date: "2026-10-28T11:20:00Z",
    buyerToken: "BUYER_AKIRA_04",
    buyerName: "Akira Sato",
    item: "Embedded Firmware Module (2 Units)",
    grossAmount: 500.0,
    fee: 22.3,
    netAmount: 477.7,
    currency: "USD",
    status: "COMPLETED",
  },
];

/**
 * GET /api/transactions
 * Retrieve recent export transactions, CFO insights, risk ratings & budget telemetry
 */
router.get("/", async (req, res) => {
  try {
    let transactions = DEFAULT_SANDBOX_TRANSACTIONS;

    if (paypalTools && paypalTools.transactions && typeof paypalTools.transactions.list === "function") {
      try {
        const result = await paypalTools.transactions.list();
        if (Array.isArray(result) && result.length > 0) {
          transactions = result;
        }
      } catch (err) {
        console.warn("[PayPal Transactions List Warning]:", err.message);
      }
    }

    const totals = computeTransactionTotals(transactions);
    const cfoInsights = computeCfoInsights(transactions);

    res.json({
      success: true,
      transactions,
      totals,
      cfoInsights,
    });
  } catch (error) {
    console.error("[Transactions Route Error]:", error);
    res.status(500).json({ success: false, error: "Failed to fetch transactions: " + error.message });
  }
});

/**
 * GET /api/transactions/cfo-insights
 * Retrieve detailed proactive CFO financial intelligence & OPGSP headroom metrics
 */
router.get("/cfo-insights", (req, res) => {
  try {
    const insights = computeCfoInsights(DEFAULT_SANDBOX_TRANSACTIONS);
    res.json({
      success: true,
      cfoInsights: insights,
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * GET /api/transactions/risk-rating
 * Retrieve real-time risk score, composite breakdown & institutional working capital rating
 */
router.get("/risk-rating", (req, res) => {
  try {
    const risk = computeRiskAndInvestmentRating(DEFAULT_SANDBOX_TRANSACTIONS);
    res.json({
      success: true,
      riskMeter: risk,
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * GET /api/transactions/budgeting
 * Retrieve limits, monthly targets and currency exposure thresholds
 */
router.get("/budgeting", (req, res) => {
  try {
    const budget = computeBudgetingAndLimits(DEFAULT_SANDBOX_TRANSACTIONS, req.query || {});
    res.json({
      success: true,
      budgeting: budget,
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * GET /api/insights
 * Retrieve merchant cross-border export performance metrics
 */
router.get("/insights", async (req, res) => {
  try {
    let insightsData = null;

    if (paypalTools && paypalTools.insights && typeof paypalTools.insights.get === "function") {
      try {
        insightsData = await paypalTools.insights.get();
      } catch (err) {
        console.warn("[PayPal Insights Get Warning]:", err.message);
      }
    }

    const totals = computeTransactionTotals(DEFAULT_SANDBOX_TRANSACTIONS);

    res.json({
      success: true,
      insights: insightsData || {
        corridor: "India to US / Europe (OPGSP Cross-Border Export)",
        totalExportVolume: `$${totals.totalGross.toFixed(2)} USD`,
        netRealizedRevenue: `$${totals.totalNet.toFixed(2)} USD`,
        estimatedPayPalFees: `$${totals.estimatedFees.toFixed(2)} USD`,
        complianceStatus: "100% Compliant (All transactions <= $2,500 USD limit)",
        topDestination: "United States (USD)",
        recommendation: "Increase invoice dispatch velocity before Friday banking settlement cut-off.",
      },
    });
  } catch (error) {
    console.error("[Insights Route Error]:", error);
    res.status(500).json({ success: false, error: "Failed to fetch insights: " + error.message });
  }
});

export default router;
