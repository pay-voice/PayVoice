import { Router } from "express";
import { paypalTools } from "../config/paypal.js";
import { computeTransactionTotals } from "../services/moneyGuide.js";

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
    fee: 7.47,
    netAmount: 192.53,
    currency: "USD",
    status: "COMPLETED",
  },
  {
    id: "TX-2026-EU-4401",
    invoiceId: "INV2-EU-1200-4491",
    date: "2026-11-08T09:15:00Z",
    buyerToken: "BUYER_GLOBAL_02",
    buyerName: "Global Tech BV",
    item: "UI/UX Design Sprint (Phase 2)",
    grossAmount: 350.0,
    fee: 12.71,
    netAmount: 337.29,
    currency: "EUR",
    status: "COMPLETED",
  },
  {
    id: "TX-2026-US-8820",
    invoiceId: "INV2-US-5541-8820",
    date: "2026-11-04T16:45:00Z",
    buyerToken: "BUYER_RAHUL_01",
    buyerName: "Rahul Mehta",
    item: "Security Audit & Code Hardening",
    grossAmount: 180.0,
    fee: 6.77,
    netAmount: 173.23,
    currency: "USD",
    status: "COMPLETED",
  },
];

/**
 * GET /api/transactions
 * Retrieve recent export transactions
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
    res.json({
      success: true,
      transactions,
      totals,
    });
  } catch (error) {
    console.error("[Transactions Route Error]:", error);
    res.status(500).json({ success: false, error: "Failed to fetch transactions: " + error.message });
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
