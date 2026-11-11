import crypto from "crypto";
import { resolveBuyerToken } from "./vault.js";

// 15-minute rolling idempotency cache for duplicate invoice prevention
const recentInvoices = new Map(); // key -> timestamp ms
const DUPLICATE_WINDOW_MS = 15 * 60 * 1000;

export function clearRecentInvoices() {
  recentInvoices.clear();
}

function cleanOldInvoices() {
  const now = Date.now();
  for (const [key, timestamp] of recentInvoices.entries()) {
    if (now - timestamp > DUPLICATE_WINDOW_MS) {
      recentInvoices.delete(key);
    }
  }
}

/**
 * Dynamic RBI Purpose Code & DGFT IEC Enforcement Classifier
 * Categorizes cross-border transactions:
 *   - Physical/Agricultural Goods: P0103 (requires valid 10-char alphanumeric IEC)
 *   - Digital/Freelance Services: P0802 (exempt from physical cargo IEC requirement)
 *
 * @param {string} itemDescription
 * @param {string} [merchantIec]
 * @returns {{ purposeCode: string, category: "GOODS" | "SERVICES", description: string, iecRequired: boolean, iecValid: boolean, merchantIec: string }}
 */
export function classifyRbiPurposeCode(itemDescription = "", merchantIec = null) {
  const norm = String(itemDescription || "").toLowerCase().trim();

  const goodsKeywords = [
    "wheat", "grain", "cotton", "seed", "seeds", "rice", "basmati", "soybean",
    "spice", "spices", "tea", "coffee", "textile", "fabric", "garment",
    "handicraft", "leather", "machinery", "equipment", "hardware", "goods",
    "crop", "produce", "organic", "fertilizer", "soil", "cargo", "shipment",
    "dispatch", "lot", "agri", "commodity", "pack", "गहू", "गेहूँ", "सोयाबीन",
    "तांदूळ", "चावल", "कपास", "बियाणे", "बीज", "मसाले", "मसाला",
  ];

  const servicesKeywords = [
    "software", "consulting", "consultancy", "code", "development", "dev",
    "ui/ux", "design", "api", "cloud", "saas", "frontend", "backend",
    "full-stack", "testing", "qa", "freelance", "translation", "audit",
    "support", "license", "maintenance", "service", "services", "analytics", "engineering",
  ];

  const isExplicitService = servicesKeywords.some((kw) => norm.includes(kw));
  const isGoods = !isExplicitService && goodsKeywords.some((kw) => norm.includes(kw));

  const resolvedIec = merchantIec || process.env.MERCHANT_IEC || "0319088821";
  const isIecFormatValid = /^[A-Z0-9]{10}$/.test(String(resolvedIec).trim().toUpperCase());

  if (isGoods) {
    return {
      purposeCode: "P0103",
      category: "GOODS",
      description: "Export of Goods (Physical Cargo / OPGSP Guidelines)",
      iecRequired: true,
      iecValid: isIecFormatValid,
      merchantIec: isIecFormatValid ? String(resolvedIec).trim().toUpperCase() : "INVALID_IEC",
    };
  }

  return {
    purposeCode: "P0802",
    category: "SERVICES",
    description: "Software & Consultancy Services (Cross-Border Non-Physical)",
    iecRequired: false,
    iecValid: true,
    merchantIec: "EXEMPT_SERVICES",
  };
}

/**
 * Deterministic Money Guide AI Policy Engine
 * Runs strict deterministic financial validation - Zero LLM hallucination risk.
 * @param {object} intent - { buyer_token, item, amount, currency, quantity, readBackConfirmed }
 * @param {object} [options={}] - { requireReadBack: boolean }
 * @returns {{ approved: boolean, policyViolation: string | null, message: string, buyer: object | null, policySnapshot: object }}
 */
export function evaluateTransactionPolicy(intent, options = {}) {
  cleanOldInvoices();

  const { buyer_token, item, amount, currency, readBackConfirmed } = intent || {};
  const numAmount = Number(amount);

  // 1. Buyer Allowlist Check
  const buyer = resolveBuyerToken(buyer_token);
  if (!buyer) {
    return {
      approved: false,
      policyViolation: "BUYER_NOT_ALLOWLISTED",
      message: `Buyer token '${buyer_token}' is not found in the verified PII Vault. Untrusted recipients cannot be invoiced.`,
      buyer: null,
      policySnapshot: { buyer_token, checkedAt: new Date().toISOString() },
    };
  }

  // 2. Read-Back Confirmation Enforcement (Required before step-up verification)
  if (options.requireReadBack === true && readBackConfirmed !== true) {
    return {
      approved: false,
      policyViolation: "READ_BACK_NOT_CONFIRMED",
      message: "The invoice preview must be visually and audibly confirmed (readBackConfirmed: true) before step-up authorization.",
      buyer,
      policySnapshot: { buyer_token, readBackConfirmed: Boolean(readBackConfirmed) },
    };
  }

  // 3. Currency Compliance (PayPal India OPGSP Rule)
  const normCurrency = String(currency || "").trim().toUpperCase();
  if (normCurrency === "INR") {
    return {
      approved: false,
      policyViolation: "DOMESTIC_INR_NOT_SUPPORTED",
      message: "PayPal India regulations strictly prohibit domestic INR transfers. PayVoice only supports cross-border export invoicing in USD or EUR.",
      buyer,
      policySnapshot: { requestedCurrency: normCurrency, permittedCurrencies: ["USD", "EUR"] },
    };
  }

  if (!["USD", "EUR"].includes(normCurrency)) {
    return {
      approved: false,
      policyViolation: "UNSUPPORTED_EXPORT_CURRENCY",
      message: `Currency '${normCurrency}' is not permitted. Only USD and EUR export invoicing are authorized.`,
      buyer,
      policySnapshot: { requestedCurrency: normCurrency },
    };
  }

  // 4. Export Value Cap Enforcement
  const maxCap = Math.min(buyer.maxLimit || 2500.0, 2500.0);
  if (isNaN(numAmount) || numAmount <= 0) {
    return {
      approved: false,
      policyViolation: "INVALID_AMOUNT",
      message: "Invoice amount must be a positive number greater than 0.",
      buyer,
      policySnapshot: { requestedAmount: amount },
    };
  }

  if (numAmount > maxCap) {
    return {
      approved: false,
      policyViolation: "EXPORT_LIMIT_EXCEEDED",
      message: `Requested amount $${numAmount.toFixed(2)} exceeds the authorized regulatory limit of $${maxCap.toFixed(2)} USD for this exporter.`,
      buyer,
      policySnapshot: { requestedAmount: numAmount, maxAuthorizedCap: maxCap },
    };
  }

  // 5. Duplicate Invoice Idempotency Check
  const normalizedItem = String(item || "").trim().toLowerCase();
  const idempotencyKey = crypto
    .createHash("sha256")
    .update(`${buyer.buyerToken}|${normalizedItem}|${numAmount.toFixed(2)}|${normCurrency}`)
    .digest("hex");

  const lastSeen = recentInvoices.get(idempotencyKey);
  const now = Date.now();

  if (!options.bypassIdempotency && lastSeen && now - lastSeen < DUPLICATE_WINDOW_MS) {
    const remainingMinutes = Math.ceil((DUPLICATE_WINDOW_MS - (now - lastSeen)) / 60000);
    return {
      approved: false,
      policyViolation: "DUPLICATE_INVOICE_BLOCKED",
      message: `An identical invoice for ${buyer.name} ($${numAmount.toFixed(2)} ${normCurrency} - ${item}) was recently staged. Blocked for ${remainingMinutes} more minute(s) to avoid double-billing.`,
      buyer,
      policySnapshot: { idempotencyKey, lastStagedAt: new Date(lastSeen).toISOString() },
    };
  }

  // Record this staged invoice in the idempotency cache
  recentInvoices.set(idempotencyKey, now);

  const rbiClassification = classifyRbiPurposeCode(normalizedItem, options.merchantIec);

  return {
    approved: true,
    policyViolation: null,
    message: "All deterministic Money Guide policies passed. Invoice is eligible for step-up WebAuthn passkey staging.",
    buyer,
    policySnapshot: {
      buyerToken: buyer.buyerToken,
      buyerName: buyer.name,
      amount: numAmount,
      currency: normCurrency,
      item: normalizedItem,
      idempotencyKey,
      rbiPurposeCode: rbiClassification.purposeCode,
      rbiCategory: rbiClassification.category,
      rbiDescription: rbiClassification.description,
      merchantIec: rbiClassification.merchantIec,
      evaluatedAt: new Date().toISOString(),
    },
  };
}

/**
 * Deterministically compute accounting totals, fee estimates, and net proceeds for a set of transactions
 * Standard PayPal international cross-border merchant fee calculation: 3.49% + $0.49
 * @param {Array} transactions - Array of transaction objects
 * @returns {{ totalGross: number, estimatedFees: number, totalNet: number, currency: string, count: number }}
 */
export function computeTransactionTotals(transactions = []) {
  let totalGross = 0;
  let estimatedFees = 0;
  const currency = transactions[0]?.currency || "USD";

  for (const tx of transactions) {
    const gross = Number(tx.amount || tx.grossAmount || 0);
    if (!isNaN(gross) && gross > 0) {
      totalGross += gross;
      const fee = Number(tx.fee || (gross * 0.0349 + 0.49).toFixed(2));
      estimatedFees += fee;
    }
  }

  const totalNet = Math.max(0, totalGross - estimatedFees);

  return {
    count: transactions.length,
    currency,
    totalGross: Number(totalGross.toFixed(2)),
    estimatedFees: Number(estimatedFees.toFixed(2)),
    totalNet: Number(totalNet.toFixed(2)),
    calculatedAt: new Date().toISOString(),
  };
}

/**
 * Abnormal Refund & Invoice Spike Detector
 * 100% deterministic Node.js financial analytics (zero LLM math).
 * Computes category totals, currency breakdowns, net export volume, refund rate %,
 * 7-day and 30-day rolling averages, and flags refund/invoice velocity spikes.
 *
 * @param {Array} transactions - Raw transaction objects
 * @param {Array} [invoices=[]] - Raw invoice objects
 * @returns {object} Structured analytics & anomaly alerts for LLM explanation
 */
export function analyzeMerchantAnomalies(transactions = [], invoices = []) {
  const now = Date.now();
  const ONE_DAY_MS = 24 * 60 * 60 * 1000;
  const SEVEN_DAYS_MS = 7 * ONE_DAY_MS;
  const THIRTY_DAYS_MS = 30 * ONE_DAY_MS;

  let totalGross = 0;
  let totalRefunded = 0;
  let totalFees = 0;
  let refundCount = 0;
  let regularCount = 0;

  const currencyBreakdown = { USD: 0, EUR: 0 };
  const categoryBreakdown = {};
  const refundsList = [];
  const amounts = [];

  let rolling7DayGross = 0;
  let rolling7DayCount = 0;
  let rolling30DayGross = 0;
  let rolling30DayCount = 0;

  // Process transactions
  for (const tx of transactions) {
    const amt = Number(tx.amount || tx.grossAmount || 0);
    const curr = (tx.currency || "USD").toUpperCase();
    const txDate = tx.date ? new Date(tx.date).getTime() : now;
    const isRefund = tx.type === "REFUND" || tx.status === "REFUNDED" || amt < 0;

    if (isRefund) {
      const posRefund = Math.abs(amt);
      totalRefunded += posRefund;
      refundCount++;
      refundsList.push({ id: tx.id, amount: posRefund, date: tx.date });
    } else if (amt > 0) {
      totalGross += amt;
      regularCount++;
      amounts.push(amt);
      currencyBreakdown[curr] = (currencyBreakdown[curr] || 0) + amt;

      const category = tx.category || (tx.description && tx.description.includes("Seed") ? "Agricultural Seeds" : "Grains & Commodities");
      categoryBreakdown[category] = (categoryBreakdown[category] || 0) + amt;

      const fee = Number(tx.fee || (amt * 0.0349 + 0.49).toFixed(2));
      totalFees += fee;

      if (now - txDate <= SEVEN_DAYS_MS) {
        rolling7DayGross += amt;
        rolling7DayCount++;
      }
      if (now - txDate <= THIRTY_DAYS_MS) {
        rolling30DayGross += amt;
        rolling30DayCount++;
      }
    }
  }

  const meanAmount = regularCount > 0 ? totalGross / regularCount : 0;
  const refundRatePercent = totalGross > 0 ? (totalRefunded / totalGross) * 100 : 0;
  const netExportVolume = Math.max(0, totalGross - totalRefunded - totalFees);

  const alerts = [];

  // Deterministic Flag 1: High Refund Rate Spike (> 10%)
  if (refundRatePercent > 10.0) {
    alerts.push({
      type: "HIGH_REFUND_RATE_SPIKE",
      severity: "HIGH",
      message: `Abnormal refund rate detected: ${refundRatePercent.toFixed(1)}% of total export volume (Threshold: 10.0%). Review recent buyer disputes.`,
      metricValue: Number(refundRatePercent.toFixed(1)),
      threshold: 10.0,
    });
  }

  // Deterministic Flag 2: Single Abnormal Refund Outlier (> 2x Mean Transaction)
  for (const r of refundsList) {
    if (meanAmount > 0 && r.amount > 2.0 * meanAmount) {
      alerts.push({
        type: "OUTLIER_SINGLE_REFUND",
        severity: "CRITICAL",
        message: `Single refund anomaly ($${r.amount.toFixed(2)}) exceeds 2x the merchant average export size ($${meanAmount.toFixed(2)}).`,
        metricValue: Number(r.amount.toFixed(2)),
        threshold: Number((2.0 * meanAmount).toFixed(2)),
        refundId: r.id,
      });
    }
  }

  // Deterministic Flag 3: Abnormal Invoice Size Spike in recent invoices (> 2.5x Mean)
  for (const inv of invoices) {
    const invAmt = Number(inv.amount || (inv.primaryRecipients && inv.amount?.value) || 0);
    if (meanAmount > 0 && invAmt > 2.5 * meanAmount) {
      alerts.push({
        type: "INVOICE_AMOUNT_SPIKE",
        severity: "MEDIUM",
        message: `High-value invoice spike ($${invAmt.toFixed(2)}) is 2.5x larger than historical mean ($${meanAmount.toFixed(2)}). Confirm goods phytosanitary specs.`,
        metricValue: invAmt,
        threshold: Number((2.5 * meanAmount).toFixed(2)),
        invoiceId: inv.id,
      });
    }
  }

  // Deterministic Flag 4: Velocity Spike (7-day activity is > 2x the 30-day weekly average)
  const weeklyAverage30Day = rolling30DayGross / 4.28;
  if (weeklyAverage30Day > 0 && rolling7DayGross > 2.0 * weeklyAverage30Day) {
    alerts.push({
      type: "EXPORT_VELOCITY_SPIKE",
      severity: "INFO",
      message: `7-day export velocity ($${rolling7DayGross.toFixed(2)}) is more than double the weekly baseline ($${weeklyAverage30Day.toFixed(2)}).`,
      metricValue: Number(rolling7DayGross.toFixed(2)),
      threshold: Number((2.0 * weeklyAverage30Day).toFixed(2)),
    });
  }

  return {
    hasAnomalies: alerts.length > 0,
    metrics: {
      totalTransactions: transactions.length,
      regularCount,
      refundCount,
      totalGross: Number(totalGross.toFixed(2)),
      totalRefunded: Number(totalRefunded.toFixed(2)),
      totalFees: Number(totalFees.toFixed(2)),
      netExportVolume: Number(netExportVolume.toFixed(2)),
      refundRatePercent: Number(refundRatePercent.toFixed(1)),
      meanAmount: Number(meanAmount.toFixed(2)),
      rolling7DayGross: Number(rolling7DayGross.toFixed(2)),
      rolling7DayCount,
      rolling30DayGross: Number(rolling30DayGross.toFixed(2)),
      rolling30DayCount,
      currencyBreakdown: {
        USD: Number((currencyBreakdown.USD || 0).toFixed(2)),
        EUR: Number((currencyBreakdown.EUR || 0).toFixed(2)),
      },
      categoryBreakdown,
    },
    alerts,
    analyzedAt: new Date().toISOString(),
  };
}
