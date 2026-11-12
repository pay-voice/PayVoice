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
 *   - Physical Hardware/Goods: P0103 (requires valid 10-char alphanumeric IEC)
 *   - Digital/IT Services: P0802 (exempt from physical cargo IEC requirement)
 *
 * @param {string} itemDescription
 * @param {string} [merchantIec]
 * @returns {{ purposeCode: string, category: "GOODS" | "SERVICES", description: string, iecRequired: boolean, iecValid: boolean, merchantIec: string }}
 */
export function classifyRbiPurposeCode(itemDescription = "", merchantIec = null) {
  const norm = String(itemDescription || "").toLowerCase().trim();

  const goodsKeywords = [
    "hardware", "equipment", "server rack", "device", "physical kit",
    "electronics", "appliance", "circuit", "sensor", "storage drive",
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
 * Deterministic Static Foreign Exchange (FX) Reference Table (25 Supported International Currencies)
 * NOTE: These are deterministic reference rates for testing & regulatory cap normalization,
 * not live fluctuating market rates. All amounts are normalized using integer minor-unit arithmetic.
 */
export const STATIC_FX_RATES_V1 = {
  USD: { rateToUsd: 1.0, decimals: 2, name: "US Dollar" },
  EUR: { rateToUsd: 1.08, decimals: 2, name: "Euro" },
  GBP: { rateToUsd: 1.28, decimals: 2, name: "British Pound" },
  AUD: { rateToUsd: 0.65, decimals: 2, name: "Australian Dollar" },
  CAD: { rateToUsd: 0.73, decimals: 2, name: "Canadian Dollar" },
  SGD: { rateToUsd: 0.75, decimals: 2, name: "Singapore Dollar" },
  JPY: { rateToUsd: 0.0065, decimals: 0, name: "Japanese Yen" },
  CHF: { rateToUsd: 1.12, decimals: 2, name: "Swiss Franc" },
  AED: { rateToUsd: 0.272, decimals: 2, name: "UAE Dirham" },
  NZD: { rateToUsd: 0.60, decimals: 2, name: "New Zealand Dollar" },
  HKD: { rateToUsd: 0.128, decimals: 2, name: "Hong Kong Dollar" },
  SEK: { rateToUsd: 0.094, decimals: 2, name: "Swedish Krona" },
  NOK: { rateToUsd: 0.092, decimals: 2, name: "Norwegian Krone" },
  DKK: { rateToUsd: 0.145, decimals: 2, name: "Danish Krone" },
  PLN: { rateToUsd: 0.252, decimals: 2, name: "Polish Zloty" },
  CZK: { rateToUsd: 0.043, decimals: 2, name: "Czech Koruna" },
  HUF: { rateToUsd: 0.0027, decimals: 0, name: "Hungarian Forint" },
  MXN: { rateToUsd: 0.055, decimals: 2, name: "Mexican Peso" },
  BRL: { rateToUsd: 0.18, decimals: 2, name: "Brazilian Real" },
  MYR: { rateToUsd: 0.215, decimals: 2, name: "Malaysian Ringgit" },
  THB: { rateToUsd: 0.028, decimals: 2, name: "Thai Baht" },
  PHP: { rateToUsd: 0.0175, decimals: 2, name: "Philippine Peso" },
  TWD: { rateToUsd: 0.031, decimals: 0, name: "New Taiwan Dollar" },
  ILS: { rateToUsd: 0.27, decimals: 2, name: "Israeli Shekel" },
  TRY: { rateToUsd: 0.029, decimals: 2, name: "Turkish Lira" },
};

/**
 * Normalizes an international currency amount to USD using integer minor-unit arithmetic
 * Avoids IEEE-754 floating point rounding drift.
 *
 * @param {number | string} amount
 * @param {string} currency
 * @returns {{ currency: string, originalAmount: number, decimals: number, minorUnits: number, fxRate: number, usdEquivalent: number }}
 */
export function normalizeToUsd(amount, currency) {
  const normCurr = String(currency || "").trim().toUpperCase();
  const num = Number(amount);
  if (isNaN(num) || num <= 0) {
    throw new Error("Amount must be a positive number greater than 0");
  }

  const fxInfo = STATIC_FX_RATES_V1[normCurr];
  if (!fxInfo) {
    throw new Error(`Unsupported currency '${normCurr}'. Supported: ${Object.keys(STATIC_FX_RATES_V1).join(", ")}`);
  }

  const scale = 10 ** fxInfo.decimals;
  const minorUnits = Math.round(num * scale);
  const rawOriginal = minorUnits / scale;
  const usdCents = Math.round(rawOriginal * fxInfo.rateToUsd * 100);
  const usdEquivalent = Number((usdCents / 100).toFixed(2));

  return {
    currency: normCurr,
    originalAmount: rawOriginal,
    decimals: fxInfo.decimals,
    minorUnits,
    fxRate: fxInfo.rateToUsd,
    usdEquivalent,
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
  if (options.requireReadBack === true) {
    if (readBackConfirmed !== true) {
      return {
        approved: false,
        policyViolation: "READ_BACK_NOT_CONFIRMED",
        message: "The invoice preview must be visually and audibly confirmed (readBackConfirmed: true) before step-up authorization.",
        buyer,
        policySnapshot: { buyer_token, readBackConfirmed: Boolean(readBackConfirmed) },
      };
    }

    if (options.confirmationDigest) {
      const expectedDigest = computeReadBackDigest(intent, options.language || "en");
      try {
        const matches = crypto.timingSafeEqual(
          Buffer.from(options.confirmationDigest, "hex"),
          Buffer.from(expectedDigest, "hex")
        );
        if (!matches) {
          return {
            approved: false,
            policyViolation: "READ_BACK_DIGEST_MISMATCH",
            message: "Cryptographic confirmation digest mismatch. Staged invoice fields do not match confirmed read-back summary.",
            buyer,
            policySnapshot: { buyer_token, readBackConfirmed: false },
          };
        }
      } catch {
        return {
          approved: false,
          policyViolation: "READ_BACK_DIGEST_INVALID",
          message: "Invalid read-back confirmation digest encoding.",
          buyer,
          policySnapshot: { buyer_token, readBackConfirmed: false },
        };
      }
    }
  }

  // 3. Currency Compliance (PayPal India OPGSP Rule & 25-Currency Normalization)
  const normCurrency = String(currency || "").trim().toUpperCase();
  if (normCurrency === "INR") {
    return {
      approved: false,
      policyViolation: "DOMESTIC_INR_NOT_SUPPORTED",
      message: "PayPal India regulations strictly prohibit domestic INR transfers under RBI OPGSP guidelines. PayVoice only supports cross-border export invoicing in approved foreign currencies.",
      buyer,
      policySnapshot: { requestedCurrency: normCurrency, permittedCurrencies: Object.keys(STATIC_FX_RATES_V1) },
    };
  }

  const fxInfo = STATIC_FX_RATES_V1[normCurrency];
  if (!fxInfo) {
    return {
      approved: false,
      policyViolation: "UNSUPPORTED_EXPORT_CURRENCY",
      message: `Currency '${normCurrency}' is not permitted. Only approved international currencies are authorized.`,
      buyer,
      policySnapshot: { requestedCurrency: normCurrency, supportedCurrencies: Object.keys(STATIC_FX_RATES_V1) },
    };
  }

  // 4. Export Value Cap Enforcement (Integer Minor-Unit Normalized to USD)
  if (isNaN(numAmount) || numAmount <= 0) {
    return {
      approved: false,
      policyViolation: "INVALID_AMOUNT",
      message: "Invoice amount must be a positive number greater than 0.",
      buyer,
      policySnapshot: { requestedAmount: amount },
    };
  }

  let normalized;
  try {
    normalized = normalizeToUsd(numAmount, normCurrency);
  } catch (err) {
    return {
      approved: false,
      policyViolation: "CURRENCY_CALCULATION_ERROR",
      message: err.message,
      buyer,
      policySnapshot: { requestedAmount: numAmount, currency: normCurrency },
    };
  }

  const maxCap = Math.min(buyer.maxLimit || 2500.0, 2500.0);
  if (normalized.usdEquivalent > maxCap) {
    return {
      approved: false,
      policyViolation: "EXPORT_LIMIT_EXCEEDED",
      message: `Requested amount ${numAmount.toFixed(2)} ${normCurrency} ($${normalized.usdEquivalent.toFixed(2)} USD equivalent) exceeds the authorized regulatory limit of $${maxCap.toFixed(2)} USD for this exporter.`,
      buyer,
      policySnapshot: {
        requestedAmount: numAmount,
        currency: normCurrency,
        usdEquivalent: normalized.usdEquivalent,
        fxRate: normalized.fxRate,
        maxAuthorizedCap: maxCap,
      },
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

      const category = tx.category || (tx.description && tx.description.includes("API") ? "Cloud & APIs" : "SaaS & Software");
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

const REMINDER_COOLDOWN_MS = 24 * 60 * 60 * 1000; // 24-hour deterministic reminder cooldown
const READBACK_SECRET = process.env.VAULT_SECRET || "payvoice-readback-secret-2026";

/**
 * Validate payment reminder policy (Eligible only if SENT and UNPAID, enforces 24-hour cooldown)
 *
 * @param {string} invoiceId
 * @param {string} invoiceStatus
 * @param {string | number} [lastReminderTimestamp]
 * @param {object} [options={}]
 * @returns {{ allowed: boolean, reason?: string, eligibleAt?: string, remainingMs?: number }}
 */
export function validateInvoiceReminderPolicy(invoiceId, invoiceStatus, lastReminderTimestamp = null, options = {}) {
  if (!invoiceId) {
    return { allowed: false, reason: "Missing mandatory invoiceId parameter." };
  }

  const normStatus = String(invoiceStatus || "").trim().toUpperCase();
  const eligibleStatuses = ["SENT", "UNPAID", "SENT (UNPAID)"];

  if (!eligibleStatuses.includes(normStatus)) {
    return {
      allowed: false,
      status: normStatus,
      reason: `Invoice status '${normStatus}' is not eligible for payment reminders. Only SENT and UNPAID invoices may receive reminders (PAID, DRAFT, and CANCELLED are blocked).`,
    };
  }

  const now = Date.now();
  const cooldownMs = options.cooldownMs || REMINDER_COOLDOWN_MS;

  if (lastReminderTimestamp !== null && lastReminderTimestamp !== undefined) {
    const lastTime = new Date(lastReminderTimestamp).getTime();
    if (isNaN(lastTime)) {
      return { allowed: false, reason: "Invalid lastReminderTimestamp format." };
    }

    if (lastTime > now + 300000) {
      return { allowed: false, reason: "Invalid reminder timestamp: Future timestamp detected." };
    }

    const elapsed = now - lastTime;
    if (elapsed < cooldownMs) {
      const remainingHours = ((cooldownMs - elapsed) / (60 * 60 * 1000)).toFixed(1);
      return {
        allowed: false,
        reason: `Reminder cooldown active. Invoices can only receive a reminder once every ${Math.round(cooldownMs / 3600000)}h to avoid buyer harassment (${remainingHours}h remaining).`,
        remainingMs: cooldownMs - elapsed,
        eligibleAt: new Date(lastTime + cooldownMs).toISOString(),
      };
    }
  }

  return {
    allowed: true,
    invoiceId,
    status: normStatus,
    eligibleAt: new Date(now).toISOString(),
  };
}

/**
 * Cryptographic Read-Back Confirmation Digest
 * Binds the localized speech preview parameters to prevent tampering between audio preview and passkey execution.
 *
 * @param {object} stagedInvoice - { buyer_token, item, quantity, amount, currency, stageId }
 * @param {string} [language="en"] - Localized confirmation language (en, hi, mr)
 * @returns {string} 64-character HMAC-SHA256 hex digest
 */
export function computeReadBackDigest(stagedInvoice, language = "en") {
  if (!stagedInvoice || typeof stagedInvoice !== "object") {
    throw new Error("Invalid stagedInvoice: must be an object");
  }

  const buyerToken = String(stagedInvoice.buyer_token || stagedInvoice.buyerToken || "").trim().toUpperCase();
  const item = String(stagedInvoice.item || "").trim().toLowerCase();
  const quantity = String(stagedInvoice.quantity || "1 unit").trim().toLowerCase();
  const amount = Number(stagedInvoice.amount || 0).toFixed(2);
  const currency = String(stagedInvoice.currency || "USD").trim().toUpperCase();
  const lang = String(language || "en").trim().toLowerCase();
  const stageId = String(stagedInvoice.stageId || stagedInvoice.id || stagedInvoice.version || "STAGED_V1").trim();

  const canonicalString = `${buyerToken}|${item}|${quantity}|${amount}|${currency}|${lang}|${stageId}`;
  return crypto.createHmac("sha256", READBACK_SECRET).update(canonicalString).digest("hex");
}

/**
 * Verifies a confirmation digest against the staged invoice parameters
 *
 * @param {object} params - { stagedInvoice, language, confirmationDigest }
 * @returns {{ valid: boolean, reason?: string }}
 */
export function verifyReadBackConfirmation({ stagedInvoice, language = "en", confirmationDigest }) {
  if (!confirmationDigest || typeof confirmationDigest !== "string") {
    return { valid: false, reason: "Missing confirmation digest" };
  }

  const expected = computeReadBackDigest(stagedInvoice, language);
  try {
    const isMatch = crypto.timingSafeEqual(
      Buffer.from(confirmationDigest, "hex"),
      Buffer.from(expected, "hex")
    );
    return {
      valid: isMatch,
      reason: isMatch ? null : "Confirmation digest does not match staged invoice payload",
    };
  } catch {
    return { valid: false, reason: "Invalid confirmation digest format" };
  }
}
