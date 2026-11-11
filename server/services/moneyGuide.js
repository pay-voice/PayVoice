import crypto from "crypto";
import { resolveBuyerToken } from "./vault.js";

// 15-minute rolling idempotency cache for duplicate invoice prevention
const recentInvoices = new Map(); // key -> timestamp ms
const DUPLICATE_WINDOW_MS = 15 * 60 * 1000;

function cleanOldInvoices() {
  const now = Date.now();
  for (const [key, timestamp] of recentInvoices.entries()) {
    if (now - timestamp > DUPLICATE_WINDOW_MS) {
      recentInvoices.delete(key);
    }
  }
}

/**
 * Deterministic Money Guide AI Policy Engine
 * Runs strict deterministic financial validation - Zero LLM hallucination risk.
 * @param {object} intent - { buyer_token, item, amount, currency, quantity }
 * @returns {{ approved: boolean, policyViolation: string | null, message: string, buyer: object | null, policySnapshot: object }}
 */
export function evaluateTransactionPolicy(intent) {
  cleanOldInvoices();

  const { buyer_token, item, amount, currency } = intent || {};
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

  // 2. Currency Compliance (PayPal India OPGSP Rule)
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

  // 3. Export Value Cap Enforcement
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

  // 4. Duplicate Invoice Idempotency Check
  const normalizedItem = String(item || "").trim().toLowerCase();
  const idempotencyKey = crypto
    .createHash("sha256")
    .update(`${buyer.buyerToken}|${normalizedItem}|${numAmount.toFixed(2)}|${normCurrency}`)
    .digest("hex");

  const lastSeen = recentInvoices.get(idempotencyKey);
  const now = Date.now();

  if (lastSeen && now - lastSeen < DUPLICATE_WINDOW_MS) {
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
      evaluatedAt: new Date().toISOString(),
    },
  };
}

/**
 * Deterministically compute accounting totals, fee estimates, and net proceeds for a set of transactions
 * Standard PayPal international cross-border merchant fee calculation:
 * Typically ~3.49% + fixed fee (e.g., $0.49 USD) or 4.4% for international commercial payments
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
      // Deterministic PayPal International Commercial fee estimate: 3.49% + $0.49
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
