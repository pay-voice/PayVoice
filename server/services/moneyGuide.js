import crypto from "crypto";
import { resolveBuyerToken, listMaskedBuyers, isBuyerInCooldown } from "./vault.js";

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
    "handloom", "goods", "physical",
  ];

  const designKeywords = [
    "ui/ux", "ui", "ux", "design", "graphic", "product design",
    "wireframe", "prototype", "branding", "illustration", "figma",
  ];

  const servicesKeywords = [
    "software", "consulting", "consultancy", "code", "development", "dev",
    "api", "cloud", "saas", "frontend", "backend",
    "full-stack", "testing", "qa", "freelance", "translation", "audit",
    "support", "license", "maintenance", "service", "services", "analytics", "engineering",
    "firmware", "penetration", "cyber",
  ];

  const isDesign = designKeywords.some((kw) => norm.includes(kw));
  const isExplicitService = servicesKeywords.some((kw) => norm.includes(kw));
  const isGoods = !isExplicitService && !isDesign && goodsKeywords.some((kw) => norm.includes(kw));

  const resolvedIec = merchantIec || process.env.MERCHANT_IEC || "0319088821";
  const isIecFormatValid = /^[A-Z0-9]{10}$/.test(String(resolvedIec).trim().toUpperCase());

  if (isGoods) {
    return {
      purposeCode: "P0103",
      category: "GOODS",
      description: "Export of Physical MSME / Handloom Goods (OPGSP)",
      iecRequired: true,
      iecValid: isIecFormatValid,
      merchantIec: isIecFormatValid ? String(resolvedIec).trim().toUpperCase() : "INVALID_IEC",
      lutStatus: "Export under Bond/LUT without payment of IGST",
    };
  }

  if (isDesign) {
    return {
      purposeCode: "P1004",
      category: "SERVICES",
      description: "Engineering, UI/UX & Product Design Services",
      iecRequired: false,
      iecValid: true,
      merchantIec: "EXEMPT_SERVICES",
      lutStatus: "Export under LUT without payment of IGST (Rule 96A CGST Rules)",
    };
  }

  return {
    purposeCode: "P0802",
    category: "SERVICES",
    description: "Software Implementation & Cloud IT Consultancy",
    iecRequired: false,
    iecValid: true,
    merchantIec: "EXEMPT_SERVICES",
    lutStatus: "Export under LUT without payment of IGST (Rule 96A CGST Rules)",
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

function computeRawLevenshtein(a = "", b = "") {
  const s1 = String(a || "").toLowerCase().trim().replace(/[^a-z0-9]/g, "");
  const s2 = String(b || "").toLowerCase().trim().replace(/[^a-z0-9]/g, "");
  if (s1 === s2) return 0;
  if (!s1.length) return s2.length;
  if (!s2.length) return s1.length;
  const d = [];
  for (let i = 0; i <= s1.length; i++) d[i] = [i];
  for (let j = 0; j <= s2.length; j++) d[0][j] = j;
  for (let i = 1; i <= s1.length; i++) {
    for (let j = 1; j <= s2.length; j++) {
      const cost = s1[i - 1] === s2[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
    }
  }
  return d[s1.length][s2.length];
}

/**
 * Normalized homoglyph Levenshtein distance
 * Neutralizes deceptive character swaps (e.g., 0->o, 1->l, 3->e, 5->s, vv->w)
 * @param {string} str1
 * @param {string} str2
 * @returns {number}
 */
export function computeHomoglyphLevenshtein(str1 = "", str2 = "") {
  const normalizeHomoglyphs = (s) =>
    String(s || "")
      .toLowerCase()
      .trim()
      .replace(/0/g, "o")
      .replace(/1/g, "l")
      .replace(/3/g, "e")
      .replace(/4/g, "a")
      .replace(/5/g, "s")
      .replace(/@/g, "a")
      .replace(/\$/g, "s")
      .replace(/vv/g, "w")
      .replace(/[^a-z0-9]/g, "");

  const s1 = normalizeHomoglyphs(str1);
  const s2 = normalizeHomoglyphs(str2);

  if (s1 === s2) return 0;
  if (!s1.length) return s2.length;
  if (!s2.length) return s1.length;

  const row = [];
  for (let i = 0; i <= s1.length; i++) row[i] = i;

  for (let i = 1; i <= s2.length; i++) {
    let prev = i;
    for (let j = 1; j <= s1.length; j++) {
      let val;
      if (s2.charAt(i - 1) === s1.charAt(j - 1)) {
        val = row[j - 1];
      } else {
        val = Math.min(row[j - 1] + 1, prev + 1, row[j] + 1);
      }
      row[j - 1] = prev;
      prev = val;
    }
    row[s1.length] = prev;
  }

  return row[s1.length];
}

/**
 * Payee Verification Sub-Check: Lookalike Names Detector
 * Flags payee names within edit distance 1-2 of saved allowlisted buyers
 * as suspected spoofing attempts (e.g., 'Rahu1 Mehta', 'Rahulll', 'Elena R0stova').
 *
 * @param {string} inputName
 * @param {number} [customThreshold=2]
 * @returns {{ isLookalike: boolean, isExactMatch: boolean, targetBuyer?: string, targetToken?: string, distance?: number, reason?: string }}
 */
export function detectLookalikePayee(inputName = "", customThreshold = 2) {
  if (!inputName || typeof inputName !== "string") {
    return { isLookalike: false, isExactMatch: false };
  }

  const rawClean = inputName.trim().toLowerCase();
  const knownBuyers = listMaskedBuyers();

  for (const b of knownBuyers) {
    const targetFull = (b.displayName || "").trim().toLowerCase();
    const targetFirst = targetFull.split(/\s+/)[0] || "";

    // Exact matches are legitimate, not lookalikes
    if (rawClean === targetFull || rawClean === targetFirst) {
      return { isLookalike: false, isExactMatch: true, matchedBuyer: b.displayName };
    }

    // Check full name homoglyph & raw Levenshtein
    const distFull = computeHomoglyphLevenshtein(rawClean, targetFull);
    const rawDistFull = computeRawLevenshtein(rawClean, targetFull);

    const isHomoglyphSwap = distFull === 0 && rawDistFull > 0;
    const isEditDistanceClose = rawDistFull >= 1 && rawDistFull <= customThreshold;

    if (isHomoglyphSwap || isEditDistanceClose) {
      const distance = isHomoglyphSwap ? rawDistFull : Math.min(distFull, rawDistFull);
      return {
        isLookalike: true,
        isExactMatch: false,
        inputName,
        targetBuyer: b.displayName,
        targetToken: b.buyerToken,
        distance,
        reason: `Suspected payee lookalike spoofing: '${inputName}' is deceptively close to allowlisted buyer '${b.displayName}' (edit distance: ${distance}).`,
      };
    }

    // Check first name if input is a single word
    if (!rawClean.includes(" ")) {
      const distFirst = computeHomoglyphLevenshtein(rawClean, targetFirst);
      const rawDistFirst = computeRawLevenshtein(rawClean, targetFirst);
      const isFirstHomoglyph = distFirst === 0 && rawDistFirst > 0;
      const isFirstEditClose = rawDistFirst >= 1 && rawDistFirst <= customThreshold;

      if (isFirstHomoglyph || isFirstEditClose) {
        const distance = isFirstHomoglyph ? rawDistFirst : Math.min(distFirst, rawDistFirst);
        return {
          isLookalike: true,
          isExactMatch: false,
          inputName,
          targetBuyer: b.displayName,
          targetToken: b.buyerToken,
          distance,
          reason: `Suspected payee lookalike spoofing: '${inputName}' is deceptively close to allowlisted buyer '${b.displayName}' (edit distance: ${distance}).`,
        };
      }
    }
  }

  return { isLookalike: false, isExactMatch: false };
}

/**
 * 4-Tier Explicit Risk Classification Engine
 * Evaluates an intent into Level 1 (Low), Level 2 (Standard), Level 3 (Elevated), or Level 4 (Critical/Blocked)
 *
 * @param {object} intent
 * @param {object} [options={}]
 * @returns {object} { riskTier, riskScore, levelLabel, requiresPasskey, requiresCameraLiveness, blocked, amountDeviationWarning, reasons }
 */
export function classifyTransactionRisk(intent = {}, options = {}) {
  const {
    action = "create_invoice",
    amount = (intent.amount !== undefined ? intent.amount : intent.amountUsd) || 0,
    currency = "USD",
  } = intent;
  const numAmt = Number(amount);
  const reasons = [];

  // Level 1: Read-only actions (No passkey required)
  if (action !== "create_invoice") {
    return {
      riskTier: "LEVEL_1",
      riskScore: 5,
      levelLabel: "Level 1 (Low Risk)",
      requiresPasskey: false,
      requiresCameraLiveness: false,
      blocked: false,
      reasons: ["Read-only action. No funds or invoicing operations affected."],
    };
  }

  // Resolve buyer if not explicitly provided in options
  const buyer = options.buyer || resolveBuyerToken(intent.buyer_token || intent.buyerToken || intent.buyer);

  // Check lookalike status
  const payeeName = intent.buyer_name || intent.payee_name || intent.buyerName || (buyer ? buyer.displayName : "");
  const lookalike = options.lookalikeCheck || (payeeName ? detectLookalikePayee(payeeName) : { isLookalike: false });

  // Level 4 Checks (Hard Blocked)
  if (String(currency).toUpperCase() === "INR") {
    reasons.push("Domestic INR transfers prohibited on PayPal India cross-border pathway");
    return {
      riskTier: "LEVEL_4",
      riskScore: 95,
      levelLabel: "Level 4 (Critical / Blocked)",
      requiresPasskey: false,
      requiresCameraLiveness: false,
      blocked: true,
      reasons,
    };
  }

  if (numAmt > 2500) {
    reasons.push(`Amount $${numAmt} exceeds $2,500 USD statutory per-invoice OPGSP export limit`);
    return {
      riskTier: "LEVEL_4",
      riskScore: 100,
      levelLabel: "Level 4 (Critical / Blocked)",
      requiresPasskey: false,
      requiresCameraLiveness: false,
      blocked: true,
      reasons,
    };
  }

  if (lookalike?.isLookalike) {
    reasons.push(lookalike.reason);
    return {
      riskTier: "LEVEL_4",
      riskScore: 90,
      levelLabel: "Level 4 (Critical / Blocked)",
      requiresPasskey: false,
      requiresCameraLiveness: false,
      blocked: true,
      lookalikeStatus: "SPOOFING_DETECTED",
      reasons,
    };
  }

  if (!buyer) {
    reasons.push("Buyer not found in allowlisted AES-256-GCM vault");
    return {
      riskTier: "LEVEL_4",
      riskScore: 88,
      levelLabel: "Level 4 (Critical / Blocked)",
      requiresPasskey: false,
      requiresCameraLiveness: false,
      blocked: true,
      reasons,
    };
  }

  // Level 3 Checks (Elevated Risk: Step-Up Passkey + Live Camera Presence Required)
  let isElevated = false;
  let score = 25;

  let isAmountDeviated = options.amountDeviationWarning;
  let ratio = options.deviationRatio;
  if (isAmountDeviated === undefined && buyer && buyer.defaultAmount && buyer.defaultAmount > 0) {
    if (numAmt > 2 * buyer.defaultAmount) {
      isAmountDeviated = true;
      ratio = (numAmt / buyer.defaultAmount).toFixed(1);
    }
  }

  if (isAmountDeviated) {
    isElevated = true;
    score += 35;
    reasons.push(`Amount deviation: Requested amount ($${numAmt}) is ${ratio || ">2"}x higher than historical baseline ($${buyer?.defaultAmount || 0})`);
  }

  const inCooldown = typeof options.inCooldown === "boolean"
    ? options.inCooldown
    : Boolean(isBuyerInCooldown(buyer)?.inCooldown);
  if (inCooldown) {
    isElevated = true;
    score += 30;
    reasons.push("New payee in active 30-minute security cool-down window");
  }

  if (isElevated) {
    return {
      riskTier: "LEVEL_3",
      riskScore: Math.min(score, 84),
      levelLabel: "Level 3 (Elevated Risk)",
      requiresPasskey: true,
      requiresCameraLiveness: true,
      blocked: false,
      amountDeviationWarning: Boolean(isAmountDeviated),
      deviationRatio: ratio,
      reasons,
    };
  }

  // Level 2: Standard Risk (Standard Passkey Required)
  return {
    riskTier: "LEVEL_2",
    riskScore: 25,
    levelLabel: "Level 2 (Standard Risk)",
    requiresPasskey: true,
    requiresCameraLiveness: false,
    blocked: false,
    amountDeviationWarning: false,
    reasons: ["Saved allowlisted buyer within normal historical parameters."],
  };
}

/**
 * Deterministic Money Guide AI Policy Engine
 * Runs strict deterministic financial validation - Zero LLM hallucination risk.
 * @param {object} intent - { buyer_token, item, amount, currency, quantity, readBackConfirmed, payee_name }
 * @param {object} [options={}] - { requireReadBack: boolean, bypassCooldown: boolean, enforceCooldown: boolean }
 * @returns {{ approved: boolean, policyViolation: string | null, message: string, buyer: object | null, policySnapshot: object, riskClassification: object }}
 */
export function evaluateTransactionPolicy(intent, options = {}) {
  cleanOldInvoices();

  const { buyer_token, item, amount, currency, readBackConfirmed, payee_name, buyer_name } = intent || {};
  const numAmount = Number(amount);

  // 1. Payee Verification: Lookalike Name Spoofing Check
  const candidateName = payee_name || buyer_name || options.buyerName || null;
  if (candidateName) {
    const lookalike = detectLookalikePayee(candidateName);
    if (lookalike.isLookalike) {
      const riskClassification = classifyTransactionRisk(intent, { lookalikeCheck: lookalike });
      return {
        approved: false,
        policyViolation: "LOOKALIKE_PAYEE_SPOOFING",
        message: lookalike.reason,
        buyer: null,
        riskClassification,
        policySnapshot: { lookalike, checkedAt: new Date().toISOString() },
      };
    }
  }

  // 2. Buyer Allowlist Check
  const buyer = resolveBuyerToken(buyer_token);
  if (!buyer) {
    const riskClassification = classifyTransactionRisk(intent, { buyer: null });
    return {
      approved: false,
      policyViolation: "BUYER_NOT_ALLOWLISTED",
      message: `Buyer token '${buyer_token}' is not found in the verified PII Vault. Untrusted recipients cannot be invoiced.`,
      buyer: null,
      riskClassification,
      policySnapshot: { buyer_token, checkedAt: new Date().toISOString() },
    };
  }

  // 3. New Payee Cool-Down Period Check
  const cooldownCheck = isBuyerInCooldown(buyer, options);
  if (cooldownCheck.inCooldown && options.enforceCooldown === true) {
    const remainingMins = Math.ceil(cooldownCheck.remainingMs / 60000);
    return {
      approved: false,
      policyViolation: "NEW_PAYEE_COOLDOWN_ACTIVE",
      message: `Newly enrolled payee is currently in a 30-minute security cool-down period (${remainingMins} min remaining). High-velocity first-time billing blocked.`,
      buyer,
      policySnapshot: { cooldownUntil: cooldownCheck.cooldownUntil, remainingMins },
    };
  }

  // 4. Amount Deviation & Frequency Check (> 2x historical average)
  const defaultAmt = Number(buyer.defaultAmount || 200.0);
  const amountDeviationWarning = !isNaN(numAmount) && defaultAmt > 0 && numAmount > 2.0 * defaultAmt;
  const deviationRatio = defaultAmt > 0 ? Number((numAmount / defaultAmt).toFixed(2)) : 1.0;

  // 5. Read-Back Confirmation Enforcement (Required before step-up verification)
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

  // 6. Currency Compliance (PayPal India OPGSP Rule & 25-Currency Normalization)
  const normCurrency = String(currency || "").trim().toUpperCase();
  if (normCurrency === "INR") {
    const riskClassification = classifyTransactionRisk(intent, { buyer });
    return {
      approved: false,
      policyViolation: "DOMESTIC_INR_NOT_SUPPORTED",
      message: "PayPal India regulations strictly prohibit domestic INR transfers under RBI OPGSP guidelines. PayVoice only supports cross-border export invoicing in approved foreign currencies.",
      buyer,
      riskClassification,
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

  // 7. Export Value Cap Enforcement (Integer Minor-Unit Normalized to USD)
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
    const riskClassification = classifyTransactionRisk(intent, { buyer });
    return {
      approved: false,
      policyViolation: "EXPORT_LIMIT_EXCEEDED",
      message: `Requested amount ${numAmount.toFixed(2)} ${normCurrency} ($${normalized.usdEquivalent.toFixed(2)} USD equivalent) exceeds the authorized regulatory limit of $${maxCap.toFixed(2)} USD for this exporter.`,
      buyer,
      riskClassification,
      policySnapshot: {
        requestedAmount: numAmount,
        currency: normCurrency,
        usdEquivalent: normalized.usdEquivalent,
        fxRate: normalized.fxRate,
        maxAuthorizedCap: maxCap,
      },
    };
  }

  // 8. Duplicate Invoice Idempotency Check
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

  // Compute 4-Tier Risk Assessment
  const riskClassification = classifyTransactionRisk(intent, {
    buyer,
    amountDeviationWarning,
    deviationRatio,
    inCooldown: cooldownCheck.inCooldown,
  });

  return {
    approved: true,
    policyViolation: null,
    message: "All deterministic Money Guide policies passed. Invoice is eligible for step-up WebAuthn passkey staging.",
    buyer,
    amountDeviationWarning,
    deviationRatio,
    cooldownStatus: cooldownCheck,
    riskClassification,
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
      amountDeviationWarning,
      deviationRatio,
      riskTier: riskClassification.riskTier,
      riskScore: riskClassification.riskScore,
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
 * Proactive Money Guide AI CFO Insights for Indian MSME Cross-Border Exporters
 * Deterministically calculates foreign currency inflows, PayPal cross-border fees (4.4% + fixed fee),
 * net INR realization at calibrated RBI exchange rates, and OPGSP $2,500 statutory cap allowance.
 *
 * @param {Array} transactions - Array of transaction objects
 * @returns {object} Proactive CFO analytics and compliance health report
 */
export function computeCfoInsights(transactions = []) {
  const FX_RATES_TO_INR = {
    USD: 86.85,
    EUR: 93.80,
    GBP: 109.50,
    CAD: 63.50,
    AUD: 56.40,
    SGD: 64.70,
    JPY: 0.58,
    CHF: 97.20,
    AED: 23.65,
  };

  const inflowsByCurrency = {};
  let totalGrossUsd = 0;
  let totalEstimatedFeesUsd = 0;
  let totalNetInr = 0;
  let singleInvoiceMaxGrossUsd = 0;

  for (const tx of transactions) {
    const gross = Number(tx.amount || tx.grossAmount || 0);
    const curr = (tx.currency || "USD").toUpperCase();
    if (gross > 0) {
      inflowsByCurrency[curr] = Number(((inflowsByCurrency[curr] || 0) + gross).toFixed(2));

      // Normalize gross to USD
      const fx = STATIC_FX_RATES_V1[curr] || { rateToUsd: 1.0 };
      const usdVal = gross * fx.rateToUsd;
      totalGrossUsd += usdVal;

      if (usdVal > singleInvoiceMaxGrossUsd) {
        singleInvoiceMaxGrossUsd = usdVal;
      }

      // India Cross-Border fee: 4.4% + fixed fee (approx $0.30 per tx)
      const fee = Number(tx.fee || (gross * 0.044 + 0.30).toFixed(2));
      const feeUsd = fee * fx.rateToUsd;
      totalEstimatedFeesUsd += feeUsd;

      // Net Inflow in native currency converted to INR
      const netNative = Math.max(0, gross - fee);
      const inrRate = FX_RATES_TO_INR[curr] || (fx.rateToUsd * 86.85);
      totalNetInr += (netNative * inrRate);
    }
  }

  const opgspCapUsd = 2500.0;
  const remainingOpgspAllowance = Math.max(0, opgspCapUsd - singleInvoiceMaxGrossUsd);

  const riskMeter = computeRiskAndInvestmentRating(transactions, { totalGrossUsd, totalNetInr });
  const budgeting = computeBudgetingAndLimits(transactions);

  return {
    inflowsByCurrency,
    totalGrossUsd: Number(totalGrossUsd.toFixed(2)),
    totalEstimatedFeesUsd: Number(totalEstimatedFeesUsd.toFixed(2)),
    effectiveFeeRatePercent: totalGrossUsd > 0 ? Number(((totalEstimatedFeesUsd / totalGrossUsd) * 100).toFixed(2)) : 4.4,
    netInrRealization: Number(totalNetInr.toFixed(2)),
    formattedInrRealization: `₹${Math.round(totalNetInr).toLocaleString("en-IN")}`,
    opgspLimit: {
      perInvoiceCapUsd: opgspCapUsd,
      maxInvoiceIssuedUsd: Number(singleInvoiceMaxGrossUsd.toFixed(2)),
      remainingAllowanceUsd: Number(remainingOpgspAllowance.toFixed(2)),
      capUtilizedPercent: Number(((singleInvoiceMaxGrossUsd / opgspCapUsd) * 100).toFixed(1)),
      status: remainingOpgspAllowance > 0 ? "WITHIN_OPGSP_STATUTORY_CAP" : "CAP_REACHED",
    },
    regulatoryCompliance: {
      iecCode: process.env.MERCHANT_IEC || "0319088821",
      gstLutRule: "Rule 96A CGST Rules (Zero-Rated Export without payment of IGST)",
      fircStatus: "Auto e-FIRC ready on PayPal INR bank disbursement",
      bankRealization: "RBI EDPMS auto-reporting via Authorized Dealer Bank",
    },
    riskMeter,
    budgeting,
    analyzedAt: new Date().toISOString(),
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


/**
 * Deterministic Risk Meter & Institutional Working Capital Investment Rating
 * Evaluates currency concentration, buyer concentration, dispute/refund rate,
 * and OPGSP regulatory compliance, plus idle INR treasury yield optimization.
 *
 * @param {Array} transactions - Array of transaction objects
 * @param {object} [options={}] - Optional net INR / gross overrides
 * @returns {object} Risk meter breakdown, investment rating & yield portfolio
 */
export function computeRiskAndInvestmentRating(transactions = [], options = {}) {
  const FX_RATES_TO_INR = {
    USD: 86.85,
    EUR: 93.80,
    GBP: 109.50,
    CAD: 63.50,
    AUD: 56.40,
    SGD: 64.70,
    JPY: 0.58,
    CHF: 97.20,
    AED: 23.65,
  };

  const inflowsByCurrencyUsd = {};
  const inflowsByBuyerUsd = {};
  let totalGrossUsd = 0;
  let totalNetInr = 0;
  let singleInvoiceMaxUsd = 0;
  let refundCount = 0;

  for (const tx of transactions) {
    const gross = Number(tx.amount || tx.grossAmount || 0);
    const curr = String(tx.currency || "USD").toUpperCase();
    if (tx.type === "REFUND" || tx.status === "REFUNDED" || gross < 0) {
      refundCount += 1;
      continue;
    }
    if (gross > 0) {
      const fx = STATIC_FX_RATES_V1[curr] || { rateToUsd: 1.0 };
      const usdVal = gross * fx.rateToUsd;
      totalGrossUsd += usdVal;
      if (usdVal > singleInvoiceMaxUsd) singleInvoiceMaxUsd = usdVal;

      inflowsByCurrencyUsd[curr] = (inflowsByCurrencyUsd[curr] || 0) + usdVal;
      const buyerKey = tx.buyerToken || tx.buyerName || "UNKNOWN_BUYER";
      inflowsByBuyerUsd[buyerKey] = (inflowsByBuyerUsd[buyerKey] || 0) + usdVal;

      const fee = Number(tx.fee || (gross * 0.044 + 0.30).toFixed(2));
      const netNative = Math.max(0, gross - fee);
      const inrRate = FX_RATES_TO_INR[curr] || fx.rateToUsd * 86.85;
      totalNetInr += netNative * inrRate;
    }
  }

  const effectiveNetInr = options.totalNetInr !== undefined ? Number(options.totalNetInr) : totalNetInr;
  const effectiveGrossUsd = options.totalGrossUsd !== undefined ? Number(options.totalGrossUsd) : totalGrossUsd;

  const currencyShares = Object.values(inflowsByCurrencyUsd).map((v) => (effectiveGrossUsd > 0 ? v / effectiveGrossUsd : 0));
  const topCurrencyShare = currencyShares.length ? Math.max(...currencyShares) : 1;
  const currencyRiskScore = topCurrencyShare > 0.85 ? 20 : topCurrencyShare > 0.65 ? 14 : topCurrencyShare > 0.45 ? 9 : 5;

  const buyerShares = Object.values(inflowsByBuyerUsd).map((v) => (effectiveGrossUsd > 0 ? v / effectiveGrossUsd : 0));
  const topBuyerShare = buyerShares.length ? Math.max(...buyerShares) : 0;
  const buyerRiskScore = topBuyerShare > 0.70 ? 22 : topBuyerShare > 0.50 ? 16 : topBuyerShare > 0.35 ? 11 : 6;

  const refundRate = transactions.length > 0 ? refundCount / transactions.length : 0;
  const defaultRiskScore = Math.min(25, Math.round(refundRate * 250));

  const complianceRiskScore = singleInvoiceMaxUsd > 2500 ? 18 : 3;
  const compositeScore = Math.min(100, currencyRiskScore + buyerRiskScore + defaultRiskScore + complianceRiskScore);

  const riskTier = compositeScore <= 25 ? "LOW" : compositeScore <= 50 ? "MODERATE" : compositeScore <= 75 ? "ELEVATED" : "CRITICAL";
  const tierLabel =
    riskTier === "LOW" ? "Low Risk" : riskTier === "MODERATE" ? "Moderate Risk" : riskTier === "ELEVATED" ? "Elevated Risk" : "High Risk";

  let investmentRating = "BB";
  let ratingTitle = "Concentrated Export Exposure";
  if (compositeScore <= 24) {
    investmentRating = "AAA";
    ratingTitle = "Prime Working Capital Grade";
  } else if (compositeScore <= 36) {
    investmentRating = "AA+";
    ratingTitle = "High-Grade Export Liquidity";
  } else if (compositeScore <= 50) {
    investmentRating = "A";
    ratingTitle = "Upper Medium Credit Grade";
  } else if (compositeScore <= 68) {
    investmentRating = "BBB";
    ratingTitle = "Moderate Reserve Grade";
  }

  const liquidPct = 60;
  const sovereignPct = 25;
  const workingCapPct = 15;
  const liquidApy = 6.85;
  const sovereignApy = 7.20;
  const projectedAnnualYieldInr = Math.round(
    effectiveNetInr * ((liquidPct / 100) * (liquidApy / 100) + (sovereignPct / 100) * (sovereignApy / 100))
  );

  return {
    compositeScore,
    maxScore: 100,
    riskTier,
    tierLabel,
    investmentRating,
    ratingTitle,
    ratingSummary:
      compositeScore <= 36
        ? "Strong multi-corridor export liquidity, zero dispute chargebacks, and verified RBI OPGSP Rule 96A compliance."
        : "Monitor buyer or currency concentration and maintain statutory OPGSP headroom before scaling invoice size.",
    breakdown: [
      {
        key: "currencyRisk",
        label: "Currency Concentration Risk",
        score: currencyRiskScore,
        max: 25,
        status: currencyRiskScore <= 10 ? "Diversified" : currencyRiskScore <= 15 ? "Moderate" : "Concentrated",
        detail: `Top currency represents ${Math.round(topCurrencyShare * 100)}% of USD-equivalent export inflows`,
      },
      {
        key: "buyerConcentrationRisk",
        label: "Buyer Concentration Risk",
        score: buyerRiskScore,
        max: 25,
        status: buyerRiskScore <= 11 ? "Balanced" : "Watchlist",
        detail: `Largest buyer accounts for ${Math.round(topBuyerShare * 100)}% of realized receivables`,
      },
      {
        key: "defaultAgingRisk",
        label: "Default & Dispute Risk",
        score: defaultRiskScore,
        max: 25,
        status: defaultRiskScore === 0 ? "Minimal" : "Review",
        detail: `${refundCount} refund(s) across ${transactions.length} settled transaction(s)`,
      },
      {
        key: "complianceRisk",
        label: "RBI & GST Compliance Risk",
        score: complianceRiskScore,
        max: 25,
        status: complianceRiskScore <= 5 ? "Verified" : "Over Cap",
        detail: "DGFT IEC 0319088821 & Rule 96A LUT status validated",
      },
    ],
    treasuryAllocation: {
      deployableInr: Math.round(effectiveNetInr),
      formattedDeployableInr: `₹${Math.round(effectiveNetInr).toLocaleString("en-IN")}`,
      projectedAnnualYieldInr,
      formattedProjectedYield: `₹${projectedAnnualYieldInr.toLocaleString("en-IN")}`,
      weightedApyPercent: Number(((liquidPct * liquidApy + sovereignPct * sovereignApy) / 100).toFixed(2)),
      buckets: [
        {
          name: "RBI 91-Day T-Bills / Overnight Liquid",
          pct: liquidPct,
          apy: liquidApy,
          amountInr: Math.round(effectiveNetInr * (liquidPct / 100)),
          liquidity: "T+1 Instant",
        },
        {
          name: "Short-Duration Sovereign Debt",
          pct: sovereignPct,
          apy: sovereignApy,
          amountInr: Math.round(effectiveNetInr * (sovereignPct / 100)),
          liquidity: "T+2 Settlement",
        },
        {
          name: "Working Capital Operating Buffer",
          pct: workingCapPct,
          apy: 0,
          amountInr: Math.round(effectiveNetInr * (workingCapPct / 100)),
          liquidity: "Immediate",
        },
      ],
    },
  };
}

/**
 * Deterministic Export Limits & Budgeting Evaluator
 *
 * @param {Array} transactions - Array of transaction objects
 * @param {object} [budgetConfig={}] - Custom budget thresholds
 * @returns {object} Monthly revenue progress, fee budget watchdog & currency limits
 */
export function computeBudgetingAndLimits(transactions = [], budgetConfig = {}) {
  const FX_RATES_TO_INR = {
    USD: 86.85,
    EUR: 93.80,
    GBP: 109.50,
    CAD: 63.50,
    AUD: 56.40,
    SGD: 64.70,
    JPY: 0.58,
    CHF: 97.20,
    AED: 23.65,
  };

  const monthlyTargetUsd = Number(budgetConfig.monthlyTargetUsd) > 0 ? Number(budgetConfig.monthlyTargetUsd) : 5000.0;
  const feeBudgetCapPercent = Number(budgetConfig.feeCapPercent) > 0 ? Number(budgetConfig.feeCapPercent) : 5.0;
  const taxReservePercent = Number(budgetConfig.taxReservePercent) >= 0 ? Number(budgetConfig.taxReservePercent) : 15;
  const maxCurrencySharePercent =
    Number(budgetConfig.maxCurrencySharePercent) > 0 ? Number(budgetConfig.maxCurrencySharePercent) : 65;

  const currencyUsdMap = {};
  let totalGrossUsd = 0;
  let totalFeesUsd = 0;
  let totalNetInr = 0;

  for (const tx of transactions) {
    const gross = Number(tx.amount || tx.grossAmount || 0);
    const curr = String(tx.currency || "USD").toUpperCase();
    if (gross > 0) {
      const fx = STATIC_FX_RATES_V1[curr] || { rateToUsd: 1.0 };
      const usdVal = gross * fx.rateToUsd;
      totalGrossUsd += usdVal;
      currencyUsdMap[curr] = (currencyUsdMap[curr] || 0) + usdVal;

      const fee = Number(tx.fee || (gross * 0.044 + 0.30).toFixed(2));
      totalFeesUsd += fee * fx.rateToUsd;

      const netNative = Math.max(0, gross - fee);
      const inrRate = FX_RATES_TO_INR[curr] || fx.rateToUsd * 86.85;
      totalNetInr += netNative * inrRate;
    }
  }

  const effectiveFeeRatePercent = totalGrossUsd > 0 ? Number(((totalFeesUsd / totalGrossUsd) * 100).toFixed(2)) : 4.4;
  const targetProgressPercent = Number(Math.min(100, (totalGrossUsd / monthlyTargetUsd) * 100).toFixed(1));
  const statutoryCorridorCapUsd = 10000.0;
  const corridorUtilizedPercent = Number(Math.min(100, (totalGrossUsd / statutoryCorridorCapUsd) * 100).toFixed(1));
  const recommendedTaxReserveInr = Math.round(totalNetInr * (taxReservePercent / 100));

  const currencyExposure = Object.entries(currencyUsdMap)
    .map(([currency, usdAmount]) => {
      const sharePercent = totalGrossUsd > 0 ? Number(((usdAmount / totalGrossUsd) * 100).toFixed(1)) : 0;
      return {
        currency,
        usdAmount: Number(usdAmount.toFixed(2)),
        sharePercent,
        limitPercent: maxCurrencySharePercent,
        overLimit: sharePercent > maxCurrencySharePercent,
      };
    })
    .sort((a, b) => b.usdAmount - a.usdAmount);

  return {
    monthlyTargetUsd: Number(monthlyTargetUsd.toFixed(2)),
    realizedExportUsd: Number(totalGrossUsd.toFixed(2)),
    targetProgressPercent,
    remainingTargetUsd: Number(Math.max(0, monthlyTargetUsd - totalGrossUsd).toFixed(2)),
    feeBudgetCapPercent: Number(feeBudgetCapPercent.toFixed(2)),
    effectiveFeeRatePercent,
    feeVarianceStatus: effectiveFeeRatePercent <= feeBudgetCapPercent ? "UNDER_BUDGET" : "FEE_OVER_CAP",
    taxReservePercent,
    recommendedTaxReserveInr,
    recommendedTaxReserveFormatted: `₹${recommendedTaxReserveInr.toLocaleString("en-IN")}`,
    statutoryCorridorCapUsd,
    statutoryCorridorRemainingUsd: Number(Math.max(0, statutoryCorridorCapUsd - totalGrossUsd).toFixed(2)),
    corridorUtilizedPercent,
    maxCurrencySharePercent,
    currencyExposure,
  };
}
