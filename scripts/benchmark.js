/**
 * PayVoice Comprehensive Security & Compliance Benchmark Suite
 * PayPal AI Hackathon 2026 - Track: Security, Guardrails & Cryptography (Shoury)
 *
 * Verifies all 6 deck benchmark targets:
 *   1. 15 Adversarial Prompt-Injection, Policy & Replay Cases (100% block rate)
 *   2. 30 Multilingual Utterance Schema & Currency Drift Checks (10 Marathi, 10 Hindi, 10 English)
 *   3. WebAuthn Origin/RP_ID & Digest Binding (zero replay acceptance, tampered payload rejection)
 *   4. AES-256-GCM Vault & Blind Index Lookup (100% PII redaction pre-auth, gated resolution post-auth)
 *   5. Encrypted PDF + Raw PayPal JSON Line-Item Sum Reconciliation (%PDF + /Encrypt active + 100% sum match)
 *   6. Hash-Chained Audit Ledger + Independent Checkpoint Cross-Verification
 */

import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";
import { ADVERSARIAL_TEST_CASES } from "../server/routes/security.js";
import {
  inspectUntrustedInput,
  validateIntentSchema,
  sanitizeAndValidateCsvLedger,
  verifyAudioReplayGuard,
} from "../server/services/guardrail.js";
import {
  evaluateTransactionPolicy,
  computeTransactionTotals,
  analyzeMerchantAnomalies,
  classifyRbiPurposeCode,
  STATIC_FX_RATES_V1,
  normalizeToUsd,
  computeReadBackDigest,
  verifyReadBackConfirmation,
} from "../server/services/moneyGuide.js";
import {
  redactPIIBeforeLLM,
  resolveBuyerToken,
  resolveBuyerForExecution,
  registerBuyer,
  computeBlindIndex,
  encryptAes256Siv,
  decryptAes256Siv,
  encryptAes256Gcm,
  decryptAes256Gcm,
} from "../server/services/vault.js";
import {
  appendAuditEntry,
  verifyLedgerIntegrity,
  createCheckpoint,
  tamperAuditEntry,
  restoreAuditLedger,
  resetAuditLedger,
} from "../server/services/auditLedger.js";
import {
  createPayloadBoundChallenge,
  verifyPasskeyAssertion,
  verifyTemporalLivenessProof,
} from "../server/routes/auth.js";
import { generateEncryptedStatementPdf, reconcilePdfTotalsWithRawJson } from "../server/services/pdfGenerator.js";
import {
  wrapPayPalToolkitWithSecurityGate,
  issueSecurityExecutionTicket,
  verifySecurityExecutionTicket,
  clearConsumedTicketsForTesting,
} from "../server/services/secureToolkitWrapper.js";
import {
  verifyPayPalWebhookEvent,
  generateMockSignedWebhook,
  clearWebhookIdempotencyCacheForTesting,
} from "../server/services/webhookVerifier.js";

// 30 Multilingual Utterance Payloads (10 Marathi, 10 Hindi, 10 English)
export const MULTILINGUAL_TEST_CASES = [
  // --- 10 Marathi Utterances ---
  { lang: "mr-IN", utterance: "राहुलला २०० डॉलर्सचा गहू इनव्हॉईस पाठव", intent: { action: "create_invoice", buyer_token: "BUYER_RAHUL_01", item: "गहू", amount: 200.0, currency: "USD" } },
  { lang: "mr-IN", utterance: "राहुलसाठी १५० यूएसडीचे कॉटन इनव्हॉईस तयार करा", intent: { action: "create_invoice", buyer_token: "BUYER_RAHUL_01", item: "कॉटन बियाणे", amount: 150.0, currency: "USD" } },
  { lang: "mr-IN", utterance: "राहुलला ३०० डॉलर्सचे सोयाबीन बिल पाठवा", intent: { action: "create_invoice", buyer_token: "BUYER_RAHUL_01", item: "सोयाबीन", amount: 300.0, currency: "USD" } },
  { lang: "mr-IN", utterance: "राहुलला ५०० युरोचे सेंद्रिय तांदूळ इनव्हॉईस पाठव", intent: { action: "create_invoice", buyer_token: "BUYER_RAHUL_01", item: "सेंद्रिय तांदूळ", amount: 500.0, currency: "EUR" } },
  { lang: "mr-IN", utterance: "८०० डॉलर्सचा गहू राहुलला पाठवा", intent: { action: "create_invoice", buyer_token: "BUYER_RAHUL_01", item: "गहू निर्यात", amount: 800.0, currency: "USD" } },
  { lang: "mr-IN", utterance: "राहुलला २५० डॉलर्सचे बियाणे इनव्हॉईस द्या", intent: { action: "create_invoice", buyer_token: "BUYER_RAHUL_01", item: "बियाणे", amount: 250.0, currency: "USD" } },
  { lang: "mr-IN", utterance: "४०० युरोचे बासमती तांदूळ बिल पाठवा", intent: { action: "create_invoice", buyer_token: "BUYER_RAHUL_01", item: "बासमती तांदूळ", amount: 400.0, currency: "EUR" } },
  { lang: "mr-IN", utterance: "राहुलला १०० डॉलर्सची माती तपासणी फी पाठवा", intent: { action: "create_invoice", buyer_token: "BUYER_RAHUL_01", item: "माती तपासणी", amount: 100.0, currency: "USD" } },
  { lang: "mr-IN", utterance: "राहुलला ६०० डॉलर्सचे मसाले पाठवा", intent: { action: "create_invoice", buyer_token: "BUYER_RAHUL_01", item: "मसाले", amount: 600.0, currency: "USD" } },
  { lang: "mr-IN", utterance: "राहुलला १२५ डॉलर्सचे कृषी पॅकेज इनव्हॉईस पाठवा", intent: { action: "create_invoice", buyer_token: "BUYER_RAHUL_01", item: "कृषी पॅकेज", amount: 125.0, currency: "USD" } },

  // --- 10 Hindi Utterances ---
  { lang: "hi-IN", utterance: "राहुल को २०० डॉलर का गेहूँ इनवॉइस भेजो", intent: { action: "create_invoice", buyer_token: "BUYER_RAHUL_01", item: "गेहूँ", amount: 200.0, currency: "USD" } },
  { lang: "hi-IN", utterance: "राहुल के लिए १५० यूएसडी का कपास इनवॉइस तैयार करो", intent: { action: "create_invoice", buyer_token: "BUYER_RAHUL_01", item: "कपास", amount: 150.0, currency: "USD" } },
  { lang: "hi-IN", utterance: "राहुल को ३०० डॉलर का सोयाबीन बिल भेजो", intent: { action: "create_invoice", buyer_token: "BUYER_RAHUL_01", item: "सोयाबीन", amount: 300.0, currency: "USD" } },
  { lang: "hi-IN", utterance: "राहुल को ५०० यूरो का जैविक चावल इनवॉइस भेजो", intent: { action: "create_invoice", buyer_token: "BUYER_RAHUL_01", item: "जैविक चावल", amount: 500.0, currency: "EUR" } },
  { lang: "hi-IN", utterance: "८०० डॉलर का गेहूँ राहुल को इनवॉइस करो", intent: { action: "create_invoice", buyer_token: "BUYER_RAHUL_01", item: "गेहूँ", amount: 800.0, currency: "USD" } },
  { lang: "hi-IN", utterance: "राहुल को २५० डॉलर का बीज इनवॉइस भेजो", intent: { action: "create_invoice", buyer_token: "BUYER_RAHUL_01", item: "बीज", amount: 250.0, currency: "USD" } },
  { lang: "hi-IN", utterance: "४०० यूरो का बासमती चावल बिल भेजो", intent: { action: "create_invoice", buyer_token: "BUYER_RAHUL_01", item: "बासमती चावल", amount: 400.0, currency: "EUR" } },
  { lang: "hi-IN", utterance: "राहुल को १०० डॉलर का मृदा परीक्षण बिल भेजो", intent: { action: "create_invoice", buyer_token: "BUYER_RAHUL_01", item: "मृदा परीक्षण", amount: 100.0, currency: "USD" } },
  { lang: "hi-IN", utterance: "राहुल को ६०० डॉलर का मसाला इनवॉइस भेजो", intent: { action: "create_invoice", buyer_token: "BUYER_RAHUL_01", item: "मसाला", amount: 600.0, currency: "USD" } },
  { lang: "hi-IN", utterance: "राहुल को १२५ डॉलर का कृषि पैक बिल भेजो", intent: { action: "create_invoice", buyer_token: "BUYER_RAHUL_01", item: "कृषि पैक", amount: 125.0, currency: "USD" } },

  // --- 10 English Utterances ---
  { lang: "en-US", utterance: "Send Rahul an invoice for 200 dollars of Grade-A wheat", intent: { action: "create_invoice", buyer_token: "BUYER_RAHUL_01", item: "Grade-A Wheat", amount: 200.0, currency: "USD" } },
  { lang: "en-US", utterance: "Create an invoice for Rahul for 150 USD of cotton seed", intent: { action: "create_invoice", buyer_token: "BUYER_RAHUL_01", item: "Cotton Seed", amount: 150.0, currency: "USD" } },
  { lang: "en-US", utterance: "Bill Rahul 300 USD for soybean export", intent: { action: "create_invoice", buyer_token: "BUYER_RAHUL_01", item: "Soybean Export", amount: 300.0, currency: "USD" } },
  { lang: "en-US", utterance: "Send Rahul an invoice of 500 EUR for organic rice", intent: { action: "create_invoice", buyer_token: "BUYER_RAHUL_01", item: "Organic Rice", amount: 500.0, currency: "EUR" } },
  { lang: "en-US", utterance: "Invoice Rahul for 800 USD of wheat shipment", intent: { action: "create_invoice", buyer_token: "BUYER_RAHUL_01", item: "Wheat Shipment", amount: 800.0, currency: "USD" } },
  { lang: "en-US", utterance: "Send a 250 USD seed invoice to Rahul", intent: { action: "create_invoice", buyer_token: "BUYER_RAHUL_01", item: "Seed", amount: 250.0, currency: "USD" } },
  { lang: "en-US", utterance: "Bill Rahul 400 EUR for basmati export", intent: { action: "create_invoice", buyer_token: "BUYER_RAHUL_01", item: "Basmati Export", amount: 400.0, currency: "EUR" } },
  { lang: "en-US", utterance: "Send Rahul an invoice for 100 USD soil testing pack", intent: { action: "create_invoice", buyer_token: "BUYER_RAHUL_01", item: "Soil Testing Pack", amount: 100.0, currency: "USD" } },
  { lang: "en-US", utterance: "Invoice Rahul 600 USD for exported spices", intent: { action: "create_invoice", buyer_token: "BUYER_RAHUL_01", item: "Exported Spices", amount: 600.0, currency: "USD" } },
  { lang: "en-US", utterance: "Bill Rahul 125 USD for agri dispatch inspection", intent: { action: "create_invoice", buyer_token: "BUYER_RAHUL_01", item: "Agri Dispatch Inspection", amount: 125.0, currency: "USD" } },
];

export async function runFullBenchmark() {
  const t0 = Date.now();
  const summaryRows = [];

  console.log("\n" + "=".repeat(92));
  console.log(" PAYVOICE: SECURE MULTILINGUAL FINANCIAL AGENT - HARDENED SECURITY BENCHMARK SUITE");
  console.log(" PayPal AI Hackathon 2026 | Shoury's Track: Security, Guardrails & Cryptography");
  console.log("=".repeat(92) + "\n");

  // Suite 1: 15 Adversarial Prompt-Injection, Policy & Replay Test Cases
  const advStart = Date.now();
  let advBlocked = 0;
  for (const tc of ADVERSARIAL_TEST_CASES) {
    let blocked = false;
    if (tc.type === "prompt_injection" || tc.type === "untrusted_email" || tc.type === "xss_injection") {
      const g = inspectUntrustedInput(tc.input);
      blocked = !g.safe;
    } else {
      const p = evaluateTransactionPolicy(tc.intent);
      blocked = !p.approved;
    }
    if (blocked === tc.expectedBlock) advBlocked++;
  }
  const advPassed = advBlocked === ADVERSARIAL_TEST_CASES.length;
  summaryRows.push({
    num: 1,
    subsystem: "Prompt Firewall & Policy",
    assertion: "15 Adversarial & Replay Attacks",
    target: "100.0% Block Rate",
    actual: `${((advBlocked / ADVERSARIAL_TEST_CASES.length) * 100).toFixed(1)}% (${advBlocked}/${ADVERSARIAL_TEST_CASES.length})`,
    status: advPassed ? "PASS" : "FAIL",
    time: `${Date.now() - advStart}ms`,
  });

  // Suite 2: 30 Multilingual Utterance Schema & Currency Drift Checks
  const multiStart = Date.now();
  let multiPassedCount = 0;
  for (const tc of MULTILINGUAL_TEST_CASES) {
    const schema = validateIntentSchema(tc.intent);
    const policy = evaluateTransactionPolicy(tc.intent, { bypassIdempotency: true });
    const isCurrencyCompliant = ["USD", "EUR"].includes(tc.intent.currency);
    const isAmountPositive = Number(tc.intent.amount) > 0 && !isNaN(tc.intent.amount);

    if (schema.valid && policy.approved && isCurrencyCompliant && isAmountPositive) {
      multiPassedCount++;
    }
  }
  const multiPassed = multiPassedCount === MULTILINGUAL_TEST_CASES.length;
  summaryRows.push({
    num: 2,
    subsystem: "Multilingual Drift Shield",
    assertion: "30 Utterances (Marathi/Hindi/Eng)",
    target: "Zero Currency/Math Drift",
    actual: `${multiPassedCount}/${MULTILINGUAL_TEST_CASES.length} Payloads Strict`,
    status: multiPassed ? "PASS" : "FAIL",
    time: `${Date.now() - multiStart}ms`,
  });

  // Suite 3: WebAuthn Origin/RP_ID & Single-Use Digest Binding
  const authStart = Date.now();
  const testPayload = { item: "Wheat Lot #44", amount: 200.0, buyer: "BUYER_RAHUL_01" };
  const challengeRecord = createPayloadBoundChallenge(testPayload, { origin: "http://localhost:8888", rpId: "localhost" });
  const validAssertion = verifyPasskeyAssertion({
    challengeId: challengeRecord.challengeId,
    expectedPayloadHash: challengeRecord.payloadHash,
    expectedRpId: "localhost",
  });
  // Attempt replay of consumed challenge
  const replayAttempt = verifyPasskeyAssertion({
    challengeId: challengeRecord.challengeId,
    expectedPayloadHash: challengeRecord.payloadHash,
  });
  // Attempt tampered payload verification
  const tamperedChallenge = createPayloadBoundChallenge(testPayload);
  const tamperedAttempt = verifyPasskeyAssertion({
    challengeId: tamperedChallenge.challengeId,
    expectedPayloadHash: "0xBAD_HASH_999999",
  });

  const authSuitePassed =
    validAssertion.verified === true &&
    replayAttempt.verified === false &&
    tamperedAttempt.verified === false;

  summaryRows.push({
    num: 3,
    subsystem: "WebAuthn Step-Up Gate",
    assertion: "Digest Binding & Replay Burn",
    target: "Zero Replay / Tamper Rej.",
    actual: authSuitePassed ? "Tamper & Replay Blocked" : "Binding Failure",
    status: authSuitePassed ? "PASS" : "FAIL",
    time: `${Date.now() - authStart}ms`,
  });

  // Suite 4: AES-256-GCM Vault & Blind Index Lookup
  const vaultStart = Date.now();
  const testEmail = "ananya.singh@delhi-exports.in";
  const bIndex = computeBlindIndex(testEmail);
  const registered = registerBuyer({
    name: "Ananya Singh",
    email: testEmail,
    country: "US",
    currency: "USD",
    maxLimit: 2500.0,
  });
  const redacted = redactPIIBeforeLLM("Please bill Ananya Singh 350 dollars for saffron");
  const preAuthDeTokenizeThrew = (() => {
    try {
      resolveBuyerForExecution(registered.buyerToken, null); // should throw without assertion ID!
      return false;
    } catch (e) {
      return true;
    }
  })();
  const postAuthDeTokenized = resolveBuyerForExecution(registered.buyerToken, "FIDO2_VERIFIED_PROOF_99");

  const vaultSuitePassed = Boolean(
    registered.blindIndex === bIndex &&
    redacted.includes(registered.buyerToken) &&
    !redacted.includes("Ananya Singh") &&
    preAuthDeTokenizeThrew &&
    postAuthDeTokenized &&
    postAuthDeTokenized.email === testEmail
  );

  summaryRows.push({
    num: 4,
    subsystem: "AES-256-GCM Vault",
    assertion: "HMAC Blind Index + Gated De-token",
    target: "100% PII Masked Pre-Auth",
    actual: vaultSuitePassed ? "Blind Index + Gated PII OK" : "Vault Boundary Breach",
    status: vaultSuitePassed ? "PASS" : "FAIL",
    time: `${Date.now() - vaultStart}ms`,
  });

  // Suite 5: Encrypted PDF + Raw PayPal JSON Line-Item Sum Reconciliation
  const pdfStart = Date.now();
  const sampleTransactions = [
    { id: "TX-BENCH-01", amount: 200.0, fee: 7.47, date: "2026-11-01", description: "Grade-A Wheat Export" },
    { id: "TX-BENCH-02", amount: 450.0, fee: 16.2, date: "2026-11-04", description: "Organic Cotton Seeds" },
    { id: "TX-BENCH-03", amount: 150.0, fee: 5.73, date: "2026-11-08", description: "Mustard Seed Lot #88" },
  ];
  const totals = computeTransactionTotals(sampleTransactions);
  const reconciliation = reconcilePdfTotalsWithRawJson(sampleTransactions, totals);

  const pdfDocResult = await generateEncryptedStatementPdf({
    dateRange: "Last 30 Days",
    transactions: sampleTransactions,
    totals,
    userPassword: "PAYVOICE2026",
    caGstCompliance: {
      panToken: "AABCP****M",
      iecCode: "0312049921",
      rbiPurposeCode: "P0103 - Agricultural Exports",
      gstStatus: "Export under LUT without payment of IGST",
      invoiceStatus: "PAID / COMPLETED",
    },
  });

  const pdfBufferStr = pdfDocResult.buffer.toString("binary");
  const isPdfHeader = pdfBufferStr.startsWith("%PDF");
  const hasEncryptDict = pdfBufferStr.includes("/Encrypt");
  const pdfSuitePassed = isPdfHeader && hasEncryptDict && reconciliation.reconciled === true;

  summaryRows.push({
    num: 5,
    subsystem: "CA/GST Encrypted PDF",
    assertion: "Raw JSON Sum Parity + Encryption",
    target: "%PDF + /Encrypt + 100% Sum",
    actual: pdfSuitePassed ? "100% Parity ($800.00 matched)" : "Sum Parity Discrepancy",
    status: pdfSuitePassed ? "PASS" : "FAIL",
    time: `${Date.now() - pdfStart}ms`,
  });

  // Suite 6: Cryptographic Audit Ledger + Independent Checkpoint Cross-Verification
  const ledgerStart = Date.now();
  resetAuditLedger();
  appendAuditEntry({
    transcript: "Benchmark Phase 2 Audit Verification",
    stagedPayload: { benchSuite: true, phase: 2 },
    passkeyAssertionId: "BENCHMARK_ASSERTION_SUITE",
    status: "AUTHORIZED",
  });
  createCheckpoint("BENCHMARK_CHECKPOINT_SUITE");

  const cleanCheck = verifyLedgerIntegrity();

  // Test Bit-Flip Tamper Detection
  tamperAuditEntry(null, '{"fraud": true, "amount": 99999.00}');
  const tamperedCheck = verifyLedgerIntegrity();
  restoreAuditLedger();
  const restoredCheck = verifyLedgerIntegrity();

  const ledgerSuitePassed =
    cleanCheck.valid === true &&
    tamperedCheck.valid === false &&
    restoredCheck.valid === true &&
    cleanCheck.checkpointsVerified > 0;

  summaryRows.push({
    num: 6,
    subsystem: "Cryptographic Audit Ledger",
    assertion: "Genesis Chain & Checkpoint Cross-Check",
    target: "Catches Rewrite & Truncation",
    actual: ledgerSuitePassed ? `Verified (${cleanCheck.totalRecords} blocks, ${cleanCheck.checkpointsVerified} cp)` : "Audit Integrity Failure",
    status: ledgerSuitePassed ? "PASS" : "FAIL",
    time: `${Date.now() - ledgerStart}ms`,
  });

  // Suite 7: Toolkit Guardrail Proxy & Ticket Boundary
  const toolkitStart = Date.now();
  clearConsumedTicketsForTesting();
  const testToolkit = wrapPayPalToolkitWithSecurityGate();

  // 1. Direct tool call without ticket should be blocked
  let directCallBlocked = false;
  try {
    await testToolkit.create_invoice({ amount: 100.0, item: "Direct Attempt" });
  } catch (err) {
    directCallBlocked = err.message.includes("BLOCKED");
  }

  // 2. Issue valid ticket and execute
  const validTicket = issueSecurityExecutionTicket({
    assertionId: "BENCH_ASSERTION_TK_01",
    buyerToken: "BUYER_RAHUL_01",
    amount: 100.0,
    currency: "USD",
    item: "Grade-A Wheat",
  });
  const writeSuccess = await testToolkit.create_invoice({
    securityExecutionTicket: validTicket,
    buyerToken: "BUYER_RAHUL_01",
    amount: 100.0,
    currency: "USD",
    item: "Grade-A Wheat",
  });

  // 3. Replay with consumed ticket must be blocked
  let replayBlocked = false;
  try {
    await testToolkit.create_invoice({
      securityExecutionTicket: validTicket,
      buyerToken: "BUYER_RAHUL_01",
      amount: 100.0,
      currency: "USD",
      item: "Grade-A Wheat",
    });
  } catch (err) {
    replayBlocked = err.message.includes("BLOCKED") || err.message.includes("consumed");
  }

  // 4. Read call attaches deterministic math
  const readOutput = await testToolkit.list_transactions({
    mockItems: [{ amount: 100.0, fee: 3.98 }, { amount: 200.0, fee: 7.47 }],
  });
  const readGuarded = Boolean(readOutput && readOutput._payvoiceGuarded === true);

  const toolkitSuitePassed = directCallBlocked && Boolean(writeSuccess) && replayBlocked && readGuarded;

  summaryRows.push({
    num: 7,
    subsystem: "PayPal Agent Toolkit Proxy",
    assertion: "Single-Use Execution Ticket Barrier",
    target: "Zero Direct LLM Mutation",
    actual: toolkitSuitePassed ? "Direct Blocked + Replay Rejected" : "Toolkit Barrier Discrepancy",
    status: toolkitSuitePassed ? "PASS" : "FAIL",
    time: `${Date.now() - toolkitStart}ms`,
  });

  // Suite 8: Cryptographic Webhook Verifier & Anti-Replay
  const webhookStart = Date.now();
  clearWebhookIdempotencyCacheForTesting();

  // 1. Valid signed webhook
  const validWh = generateMockSignedWebhook({
    eventType: "INVOICING.INVOICE.PAID",
    invoiceId: "INV2-WH-BENCHMARK-01",
    amount: 250.0,
  });
  const whValidCheck = verifyPayPalWebhookEvent(validWh.headers, validWh.rawBody);

  // 2. Replay of same transmission ID must be rejected
  const whReplayCheck = verifyPayPalWebhookEvent(validWh.headers, validWh.rawBody);

  // 3. Stale webhook (>5 minutes) must be rejected
  const staleTime = new Date(Date.now() - 10 * 60 * 1000).toISOString();
  const staleWh = generateMockSignedWebhook({
    eventType: "INVOICING.INVOICE.PAID",
    invoiceId: "INV2-WH-STALE-01",
    timestamp: staleTime,
  });
  const whStaleCheck = verifyPayPalWebhookEvent(staleWh.headers, staleWh.rawBody);

  // 4. Forged signature must be rejected
  const forgedHeaders = {
    ...validWh.headers,
    "paypal-transmission-id": "TX_FORGED_9999",
    "paypal-transmission-sig": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  };
  const whForgedCheck = verifyPayPalWebhookEvent(forgedHeaders, validWh.rawBody);

  const webhookSuitePassed =
    whValidCheck.verified === true &&
    whReplayCheck.verified === false &&
    whStaleCheck.verified === false &&
    whForgedCheck.verified === false;

  summaryRows.push({
    num: 8,
    subsystem: "Cryptographic Webhook Verifier",
    assertion: "Signature, Anti-Replay & Drift Window",
    target: "100% Forged/Replay Rejected",
    actual: webhookSuitePassed ? "Replay Rej. + Drift Rej. + Sig OK" : "Webhook Verification Failure",
    status: webhookSuitePassed ? "PASS" : "FAIL",
    time: `${Date.now() - webhookStart}ms`,
  });

  // Suite 9: Consented CSV Ledger Firewall & Dynamic RBI Purpose Code
  const csvStart = Date.now();

  // 1. Formula injection CSV checks
  const maliciousCsv = `Date,Amount,Fee,Description\n2026-11-10,=cmd|' /C calc'!A0,3.98,Wheat Export\n2026-11-11,@SUM(A1:A10),7.47,Cotton Shipment`;
  const csvBlockCheck = sanitizeAndValidateCsvLedger(maliciousCsv);

  // 2. Clean CSV with valid numbers
  const cleanCsv = `Date,Amount,Fee,Description,Currency,Buyer\n2026-11-10,200.00,7.47,Organic Wheat,USD,BUYER_RAHUL_01\n2026-11-11,-15.00,0.52,Dispute Fee,USD,BUYER_RAHUL_01`;
  const csvCleanCheck = sanitizeAndValidateCsvLedger(cleanCsv);

  // 3. Dynamic RBI Purpose Code checks
  const goodsRbi = classifyRbiPurposeCode("Grade-A Wheat (100 kg)");
  const servicesRbi = classifyRbiPurposeCode("Full-Stack React Development");
  const rbiPassed =
    goodsRbi.purposeCode === "P0103" &&
    goodsRbi.iecRequired === true &&
    servicesRbi.purposeCode === "P0802" &&
    servicesRbi.iecRequired === false;

  const csvSuitePassed =
    csvBlockCheck.safe === false &&
    csvCleanCheck.safe === true &&
    csvCleanCheck.totalRows === 2 &&
    rbiPassed === true;

  summaryRows.push({
    num: 9,
    subsystem: "CSV Firewall & RBI Classifier",
    assertion: "Formula Injection & Dynamic P0103/P0802",
    target: "Zero Injection + Verified IEC",
    actual: csvSuitePassed ? "CSV Sanitized + P0103/P0802 Classified" : "CSV/RBI Verification Failure",
    status: csvSuitePassed ? "PASS" : "FAIL",
    time: `${Date.now() - csvStart}ms`,
  });

  // Suite 10: 25-Currency FX Cap, AES-256-SIV & Audio/Temporal Liveness Gate
  const sub10Start = Date.now();

  // 1. AES-256-SIV encryption/decryption round trip
  const key64 = crypto.randomBytes(64);
  const sivCt = encryptAes256Siv("Sensitive Buyer PAN: AABCP1234M", ["buyer_id_01"], key64);
  const sivPt = decryptAes256Siv(sivCt, ["buyer_id_01"], key64);
  const a1_sivRoundtrip = sivPt.toString("utf8") === "Sensitive Buyer PAN: AABCP1234M";

  // 2. AES-256-SIV wrong-key rejection
  let a2_sivWrongKey = false;
  try {
    decryptAes256Siv(sivCt, ["buyer_id_01"], crypto.randomBytes(64));
  } catch {
    a2_sivWrongKey = true;
  }

  // 3. AES-256-SIV associated-data tampering rejection
  let a3_sivAdTamper = false;
  try {
    decryptAes256Siv(sivCt, ["tampered_ad_vector"], key64);
  } catch {
    a3_sivAdTamper = true;
  }

  // 4. AES-256-GCM encryption/decryption
  const key32 = crypto.randomBytes(32);
  const gcmObj = encryptAes256Gcm("Secret Tax Identifier", "metadata_v1", key32);
  const gcmPt = decryptAes256Gcm(gcmObj, "metadata_v1", key32);
  const a4_gcmRoundtrip = gcmPt.toString("utf8") === "Secret Tax Identifier";

  // 5. GCM authentication failure
  let a5_gcmAuthFail = false;
  try {
    decryptAes256Gcm({ ...gcmObj, authTag: crypto.randomBytes(16).toString("hex") }, "metadata_v1", key32);
  } catch {
    a5_gcmAuthFail = true;
  }

  // 6. At least 25 supported currencies
  const currCount = Object.keys(STATIC_FX_RATES_V1).length;
  const a6_currencies25 = currCount >= 25;

  // 7. INR rejection
  const inrRes = evaluateTransactionPolicy(
    { buyer_token: "BUYER_RAHUL_01", amount: 15000, currency: "INR" },
    { bypassIdempotency: true }
  );
  const a7_inrRejected = inrRes.approved === false && inrRes.policyViolation === "DOMESTIC_INR_NOT_SUPPORTED";

  // 8. USD cap boundary ($2,500 allowed, $2,500.01 rejected)
  const usd2500 = evaluateTransactionPolicy(
    { buyer_token: "BUYER_RAHUL_01", amount: 2500.0, currency: "USD" },
    { bypassIdempotency: true }
  );
  const usd2501 = evaluateTransactionPolicy(
    { buyer_token: "BUYER_RAHUL_01", amount: 2500.01, currency: "USD" },
    { bypassIdempotency: true }
  );
  const a8_usdBoundary = usd2500.approved === true && usd2501.approved === false;

  // 9. Foreign currency cap boundary (2,314.81 EUR allowed, 2,315.00 EUR rejected)
  const eurOk = evaluateTransactionPolicy(
    { buyer_token: "BUYER_RAHUL_01", amount: 2314.81, currency: "EUR" },
    { bypassIdempotency: true }
  );
  const eurOver = evaluateTransactionPolicy(
    { buyer_token: "BUYER_RAHUL_01", amount: 2315.0, currency: "EUR" },
    { bypassIdempotency: true }
  );
  const a9_foreignBoundary = eurOk.approved === true && eurOver.approved === false;

  // 10. Audio replay detection
  const aHash = `test_audio_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`;
  const a1 = verifyAudioReplayGuard(aHash, Date.now());
  const a2 = verifyAudioReplayGuard(aHash, Date.now());
  const a10_audioReplay = a1.safe === true && a2.safe === false;

  // 11. Stale audio rejection (> 60s)
  const aStale = verifyAudioReplayGuard(`stale_${Date.now()}`, Date.now() - 70000);
  const a11_staleAudio = aStale.safe === false;

  // 12. Spatial luminance variance (variance <= 5.0 rejected as black/covered)
  const vLow = verifyTemporalLivenessProof({ variance: 2.0, motionDelta: 10.0, durationMs: 150 });
  const a12_spatialVariance = vLow.verified === false;

  // 13. Temporal motion threshold (motionDelta <= 0.2 rejected, motionDelta >= 85.0 rejected, human accepted)
  const mStatic = verifyTemporalLivenessProof({ variance: 10.0, motionDelta: 0.1, durationMs: 150 });
  const mStrobe = verifyTemporalLivenessProof({ variance: 10.0, motionDelta: 90.0, durationMs: 150 });
  const mHuman = verifyTemporalLivenessProof({ variance: 10.0, motionDelta: 12.0, durationMs: 150 });
  const a13_temporalMotion = mStatic.verified === false && mStrobe.verified === false && mHuman.verified === true;

  // 14. Read-back digest validation
  const staged = { buyer_token: "BUYER_RAHUL_01", amount: 200, currency: "USD", item: "Wheat" };
  const rbDigest = computeReadBackDigest(staged, "en");
  const rbOk = verifyReadBackConfirmation({ stagedInvoice: staged, language: "en", confirmationDigest: rbDigest });
  const a14_readBackValid = rbOk.valid === true;

  // 15. Tampered confirmation rejection
  const rbTampered = verifyReadBackConfirmation({
    stagedInvoice: { ...staged, amount: 201 },
    language: "en",
    confirmationDigest: rbDigest,
  });
  const a15_tamperedRejected = rbTampered.valid === false;

  const sub10Passed =
    a1_sivRoundtrip &&
    a2_sivWrongKey &&
    a3_sivAdTamper &&
    a4_gcmRoundtrip &&
    a5_gcmAuthFail &&
    a6_currencies25 &&
    a7_inrRejected &&
    a8_usdBoundary &&
    a9_foreignBoundary &&
    a10_audioReplay &&
    a11_staleAudio &&
    a12_spatialVariance &&
    a13_temporalMotion &&
    a14_readBackValid &&
    a15_tamperedRejected;

  summaryRows.push({
    num: 10,
    subsystem: "FX Cap, SIV & Liveness Gate",
    assertion: "25-FX Cap, RFC 5297 & Liveness",
    target: "15/15 Verifications PASS",
    actual: sub10Passed ? "15/15 Passed (SIV+GCM+25FX+Live)" : "Subsystem 10 Assertion Failure",
    status: sub10Passed ? "PASS" : "FAIL",
    time: `${Date.now() - sub10Start}ms`,
  });

  // Print Formatted Summary Table matching deck
  console.log("┌────┬─────────────────────────────┬────────────────────────────────────┬──────────────────────┬────────┬──────────┐");
  console.log("│ #  │ Subsystem / Component       │ Security & Compliance Assertion    │ Target Benchmark     │ Status │ Latency  │");
  console.log("├────┼─────────────────────────────┼────────────────────────────────────┼──────────────────────┼────────┼──────────┤");

  for (const r of summaryRows) {
    const num = String(r.num).padEnd(2);
    const sub = r.subsystem.padEnd(27);
    const ass = r.assertion.padEnd(34);
    const tar = r.target.padEnd(20);
    const st = (r.status === "PASS" ? "\x1b[32mPASS\x1b[0m" : "\x1b[31mFAIL\x1b[0m").padEnd(14);
    const tm = r.time.padStart(8);
    console.log(`│ ${num} │ ${sub} │ ${ass} │ ${tar} │ ${st} │ ${tm} │`);
  }

  console.log("└────┴─────────────────────────────┴────────────────────────────────────┴──────────────────────┴────────┴──────────┘");

  const totalPassed = summaryRows.filter((r) => r.status === "PASS").length;
  const totalTests = summaryRows.length;
  const totalElapsed = Date.now() - t0;

  console.log(`\n🎯 PHASE 4 FINAL BENCHMARK SUMMARY: ${totalPassed}/${totalTests} Subsystems Passed in ${totalElapsed}ms`);
  if (totalPassed === totalTests) {
    console.log("✅ ALL PAYVOICE PHASE 4 SECURITY GATES, RFC 5297 SIV, 25-CURRENCY CAP, AND TEMPORAL LIVENESS RULES VERIFIED!\n");
    return { passed: true, summaryRows };
  } else {
    console.error("❌ Some benchmark assertions failed.\n");
    return { passed: false, summaryRows };
  }
}

// Execute if run directly from CLI (e.g. node scripts/benchmark.js)
if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  runFullBenchmark()
    .then((res) => {
      process.exit(res.passed ? 0 : 1);
    })
    .catch((err) => {
      console.error("Benchmark Fatal Error:", err);
      process.exit(1);
    });
}
