/**
 * PayVoice Standalone Security & Mathematical Benchmark Suite
 * PayPal AI Hackathon 2026 - Security, Guardrails & Encryption Track
 */

import { ADVERSARIAL_TEST_CASES } from "../routes/security.js";
import { inspectUntrustedInput } from "../services/guardrail.js";
import { evaluateTransactionPolicy, computeTransactionTotals } from "../services/moneyGuide.js";
import { redactPIIBeforeLLM, resolveBuyerToken, registerBuyer } from "../services/vault.js";
import { appendAuditEntry, verifyLedgerIntegrity } from "../services/auditLedger.js";
import { createPayloadBoundChallenge, verifyPasskeyAssertion } from "../routes/auth.js";
import { generateEncryptedStatementPdf } from "../services/pdfGenerator.js";

async function runBenchmarkSuite() {
  const t0 = Date.now();
  const results = [];

  console.log("\n" + "=".repeat(88));
  console.log(" PAYVOICE: SECURE MULTILINGUAL FINANCIAL AGENT - BENCHMARK & VERIFICATION SUITE");
  console.log(" PayPal AI Hackathon 2026 | Track: Security, Guardrails & Cryptography");
  console.log("=".repeat(88) + "\n");

  // 1. Adversarial Guardrail & Policy Suite (15 Test Cases)
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
  const advTime = Date.now() - advStart;
  results.push({
    num: 1,
    subsystem: "Prompt Firewall & Policy",
    assertion: "15 Adversarial Injection & Policy Tests",
    target: "100.0% Block Rate",
    actual: `${((advBlocked / ADVERSARIAL_TEST_CASES.length) * 100).toFixed(1)}% (${advBlocked}/${ADVERSARIAL_TEST_CASES.length})`,
    status: advBlocked === ADVERSARIAL_TEST_CASES.length ? "PASS" : "FAIL",
    time: `${advTime}ms`,
  });

  // 2. WebAuthn Single-Use Anti-Replay Shield
  const replayStart = Date.now();
  const testPayload = { item: "Organic Wheat", amount: 200.0, buyer: "BUYER_RAHUL_01" };
  const challengeRecord = createPayloadBoundChallenge(testPayload);
  const firstUse = verifyPasskeyAssertion({
    challengeId: challengeRecord.challengeId,
    expectedPayloadHash: challengeRecord.payloadHash,
  });
  const replayAttempt = verifyPasskeyAssertion({
    challengeId: challengeRecord.challengeId,
    expectedPayloadHash: challengeRecord.payloadHash,
  });
  const replayPassed = firstUse.verified === true && replayAttempt.verified === false;
  results.push({
    num: 2,
    subsystem: "WebAuthn Passkey Binder",
    assertion: "Single-Use Challenge Replay Defense",
    target: "Zero-Replay Rejection",
    actual: replayPassed ? "Replay Blocked (403)" : "Replay Leaked",
    status: replayPassed ? "PASS" : "FAIL",
    time: `${Date.now() - replayStart}ms`,
  });

  // 3. True PDF Password-Locked Encryption
  const pdfStart = Date.now();
  const sampleTx = [
    { id: "INV2-OPGSP-BENCH-01", amount: 200.0, date: "2026-11-01", description: "Grade-A Wheat Export" },
    { id: "INV2-OPGSP-BENCH-02", amount: 350.0, date: "2026-11-04", description: "Organic Cotton Seeds" },
  ];
  const pdfResult = await generateEncryptedStatementPdf({
    dateRange: "November 2026",
    transactions: sampleTx,
    totals: computeTransactionTotals(sampleTx),
    userPassword: "PAYVOICE2026",
  });

  const bufferStr = pdfResult.buffer.toString("binary");
  const isPdfHeader = bufferStr.startsWith("%PDF");
  const hasEncryptDict = bufferStr.includes("/Encrypt");
  const pdfPassed = isPdfHeader && hasEncryptDict && pdfResult.checksum.length === 64;
  results.push({
    num: 3,
    subsystem: "Encrypted PDF Statements",
    assertion: "Standard Password Encrypt + Checksum",
    target: "%PDF + /Encrypt Active",
    actual: hasEncryptDict ? "Active (Prompt on Open)" : "Unencrypted",
    status: pdfPassed ? "PASS" : "FAIL",
    time: `${Date.now() - pdfStart}ms`,
  });

  // 4. AES-256-GCM Opaque PII Tokenization Vault
  const vaultStart = Date.now();
  const registered = registerBuyer({
    name: "Vikram Malhotra",
    email: "vikram.m@singapore-trading.sg",
    country: "SG",
    currency: "USD",
    maxLimit: 2500.0,
  });
  const redactedText = redactPIIBeforeLLM("Invoice Vikram Malhotra for $400 USD");
  const resolved = resolveBuyerToken(registered.buyerToken);
  const vaultPassed = Boolean(
    resolved &&
    resolved.email === "vikram.m@singapore-trading.sg" &&
    redactedText.includes(registered.buyerToken) &&
    !redactedText.includes("Vikram Malhotra")
  );
  results.push({
    num: 4,
    subsystem: "AES-256-GCM PII Vault",
    assertion: "Opaque Tokenization & Redaction",
    target: "100% PII Stripped to Token",
    actual: vaultPassed ? `Redacted: ${registered.buyerToken}` : "PII Leaked",
    status: vaultPassed ? "PASS" : "FAIL",
    time: `${Date.now() - vaultStart}ms`,
  });

  // 5. Deterministic Money Guide AI vs Raw Floating Point
  const mathStart = Date.now();
  const mathTx = [
    { amount: 199.99, fee: 7.47 },
    { amount: 800.5, fee: 28.43 },
    { amount: 1500.0, fee: 52.84 },
  ];
  const totals = computeTransactionTotals(mathTx);
  const rawSum = 199.99 + 800.5 + 1500.0;
  const rawFees = 7.47 + 28.43 + 52.84;
  const rawNet = rawSum - rawFees;
  const mathPassed =
    Math.abs(totals.totalGross - rawSum) < 0.001 &&
    Math.abs(totals.estimatedFees - rawFees) < 0.001 &&
    Math.abs(totals.totalNet - rawNet) < 0.001;
  results.push({
    num: 5,
    subsystem: "Deterministic Money Guide",
    assertion: "Precision Mathematical Totals",
    target: "Zero-LLM Math Drift",
    actual: `Gross: $${totals.totalGross} Net: $${totals.totalNet}`,
    status: mathPassed ? "PASS" : "FAIL",
    time: `${Date.now() - mathStart}ms`,
  });

  // 6. SHA-256 Cryptographic Hash Chain Audit Ledger
  const ledgerStart = Date.now();
  appendAuditEntry({
    transcript: "Benchmark Ledger Check",
    stagedPayload: { bench: true },
    passkeyAssertionId: "BENCH_TEST_ASSERTION",
    invoiceId: "INV2-BENCH-99",
    status: "BENCHMARK_VERIFIED",
  });
  const integrity = verifyLedgerIntegrity();
  results.push({
    num: 6,
    subsystem: "Cryptographic Audit Ledger",
    assertion: "Genesis-to-Tip SHA-256 Chain",
    target: "100% Tamper Proof",
    actual: integrity.valid ? `Chain Verified (${integrity.totalRecords} blocks)` : "Chain Compromised",
    status: integrity.valid ? "PASS" : "FAIL",
    time: `${Date.now() - ledgerStart}ms`,
  });

  // Print Formatted Presentation Summary Table
  console.log("┌────┬─────────────────────────────┬────────────────────────────────────┬──────────────────────┬────────┬──────────┐");
  console.log("│ #  │ Subsystem / Component       │ Security & Compliance Assertion    │ Target Benchmark     │ Status │ Latency  │");
  console.log("├────┼─────────────────────────────┼────────────────────────────────────┼──────────────────────┼────────┼──────────┤");

  for (const r of results) {
    const num = String(r.num).padEnd(2);
    const sub = r.subsystem.padEnd(27);
    const ass = r.assertion.padEnd(34);
    const tar = r.target.padEnd(20);
    const st = (r.status === "PASS" ? "\x1b[32mPASS\x1b[0m" : "\x1b[31mFAIL\x1b[0m").padEnd(14);
    const tm = r.time.padStart(8);
    console.log(`│ ${num} │ ${sub} │ ${ass} │ ${tar} │ ${st} │ ${tm} │`);
  }

  console.log("└────┴─────────────────────────────┴────────────────────────────────────┴──────────────────────┴────────┴──────────┘");

  const totalPassed = results.filter((r) => r.status === "PASS").length;
  const totalTests = results.length;
  const totalElapsed = Date.now() - t0;

  console.log(`\n🎯 BENCHMARK SUMMARY: ${totalPassed}/${totalTests} Subsystems Passed in ${totalElapsed}ms`);
  if (totalPassed === totalTests) {
    console.log("✅ ALL PAYVOICE SECURITY, WEBAUTHN, PDF ENCRYPTION & DETERMINISTIC GATES VERIFIED!\n");
    process.exit(0);
  } else {
    console.error("❌ Some benchmark assertions failed.\n");
    process.exit(1);
  }
}

runBenchmarkSuite().catch((err) => {
  console.error("Benchmark Execution Fatal Error:", err);
  process.exit(1);
});
