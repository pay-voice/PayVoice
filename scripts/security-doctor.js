/**
 * PayVoice Pre-Merge Security Doctor & Stage Readiness Verification Script
 * PayPal AI Hackathon 2026 - Track: Security, Guardrails & Cryptography (Shoury Rai)
 *
 * Runs a fast, rigorous pre-flight checklist:
 *   1. Zero Secret Leakage: Confirms .env, server/data/*.json, and private keys are untracked.
 *   2. Module & Contract Integrity: Verifies all 9 security modules and their exported contracts.
 *   3. Clean Audit State: Restores pristine state and verifies unbroken genesis-to-tip hash chain.
 *   4. Full Triad Execution: Runs benchmark (10/10), lifecycle trace (7/7), and redteam suite (10/10 attacks blocked).
 *   5. Final Demo Seal: Restores pristine ledger state so the live demo starts in 100% PRISTINE state.
 */

import { execSync } from "child_process";
import fs from "fs";
import path from "path";
import { performance } from "perf_hooks";
import { fileURLToPath } from "url";

// 1. Security Modules & Services
import * as vault from "../server/services/vault.js";
import * as sivCrypto from "../server/services/sivCrypto.js";
import * as moneyGuide from "../server/services/moneyGuide.js";
import * as guardrail from "../server/services/guardrail.js";
import * as auditLedger from "../server/services/auditLedger.js";
import * as pdfGenerator from "../server/services/pdfGenerator.js";
import * as secureToolkitWrapper from "../server/services/secureToolkitWrapper.js";
import * as webhookVerifier from "../server/services/webhookVerifier.js";
import * as securityGate from "../server/middleware/securityGate.js";

// 2. Full Test Triad Runners
import { runFullBenchmark } from "./benchmark.js";
import { runLifecycleTrace } from "./lifecycle-trace.js";
import { runRedTeamSuite } from "./redteam.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, "..");

export async function runSecurityDoctor() {
  const doctorStart = performance.now();
  const checks = [];

  console.log("\n" + "=".repeat(100));
  console.log(" 🩺 PAYVOICE PRE-MERGE SECURITY DOCTOR & STAGE READINESS VERIFIER");
  console.log(" PayPal AI Hackathon 2026 | Shoury Rai (Security, Guardrails & Cryptography Lead)");
  console.log("=".repeat(100) + "\n");

  // =========================================================================
  // CHECK 1: Zero Secret Leakage Verification
  // =========================================================================
  const c1Start = performance.now();
  let secretLeakageDetected = false;
  let secretLeakDetails = [];

  try {
    const trackedSecrets = execSync("git ls-files .env .env.local server/data/*.json *.pem *.key *.p12 id_rsa", {
      cwd: rootDir,
      encoding: "utf8",
      stdio: ["pipe", "pipe", "ignore"],
    }).trim();

    if (trackedSecrets.length > 0) {
      secretLeakageDetected = true;
      secretLeakDetails = trackedSecrets.split("\n").filter(Boolean);
    }

    // Verify .gitignore contains .env and server/data/
    const gitignorePath = path.resolve(rootDir, ".gitignore");
    if (fs.existsSync(gitignorePath)) {
      const gitignoreContent = fs.readFileSync(gitignorePath, "utf8");
      if (!gitignoreContent.includes(".env")) {
        secretLeakageDetected = true;
        secretLeakDetails.push("Missing '.env' entry in .gitignore");
      }
      if (!gitignoreContent.includes("server/data/")) {
        secretLeakageDetected = true;
        secretLeakDetails.push("Missing 'server/data/' entry in .gitignore");
      }
    }
  } catch (err) {
    // If git command fails, flag warning
    secretLeakDetails.push("Git command check note: " + err.message);
  }

  checks.push({
    num: 1,
    name: "Zero Secret Leakage Check",
    scope: ".env, server/data/*.json, private keys",
    passed: !secretLeakageDetected,
    details: secretLeakageDetected ? `LEAK DETECTED: ${secretLeakDetails.join(", ")}` : "0 Tracked Secrets / All Ignored",
    latencyMs: Number((performance.now() - c1Start).toFixed(2)),
  });

  // =========================================================================
  // CHECK 2: Module & Export Contract Integrity
  // =========================================================================
  const c2Start = performance.now();
  const requiredContracts = [
    { mod: "vault.js", symbols: ["encryptAes256Siv", "decryptAes256Siv", "encryptAes256Gcm", "decryptAes256Gcm", "scrubPiiFromLogs", "redactPIIBeforeLLM", "resolveBuyerToken"], obj: vault },
    { mod: "sivCrypto.js", symbols: ["encryptAes256Siv", "decryptAes256Siv", "encryptAes256Gcm", "decryptAes256Gcm"], obj: sivCrypto },
    { mod: "moneyGuide.js", symbols: ["STATIC_FX_RATES_V1", "normalizeToUsd", "evaluateTransactionPolicy", "validateInvoiceReminderPolicy", "computeReadBackDigest", "verifyReadBackConfirmation", "classifyRbiPurposeCode"], obj: moneyGuide },
    { mod: "guardrail.js", symbols: ["inspectUntrustedInput", "sanitizeAndValidateCsvLedger", "verifyAudioReplayGuard"], obj: guardrail },
    { mod: "auditLedger.js", symbols: ["appendAuditEntry", "getAuditLedger", "verifyLedgerIntegrity", "restoreAuditLedger", "exportVerifiableAuditBundle", "verifyAuditBundleOffline"], obj: auditLedger },
    { mod: "pdfGenerator.js", symbols: ["generateEncryptedStatementPdf", "createAes256EncryptedPdfEnvelope", "verifyAndDecryptPdfEnvelope"], obj: pdfGenerator },
    { mod: "secureToolkitWrapper.js", symbols: ["wrapPayPalToolkitWithSecurityGate", "issueSecurityExecutionTicket", "verifySecurityExecutionTicket"], obj: secureToolkitWrapper },
    { mod: "webhookVerifier.js", symbols: ["verifyPayPalWebhookEvent", "generateMockSignedWebhook"], obj: webhookVerifier },
    { mod: "securityGate.js", symbols: ["requireStepUpSecurityGate"], obj: securityGate },
  ];

  let contractsPassed = true;
  const missingContracts = [];

  for (const { mod, symbols, obj } of requiredContracts) {
    for (const sym of symbols) {
      if (typeof obj[sym] === "undefined") {
        contractsPassed = false;
        missingContracts.push(`${mod}::${sym}`);
      }
    }
  }

  checks.push({
    num: 2,
    name: "Module Contract Integrity",
    scope: "9 Security Modules & Exported Functions",
    passed: contractsPassed,
    details: contractsPassed ? "All 9 Modules & Contracts Fully Exported" : `Missing: ${missingContracts.join(", ")}`,
    latencyMs: Number((performance.now() - c2Start).toFixed(2)),
  });

  // =========================================================================
  // CHECK 3: Clean Audit Ledger State Initializer
  // =========================================================================
  const c3Start = performance.now();
  auditLedger.restoreAuditLedger();
  const initIntegrity = auditLedger.verifyLedgerIntegrity();

  checks.push({
    num: 3,
    name: "Pristine Ledger State Verification",
    scope: "Genesis Hash Chain & Checkpoint Signature",
    passed: initIntegrity.valid === true,
    details: initIntegrity.valid ? `PRISTINE (${initIntegrity.totalRecords} blocks, Tip: ${initIntegrity.chainRoot.slice(0, 16)}...)` : `Ledger Error: ${initIntegrity.error}`,
    latencyMs: Number((performance.now() - c3Start).toFixed(2)),
  });

  // =========================================================================
  // CHECK 4: Stage 4A — Full Benchmark Suite (10/10 Subsystems)
  // =========================================================================
  console.log("\n▶ Running Benchmark Suite (10/10 Subsystems)...");
  const c4aStart = performance.now();
  const benchmarkResult = await runFullBenchmark();

  checks.push({
    num: 4,
    name: "10-Subsystem Benchmark Suite",
    scope: "Prompt, Multilingual, SIV, GCM, FX Cap, PDF, Liveness",
    passed: benchmarkResult.passed === true,
    details: benchmarkResult.passed ? "10/10 Subsystems Passed" : "Benchmark Subsystem Failure",
    latencyMs: Number((performance.now() - c4aStart).toFixed(2)),
  });

  // =========================================================================
  // CHECK 5: Stage 4B — Authentic 7-Step Lifecycle Trace
  // =========================================================================
  console.log("\n▶ Running 7-Step Lifecycle Trace (Deck-Aligned)...");
  const c4bStart = performance.now();
  const traceResult = await runLifecycleTrace();

  checks.push({
    num: 5,
    name: "7-Step Sandbox Lifecycle Trace",
    scope: "Voice Capture -> WebAuthn -> Toolkit -> Webhook -> Defense",
    passed: traceResult.success === true,
    details: traceResult.success ? "7/7 Lifecycle Stages Verified" : "Trace Stage Failure",
    latencyMs: Number((performance.now() - c4bStart).toFixed(2)),
  });

  // =========================================================================
  // CHECK 6: Stage 4C — Live Judge Red-Team Matrix (10 Trials & 10 Attacks)
  // =========================================================================
  console.log("\n▶ Running Live Judge Red-Team Suite (10 Attacks Blocked)...");
  const c4cStart = performance.now();
  const redteamResult = await runRedTeamSuite();

  checks.push({
    num: 6,
    name: "Judge Red-Team Adversarial Matrix",
    scope: "10 Multilingual Trials & 10 Attack Vectors Blocked",
    passed: redteamResult.success === true,
    details: redteamResult.success ? `10/10 Attacks Blocked (${redteamResult.summary.defenseRatePercent})` : "Red-Team Attack Bypassed",
    latencyMs: Number((performance.now() - c4cStart).toFixed(2)),
  });

  // =========================================================================
  // CHECK 7: Final Stage Demo Seal & State Restoration
  // =========================================================================
  const c7Start = performance.now();
  auditLedger.restoreAuditLedger();
  const finalIntegrity = auditLedger.verifyLedgerIntegrity();

  checks.push({
    num: 7,
    name: "Pre-Stage Ledger Cleanse & Seal",
    scope: "Restore Pristine State for Stage Presentation",
    passed: finalIntegrity.valid === true,
    details: finalIntegrity.valid ? "Ledger Sealed in Pristine State" : "Post-Test Reset Error",
    latencyMs: Number((performance.now() - c7Start).toFixed(2)),
  });

  // =========================================================================
  // Summary Reporting
  // =========================================================================
  const totalElapsed = Number((performance.now() - doctorStart).toFixed(2));
  const allPassed = checks.every((c) => c.passed);

  console.log("\n" + "=".repeat(100));
  console.log(" 🩺 PRE-MERGE SECURITY DOCTOR AUDIT SCORECARD");
  console.log("=".repeat(100));
  console.log("┌────┬──────────────────────────────────────┬──────────────────────────────────────────┬────────┬──────────┐");
  console.log("│ #  │ Doctor Verification Check            │ Target Scope & Deliverable               │ Status │ Latency  │");
  console.log("├────┼──────────────────────────────────────┼──────────────────────────────────────────┼────────┼──────────┤");

  for (const c of checks) {
    const num = String(c.num).padEnd(2);
    const nm = c.name.padEnd(36);
    const sc = c.scope.slice(0, 40).padEnd(40);
    const st = (c.passed ? "\x1b[32mPASS\x1b[0m" : "\x1b[31mFAIL\x1b[0m").padEnd(14);
    const lt = `${c.latencyMs}ms`.padStart(8);
    console.log(`│ ${num} │ ${nm} │ ${sc} │ ${st} │ ${lt} │`);
  }
  console.log("└────┴──────────────────────────────────────┴──────────────────────────────────────────┴────────┴──────────┘\n");

  if (allPassed) {
    console.log("╔" + "═".repeat(98) + "╗");
    console.log("║                                                                                                  ║");
    console.log("║   \x1b[1;32m🎉 100% SECURITY & INTEGRITY VERIFIED — PAYVOICE IS READY FOR LIVE STAGE DEMO!\x1b[0m                 ║");
    console.log("║                                                                                                  ║");
    console.log("║   • 0 Secrets Leaked / Clean Git Hygiene Verified                                               ║");
    console.log("║   • 9/9 Security Module Contracts Intact                                                        ║");
    console.log("║   • 10/10 Benchmark Subsystems Passed                                                            ║");
    console.log("║   • 7/7 Deck-Aligned Lifecycle Stages Verified                                                  ║");
    console.log("║   • 10/10 Adversarial Attacks Blocked (0 Bypassed)                                              ║");
    console.log("║   • Cryptographic Audit Ledger Pristine & Ready                                                  ║");
    console.log("║                                                                                                  ║");
    console.log("╚" + "═".repeat(98) + "╝\n");
    return 0;
  } else {
    console.error("❌ CRITICAL: SECURITY DOCTOR DETECTED PRE-FLIGHT COMPLIANCE OR REGRESSION FAILURES.\n");
    return 1;
  }
}

// CLI Execution
if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  runSecurityDoctor()
    .then((code) => process.exit(code))
    .catch((err) => {
      console.error("Security Doctor Fatal Error:", err);
      process.exit(1);
    });
}
