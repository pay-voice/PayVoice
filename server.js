import express from "express";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import "dotenv/config";

// Services
import { getAuditLedger, verifyLedgerIntegrity } from "./server/services/auditLedger.js";
import { listMaskedBuyers, registerBuyer } from "./server/services/vault.js";
import { parseMultilingualIntent } from "./server/services/intentParser.js";

// Routes
import authRouter from "./server/routes/auth.js";
import invoicesRouter from "./server/routes/invoices.js";
import transactionsRouter from "./server/routes/transactions.js";
import statementsRouter from "./server/routes/statements.js";
import webhooksRouter from "./server/routes/webhooks.js";
import securityRouter from "./server/routes/security.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID || "";
const PAYPAL_API_BASE = process.env.PAYPAL_API_BASE || "https://api-m.sandbox.paypal.com";

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "client")));

// --- Core API Routers ---
app.use("/api/auth", authRouter);
app.use("/api/invoices", invoicesRouter);
app.use("/api/transactions", transactionsRouter);
app.use("/api/statements", statementsRouter);
app.use("/api/webhooks", webhooksRouter);
app.use("/api/security", securityRouter);

/**
 * POST /api/ai/parse-intent
 * High-Precision Multilingual Gemini Intent Extraction with Instant Deterministic Fallback
 */
app.post("/api/ai/parse-intent", async (req, res) => {
  try {
    const { transcript = "", language = "auto" } = req.body || {};
    const intent = await parseMultilingualIntent(transcript, { language });
    res.json({
      success: true,
      transcript,
      intent,
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message,
    });
  }
});

// --- Shared Security & Vault Endpoints ---

/**
 * GET /api/audit-ledger
 * Returns the immutable SHA-256 sequential audit trail
 */
app.get("/api/audit-ledger", (req, res) => {
  res.json({
    success: true,
    ledger: getAuditLedger(),
  });
});

/**
 * GET /api/audit-ledger/verify
 * Validates the cryptographic integrity of every row hash in the chain
 */
app.get("/api/audit-ledger/verify", (req, res) => {
  const result = verifyLedgerIntegrity();
  res.json(result);
});

/**
 * GET /api/vault/buyers
 * Lists allowlisted buyers with PII masked
 */
app.get("/api/vault/buyers", (req, res) => {
  res.json({
    success: true,
    buyers: listMaskedBuyers(),
  });
});

/**
 * POST /api/vault/buyers
 * Enrolls a new overseas buyer into the AES-256-GCM encrypted vault
 */
app.post("/api/vault/buyers", (req, res) => {
  try {
    const buyer = registerBuyer(req.body);
    res.json({
      success: true,
      buyer,
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message,
    });
  }
});

/**
 * GET /api/config
 * Provides public client ID and runtime environment status
 */
app.get("/api/config", (req, res) => {
  const isConfigured = Boolean(PAYPAL_CLIENT_ID) && PAYPAL_CLIENT_ID !== "YOUR_SANDBOX_CLIENT_ID_HERE";

  res.json({
    clientId: isConfigured ? PAYPAL_CLIENT_ID : "test",
    currency: "USD",
    isConfigured,
    environment: PAYPAL_API_BASE.includes("sandbox") ? "sandbox" : "live",
    agent: "PayVoice v1.0.0",
    corridor: "India MSME Cross-Border Exporter Portal",
  });
});

// Fallback to client/index.html
// Dedicated route for Shoury's Security Console
app.get(["/security-console", "/security-console.html"], (req, res) => {
  res.sendFile(path.join(__dirname, "client", "security-console.html"));
});

// Direct alias for /api/insights
app.get("/api/insights", (req, res) => {
  res.redirect(307, "/api/transactions/insights");
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "client", "index.html"));
});

// Only listen when executed directly (not when imported in tests or serverless functions)
const isServerless = Boolean(
  process.env.NETLIFY ||
  process.env.AWS_LAMBDA_FUNCTION_NAME ||
  process.env.LAMBDA_TASK_ROOT ||
  process.env.VERCEL
);

if (process.env.NODE_ENV !== "test" && !isServerless) {
  app.listen(PORT, () => {
    console.log(`=======================================================`);
    console.log(`PayVoice Secure Financial Agent Server running!`);
    console.log(`URL: http://localhost:${PORT}`);
    console.log(`Environment: ${PAYPAL_API_BASE}`);
    console.log(`Security: AES-256-GCM Vault & SHA-256 Hash Chain ACTIVE`);
    console.log(`=======================================================`);
  });
}

export default app;
