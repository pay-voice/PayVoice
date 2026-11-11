import { Router } from "express";
import { computeTransactionTotals } from "../services/moneyGuide.js";
import { generateEncryptedStatementPdf } from "../services/pdfGenerator.js";
import { appendAuditEntry } from "../services/auditLedger.js";
import { inspectUntrustedInput } from "../services/guardrail.js";

const router = Router();

// Sample export transaction history for demonstration when PayPal sandbox transactions list is loading
const DEMO_TRANSACTIONS = [
  {
    id: "INV2-OPGSP-2026-001",
    date: "2026-11-02",
    description: "BUYER_RAHUL_01 - 100 kg Grade-A Wheat",
    status: "PAID",
    amount: 200.0,
    currency: "USD",
  },
  {
    id: "INV2-OPGSP-2026-002",
    date: "2026-11-05",
    description: "BUYER_GLOBAL_02 - 50 kg Organic Cotton Seed",
    status: "PAID",
    amount: 450.0,
    currency: "USD",
  },
  {
    id: "INV2-OPGSP-2026-003",
    date: "2026-11-09",
    description: "BUYER_RAHUL_01 - Agricultural Soil Testing & Phytosanitary Pack",
    status: "SENT",
    amount: 150.0,
    currency: "USD",
  },
];

/**
 * POST /api/statements/pdf
 * Generates an AES-256 password-encrypted PDF accounting statement
 * Body: { dateRange, password, transactions }
 */
router.post("/pdf", async (req, res) => {
  try {
    const { dateRange = "Last 30 Days", password = "PAYVOICE2026", transactions } = req.body || {};

    // Guardrail check on dateRange query if spoken
    const guard = inspectUntrustedInput(dateRange);
    if (!guard.safe) {
      return res.status(400).json({ error: `Security firewall blocked query: ${guard.reason}` });
    }

    const txList = Array.isArray(transactions) && transactions.length > 0 ? transactions : DEMO_TRANSACTIONS;
    const totals = computeTransactionTotals(txList);

    // Generate encrypted PDF with pdfkit
    const { buffer, checksum, filename, recordCount, generatedAt } = await generateEncryptedStatementPdf({
      dateRange,
      transactions: txList,
      totals,
      userPassword: password || "PAYVOICE2026",
    });

    // Record immutable audit entry
    appendAuditEntry({
      transcript: `Voice-Triggered Statement Export: ${dateRange}`,
      stagedPayload: { dateRange, totals, checksum },
      passkeyAssertionId: "STATEMENT_EXPORT_SYS",
      invoiceId: "N/A",
      status: "STATEMENT_EXPORTED",
      metadata: { filename, checksum, recordCount },
    });

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    res.setHeader("X-PayVoice-SHA256", checksum);
    res.setHeader("X-PayVoice-Records", String(recordCount));
    res.setHeader("X-PayVoice-Generated-At", generatedAt);

    return res.send(buffer);
  } catch (error) {
    console.error("[Statements Route Error]:", error);
    return res.status(500).json({ error: "Failed to generate encrypted PDF statement: " + error.message });
  }
});

export default router;
