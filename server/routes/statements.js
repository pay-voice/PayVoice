import { Router } from "express";
import { computeTransactionTotals } from "../services/moneyGuide.js";
import { generateEncryptedStatementPdf } from "../services/pdfGenerator.js";
import { appendAuditEntry, getAuditLedger } from "../services/auditLedger.js";
import { inspectUntrustedInput } from "../services/guardrail.js";

const router = Router();

// Sample export transaction history for demonstration when PayPal sandbox transactions list is loading
const DEMO_TRANSACTIONS = [
  {
    id: "INV2-OPGSP-2026-001",
    date: "2026-11-02T10:00:00Z",
    description: "BUYER_RAHUL_01 - 100 kg Grade-A Wheat Export",
    status: "PAID",
    amount: 200.0,
    currency: "USD",
  },
  {
    id: "INV2-OPGSP-2026-002",
    date: "2026-11-05T14:30:00Z",
    description: "BUYER_GLOBAL_02 - 50 kg Organic Cotton Seed",
    status: "PAID",
    amount: 450.0,
    currency: "USD",
  },
  {
    id: "INV2-OPGSP-2026-003",
    date: "2026-11-09T16:45:00Z",
    description: "BUYER_RAHUL_01 - Agricultural Soil Testing & Phytosanitary Pack",
    status: "SENT",
    amount: 150.0,
    currency: "USD",
  },
  {
    id: "INV2-OPGSP-2026-004",
    date: "2026-10-15T09:15:00Z",
    description: "BUYER_GLOBAL_02 - Mustard Seed Lot #210",
    status: "PAID",
    amount: 320.0,
    currency: "USD",
  },
  {
    id: "INV2-OPGSP-2026-005",
    date: "2026-10-28T11:20:00Z",
    description: "BUYER_RAHUL_01 - Grain Inspection Dispatch Pack",
    status: "PAID",
    amount: 180.0,
    currency: "USD",
  },
];

/**
 * Helper to parse multilingual / spoken date range expressions
 * Examples: "last 7 days", "last 30 days", "October 2026", "last quarter", "today"
 */
export function parseSpokenDateRange(query = "") {
  const norm = String(query).toLowerCase().trim();
  const now = new Date();
  let startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000); // default 30 days
  let endDate = new Date(now.getTime());
  let label = "Last 30 Days";

  if (norm.includes("7 day") || norm.includes("7 days") || norm.includes("week") || norm.includes("७ दिवस")) {
    startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    label = "Last 7 Days";
  } else if (norm.includes("today") || norm.includes("आज") || norm.includes("आजचे")) {
    startDate = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    label = "Today";
  } else if (norm.includes("quarter") || norm.includes("90 day") || norm.includes("3 month")) {
    startDate = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
    label = "Last 90 Days (Quarter)";
  } else if (norm.includes("october") || norm.includes("ऑक्टोबर")) {
    startDate = new Date(2026, 9, 1);
    endDate = new Date(2026, 9, 31, 23, 59, 59);
    label = "October 2026";
  } else if (norm.includes("november") || norm.includes("नोव्हेंबर")) {
    startDate = new Date(2026, 10, 1);
    endDate = new Date(2026, 10, 30, 23, 59, 59);
    label = "November 2026";
  } else if (norm.includes("year") || norm.includes("वर्ष")) {
    startDate = new Date(now.getFullYear(), 0, 1);
    label = `Year to Date (${now.getFullYear()})`;
  }

  return { startDate, endDate, label };
}

/**
 * POST /api/statements/pdf
 * Generates an AES-256 password-encrypted PDF accounting statement
 * Body: { dateRange, password, transactions }
 */
router.post("/pdf", async (req, res) => {
  try {
    const { dateRange = "Last 30 Days", password = "PAYVOICE2026", transactions } = req.body || {};

    // 1. Guardrail check on dateRange query if spoken
    const guard = inspectUntrustedInput(dateRange);
    if (!guard.safe) {
      return res.status(400).json({ error: `Security firewall blocked query: ${guard.reason}` });
    }

    // 2. Parse spoken date-range
    const { startDate, endDate, label } = parseSpokenDateRange(dateRange);

    const sourceList = Array.isArray(transactions) && transactions.length > 0 ? transactions : DEMO_TRANSACTIONS;

    // 3. Filter transactions matching parsed date range
    const filteredTx = sourceList.filter((tx) => {
      if (!tx.date) return true;
      const txDate = new Date(tx.date);
      return !isNaN(txDate.getTime()) && txDate >= startDate && txDate <= endDate;
    });

    const txList = filteredTx.length > 0 ? filteredTx : sourceList;
    const totals = computeTransactionTotals(txList);

    // 4. Retrieve latest audit root hash to embed in document
    const ledger = getAuditLedger();
    const auditRootHash = ledger[ledger.length - 1]?.rowHash || "GENESIS_ROOT";

    // 5. Generate password-encrypted PDF with pdfkit
    const { buffer, checksum, filename, recordCount, generatedAt } = await generateEncryptedStatementPdf({
      dateRange: label,
      transactions: txList,
      totals,
      userPassword: password || "PAYVOICE2026",
    });

    // 6. Record immutable audit entry
    appendAuditEntry({
      transcript: `Voice-Triggered Statement Export: ${label}`,
      stagedPayload: { dateRange: label, totals, checksum, auditRootHash },
      passkeyAssertionId: "STATEMENT_EXPORT_SYS",
      invoiceId: "N/A",
      status: "STATEMENT_EXPORTED",
      metadata: { filename, checksum, recordCount, auditRootHash },
    });

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    res.setHeader("X-PayVoice-SHA256", checksum);
    res.setHeader("X-PayVoice-Audit-Root", auditRootHash);
    res.setHeader("X-PayVoice-Records", String(recordCount));
    res.setHeader("X-PayVoice-Generated-At", generatedAt);

    return res.send(buffer);
  } catch (error) {
    console.error("[Statements Route Error]:", error);
    return res.status(500).json({ error: "Failed to generate encrypted PDF statement: " + error.message });
  }
});

export default router;
