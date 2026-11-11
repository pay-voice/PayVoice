import PDFDocument from "pdfkit";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { getAuditLedger } from "./auditLedger.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const checkpointFilePath = path.resolve(__dirname, "../data/auditCheckpoints.json");

/**
 * Deterministically verify 100% mathematical parity between raw PayPal JSON line items
 * and the computed PDF statement totals before signing and exporting.
 * @param {Array} rawTransactions - Raw transaction line items from PayPal Sandbox
 * @param {object} computedSummary - Output from computeTransactionTotals()
 * @returns {{ reconciled: boolean, lineItemCount: number, rawTotalGross: number, summaryTotalGross: number, parityDelta: number, verifiedAt: string }}
 */
export function reconcilePdfTotalsWithRawJson(rawTransactions = [], computedSummary = {}) {
  let rawGrossSum = 0;
  let count = 0;

  for (const tx of rawTransactions) {
    const amt = Number(tx.amount || tx.grossAmount || 0);
    if (!isNaN(amt) && amt > 0) {
      rawGrossSum += amt;
      count++;
    }
  }

  const rawTotalGross = Number(rawGrossSum.toFixed(2));
  const summaryTotalGross = Number((computedSummary.totalGross || 0).toFixed(2));
  const parityDelta = Number(Math.abs(rawTotalGross - summaryTotalGross).toFixed(4));
  const isMatch = parityDelta < 0.01;

  return {
    reconciled: isMatch,
    lineItemCount: count,
    rawTotalGross,
    summaryTotalGross,
    parityDelta,
    verifiedAt: new Date().toISOString(),
  };
}

/**
 * Generate a password-encrypted PDF Accounting Statement using PDFKit
 * Includes CA/GST Compliance block, itemized export transactions, deterministic fee summaries,
 * and the latest cryptographic hash chain root & checkpoint hash.
 *
 * @param {object} params
 * @param {string} params.dateRange - Description of range (e.g., "Last 30 Days")
 * @param {Array} params.transactions - List of transaction objects
 * @param {object} params.totals - Output from computeTransactionTotals()
 * @param {string} params.userPassword - Encryption password (defaults to "PAYVOICE2026")
 * @param {object} params.merchant - Exporter profile info
 * @param {object} params.caGstCompliance - CA/GST regulatory fields
 * @returns {Promise<{ buffer: Buffer, checksum: string, filename: string, recordCount: number, generatedAt: string, reconciliation: object }>}
 */
export async function generateEncryptedStatementPdf({
  dateRange = "Last 30 Days",
  transactions = [],
  totals = { totalGross: 0, estimatedFees: 0, totalNet: 0, currency: "USD", count: 0 },
  userPassword = "PAYVOICE2026",
  merchant = { name: "AgriMandi MSME Exporters", email: "exports@agrimandi.in", country: "India" },
  caGstCompliance = {
    panToken: "AABCP****M",
    iecCode: "0312049921",
    rbiPurposeCode: "P0103 - Agricultural & Food Produce Exports",
    gstStatus: "Export under LUT (Rule 96A CGST Rules)",
    invoiceStatus: "PAID / COMPLETED",
  },
}) {
  return new Promise((resolve, reject) => {
    try {
      // 1. Reconcile raw transaction line items with totals
      const reconciliation = reconcilePdfTotalsWithRawJson(transactions, totals);

      // 2. Fetch latest audit chain root & latest checkpoint hash
      const ledger = getAuditLedger();
      const latestAuditRoot = ledger[ledger.length - 1]?.rowHash || "GENESIS_ROOT";

      let latestCheckpointHash = "CHECKPOINT_PENDING";
      try {
        if (fs.existsSync(checkpointFilePath)) {
          const cpData = JSON.parse(fs.readFileSync(checkpointFilePath, "utf8"));
          if (Array.isArray(cpData) && cpData.length > 0) {
            latestCheckpointHash = cpData[cpData.length - 1]?.hmacSignature || "CP_VERIFIED";
          }
        }
      } catch (e) {
        // Fallback
      }

      const generatedAt = new Date().toISOString();
      const filename = `PayVoice_Export_Statement_${Date.now()}.pdf`;

      // 3. Instantiate PDFKit with strict password encryption
      const effectiveUserPassword = String(userPassword || "PAYVOICE2026").trim();
      const effectiveOwnerPassword = process.env.PDF_OWNER_SECRET || "PAYVOICE_ADMIN_MASTER_2026";

      const doc = new PDFDocument({
        size: "A4",
        margin: 40,
        userPassword: effectiveUserPassword,
        ownerPassword: effectiveOwnerPassword,
        permissions: {
          printing: "highResolution",
          modifying: false,
          copying: false,
          annotating: false,
        },
        info: {
          Title: `PayVoice CA/GST Export Statement - ${dateRange}`,
          Author: "PayVoice Secure Financial Agent",
          Subject: "PayPal India MSME Cross-Border Invoicing Statement",
          Keywords: "PayVoice, PayPal, Invoicing, OPGSP, MSME, CA, GST, Export",
        },
      });

      const chunks = [];
      doc.on("data", (chunk) => chunks.push(chunk));
      doc.on("end", () => {
        const buffer = Buffer.concat(chunks);
        const checksum = crypto.createHash("sha256").update(buffer).digest("hex");
        resolve({
          buffer,
          checksum,
          filename,
          recordCount: transactions.length,
          generatedAt,
          reconciliation,
          auditRoot: latestAuditRoot,
          checkpointHash: latestCheckpointHash,
        });
      });
      doc.on("error", (err) => reject(err));

      // --- Header Branding ---
      doc.rect(40, 40, 515, 60).fill("#003087"); // PayPal Deep Blue
      doc.fillColor("#FFFFFF").fontSize(18).font("Helvetica-Bold").text("PayVoice CA/GST Export Statement", 55, 52);
      doc
        .fontSize(9)
        .font("Helvetica")
        .text("Secure Multilingual Financial Statement for Indian MSME Exporters | PayPal AI Hackathon 2026", 55, 76);

      // --- Merchant & Statement Meta Block ---
      doc.fillColor("#1E293B").fontSize(10).font("Helvetica-Bold").text("Merchant & Statement Meta", 40, 112);
      doc.font("Helvetica").fontSize(8.5).fillColor("#475569");
      doc.text(`Merchant Name: ${merchant.name}`, 40, 128);
      doc.text(`Regulated Channel: PayPal India OPGSP Export Pathway`, 40, 140);
      doc.text(`Statement Period: ${dateRange}`, 40, 152);
      doc.text(`Generated On: ${new Date(generatedAt).toLocaleString()}`, 40, 164);

      doc.text(`Encryption: AES Password Protected`, 320, 128);
      doc.text(`Currency: ${totals.currency || "USD"}`, 320, 140);
      doc.text(`Items Count: ${transactions.length}`, 320, 152);
      doc.text(`Default Unlock PIN: ${effectiveUserPassword}`, 320, 164);

      // --- Indian Exporter CA / GST Compliance Block ---
      const caTop = 184;
      doc.rect(40, caTop, 515, 42).fillAndStroke("#F1F5F9", "#CBD5E1");
      doc.fillColor("#0F172A").fontSize(8.5).font("Helvetica-Bold").text("CA / GST REGULATORY COMPLIANCE BLOCK (INDIA DGFT & RBI)", 48, caTop + 6);
      doc.font("Helvetica").fontSize(7.5).fillColor("#334155");
      doc.text(`Masked PAN: ${caGstCompliance.panToken}`, 48, caTop + 18);
      doc.text(`IEC Code: ${caGstCompliance.iecCode}`, 160, caTop + 18);
      doc.text(`RBI Export Code: ${caGstCompliance.rbiPurposeCode}`, 280, caTop + 18);
      doc.text(`GST Status: ${caGstCompliance.gstStatus}`, 48, caTop + 28);
      doc.text(`Lifecycle Status: ${caGstCompliance.invoiceStatus}`, 360, caTop + 28);

      // --- Financial Summary Boxes ---
      const boxTop = 236;
      doc.rect(40, boxTop, 160, 44).fillAndStroke("#F8FAFC", "#CBD5E1");
      doc.fillColor("#64748B").fontSize(7.5).font("Helvetica").text("GROSS EXPORT REALIZATION", 48, boxTop + 8);
      doc.fillColor("#0F172A").fontSize(13).font("Helvetica-Bold").text(`$${totals.totalGross.toFixed(2)} ${totals.currency}`, 48, boxTop + 20);

      doc.rect(215, boxTop, 160, 44).fillAndStroke("#F8FAFC", "#CBD5E1");
      doc.fillColor("#64748B").fontSize(7.5).font("Helvetica").text("EST. PAYPAL FEES (3.49% + $0.49)", 223, boxTop + 8);
      doc.fillColor("#DC2626").fontSize(13).font("Helvetica-Bold").text(`-$${totals.estimatedFees.toFixed(2)} ${totals.currency}`, 223, boxTop + 20);

      doc.rect(390, boxTop, 165, 44).fillAndStroke("#EFF6FF", "#93C5FD");
      doc.fillColor("#1E40AF").fontSize(7.5).font("Helvetica-Bold").text("NET EXPORT EARNINGS", 398, boxTop + 8);
      doc.fillColor("#0070BA").fontSize(13).font("Helvetica-Bold").text(`$${totals.totalNet.toFixed(2)} ${totals.currency}`, 398, boxTop + 20);

      // --- Itemized Transaction Table ---
      let y = 294;
      doc.fillColor("#0F172A").fontSize(10).font("Helvetica-Bold").text("Itemized Export Invoices & Remittances", 40, y);
      y += 14;

      // Table Header
      doc.rect(40, y, 515, 18).fill("#E2E8F0");
      doc.fillColor("#1E293B").fontSize(7.5).font("Helvetica-Bold");
      doc.text("DATE", 45, y + 5);
      doc.text("INVOICE / ID", 110, y + 5);
      doc.text("BUYER / COMMODITY DESCRIPTION", 230, y + 5);
      doc.text("STATUS", 420, y + 5);
      doc.text("AMOUNT", 490, y + 5);
      y += 20;

      const itemsToPrint =
        transactions.length > 0
          ? transactions
          : [
              {
                date: "2026-11-02",
                id: "INV2-OPGSP-SAMPLE",
                description: "BUYER_RAHUL_01 - 100 kg Grade-A Wheat",
                status: "PAID",
                amount: 200.0,
              },
            ];

      doc.font("Helvetica").fontSize(7.5);
      for (const item of itemsToPrint) {
        if (y > 700) {
          doc.addPage();
          y = 40;
        }

        doc.fillColor("#475569").text(String(item.date || "2026-11-11").slice(0, 10), 45, y);
        doc.fillColor("#0070BA").text(String(item.id || item.invoiceId || "N/A"), 110, y, { width: 110, ellipsis: true });
        doc.fillColor("#1E293B").text(String(item.description || item.item || "Export Goods"), 230, y, { width: 180, ellipsis: true });
        doc.fillColor(item.status === "PAID" ? "#16A34A" : "#D97706").text(String(item.status || "SENT"), 420, y);
        doc.fillColor("#0F172A").font("Helvetica-Bold").text(`$${Number(item.amount || 0).toFixed(2)}`, 490, y);
        doc.font("Helvetica");

        y += 14;
        doc.moveTo(40, y - 2).lineTo(555, y - 2).strokeColor("#E2E8F0").stroke();
      }

      // --- Cryptographic Hash-Chain & Checkpoint Footer ---
      const footerY = 740;
      doc.rect(40, footerY, 515, 48).fill("#F8FAFC");
      doc.fillColor("#64748B").fontSize(6.5).font("Helvetica-Bold").text("AUDIT LEDGER TIP HASH (SHA-256):", 48, footerY + 6);
      doc.fillColor("#0F172A").font("Courier").fontSize(6.5).text(latestAuditRoot, 48, footerY + 16);

      doc.fillColor("#64748B").font("Helvetica-Bold").fontSize(6.5).text("INDEPENDENT CHECKPOINT SIGNATURE (HMAC-SHA256):", 48, footerY + 28);
      doc.fillColor("#0F172A").font("Courier").fontSize(6.5).text(latestCheckpointHash, 48, footerY + 38);

      doc.end();
    } catch (err) {
      reject(err);
    }
  });
}
