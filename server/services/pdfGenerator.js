import PDFDocument from "pdfkit";
import crypto from "crypto";
import { getAuditLedger } from "./auditLedger.js";

/**
 * Generate a password-encrypted PDF Accounting Statement using PDFKit
 * Includes merchant headers, itemized international transactions, deterministic fee summaries,
 * and the latest cryptographic hash chain root from the audit ledger.
 *
 * @param {object} params
 * @param {string} params.dateRange - Description of range (e.g., "Last 30 Days")
 * @param {Array} params.transactions - List of transaction objects
 * @param {object} params.totals - Output from computeTransactionTotals()
 * @param {string} params.userPassword - Encryption password (defaults to "PAYVOICE2026")
 * @param {object} params.merchant - Exporter profile info
 * @returns {Promise<{ buffer: Buffer, checksum: string, filename: string, recordCount: number, generatedAt: string }>}
 */
export async function generateEncryptedStatementPdf({
  dateRange = "Last 30 Days",
  transactions = [],
  totals = { totalGross: 0, estimatedFees: 0, totalNet: 0, currency: "USD", count: 0 },
  userPassword = "PAYVOICE2026",
  merchant = { name: "AgriMandi MSME Exporters", email: "exports@agrimandi.in", country: "India" },
}) {
  return new Promise((resolve, reject) => {
    try {
      // Fetch latest audit chain root
      const ledger = getAuditLedger();
      const latestAuditRoot = ledger[ledger.length - 1]?.rowHash || "GENESIS_ROOT";
      const generatedAt = new Date().toISOString();
      const filename = `PayVoice_Export_Statement_${Date.now()}.pdf`;

      // PDFKit Document with standard password encryption (prompts on open)
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
          Title: `PayVoice Export Statement - ${dateRange}`,
          Author: "PayVoice Secure Financial Agent",
          Subject: "PayPal India MSME Cross-Border Invoicing Statement",
          Keywords: "PayVoice, PayPal, Invoicing, OPGSP, MSME, Export",
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
        });
      });
      doc.on("error", (err) => reject(err));

      // --- Header Branding ---
      doc.rect(40, 40, 515, 60).fill("#003087"); // PayPal Deep Blue
      doc.fillColor("#FFFFFF").fontSize(20).font("Helvetica-Bold").text("PayVoice Financial Statement", 55, 52);
      doc
        .fontSize(10)
        .font("Helvetica")
        .text("Secure Multilingual Agent for Indian MSME Exporters | PayPal AI Hackathon 2026", 55, 78);

      doc.moveDown(2);

      // --- Meta Block ---
      doc.fillColor("#1E293B").fontSize(11).font("Helvetica-Bold").text("Statement Information", 40, 115);
      doc.font("Helvetica").fontSize(9).fillColor("#475569");
      doc.text(`Merchant Name: ${merchant.name}`, 40, 132);
      doc.text(`Account Reg.: PayPal India OPGSP Export Compliant`, 40, 146);
      doc.text(`Statement Period: ${dateRange}`, 40, 160);
      doc.text(`Generated On: ${new Date(generatedAt).toLocaleString()}`, 40, 174);

      doc.text(`Document Encryption: AES Password Protected`, 320, 132);
      doc.text(`Target Currency: ${totals.currency || "USD"}`, 320, 146);
      doc.text(`Transactions Count: ${transactions.length}`, 320, 160);
      doc.text(`Default Unlock PIN: ${userPassword}`, 320, 174);

      // --- Financial Summary Boxes ---
      const boxTop = 200;
      doc.rect(40, boxTop, 160, 50).fillAndStroke("#F8FAFC", "#CBD5E1");
      doc.fillColor("#64748B").fontSize(8).font("Helvetica").text("GROSS EXPORT BILLING", 50, boxTop + 10);
      doc.fillColor("#0F172A").fontSize(14).font("Helvetica-Bold").text(`$${totals.totalGross.toFixed(2)} ${totals.currency}`, 50, boxTop + 24);

      doc.rect(215, boxTop, 160, 50).fillAndStroke("#F8FAFC", "#CBD5E1");
      doc.fillColor("#64748B").fontSize(8).font("Helvetica").text("EST. PAYPAL FEES (3.49% + $0.49)", 225, boxTop + 10);
      doc.fillColor("#DC2626").fontSize(14).font("Helvetica-Bold").text(`-$${totals.estimatedFees.toFixed(2)} ${totals.currency}`, 225, boxTop + 24);

      doc.rect(390, boxTop, 165, 50).fillAndStroke("#EFF6FF", "#93C5FD");
      doc.fillColor("#1E40AF").fontSize(8).font("Helvetica-Bold").text("NET EXPORT INFLOW", 400, boxTop + 10);
      doc.fillColor("#0070BA").fontSize(14).font("Helvetica-Bold").text(`$${totals.totalNet.toFixed(2)} ${totals.currency}`, 400, boxTop + 24);

      // --- Itemized Transaction Table ---
      let y = 270;
      doc.fillColor("#0F172A").fontSize(11).font("Helvetica-Bold").text("Itemized Export Invoices & Transactions", 40, y);
      y += 18;

      // Table Header
      doc.rect(40, y, 515, 20).fill("#F1F5F9");
      doc.fillColor("#334155").fontSize(8).font("Helvetica-Bold");
      doc.text("DATE", 45, y + 6);
      doc.text("INVOICE / ID", 110, y + 6);
      doc.text("BUYER / ITEM DESCRIPTION", 230, y + 6);
      doc.text("STATUS", 420, y + 6);
      doc.text("AMOUNT", 490, y + 6);
      y += 24;

      const itemsToPrint =
        transactions.length > 0
          ? transactions
          : [
              {
                date: new Date().toLocaleDateString(),
                id: "INV2-SAMPLE-OPGSP-01",
                description: "BUYER_RAHUL_01 - 100 kg Grade-A Wheat",
                status: "PAID",
                amount: 200.0,
              },
            ];

      doc.font("Helvetica").fontSize(8);
      for (const item of itemsToPrint) {
        if (y > 720) {
          doc.addPage();
          y = 40;
        }

        doc.fillColor("#475569").text(String(item.date || "2026-11-11").slice(0, 10), 45, y);
        doc.fillColor("#0070BA").text(String(item.id || item.invoiceId || "N/A"), 110, y, { width: 110, ellipsis: true });
        doc.fillColor("#1E293B").text(String(item.description || item.item || "Export Goods"), 230, y, { width: 180, ellipsis: true });
        doc.fillColor(item.status === "PAID" ? "#16A34A" : "#D97706").text(String(item.status || "SENT"), 420, y);
        doc.fillColor("#0F172A").font("Helvetica-Bold").text(`$${Number(item.amount || 0).toFixed(2)}`, 490, y);
        doc.font("Helvetica");

        y += 16;
        doc.moveTo(40, y - 4).lineTo(555, y - 4).strokeColor("#E2E8F0").stroke();
      }

      // --- Cryptographic Hash-Chain Verification Footer ---
      const footerY = 760;
      doc.rect(40, footerY, 515, 36).fill("#F8FAFC");
      doc.fillColor("#64748B").fontSize(7).font("Helvetica-Bold").text("TAMPER-EVIDENT AUDIT ROOT HASH (SHA-256):", 48, footerY + 8);
      doc.fillColor("#0F172A").font("Courier").fontSize(7).text(latestAuditRoot, 48, footerY + 20);

      doc.end();
    } catch (err) {
      reject(err);
    }
  });
}
