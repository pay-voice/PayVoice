import { Router } from "express";
import { appendAuditEntry } from "../services/auditLedger.js";

const router = Router();

/**
 * POST /api/webhooks/paypal
 * Ingests PayPal Webhook notifications (e.g. INVOICING.INVOICE.PAID)
 */
router.post("/paypal", async (req, res) => {
  try {
    const event = req.body || {};
    const eventType = event.event_type || "UNKNOWN_EVENT";
    const resource = event.resource || {};
    const invoiceId = resource.id || resource.invoice_id || "N/A";

    console.log(`[PayPal Webhook Received]: ${eventType} for Invoice ID: ${invoiceId}`);

    // Record immutable audit entry
    appendAuditEntry({
      transcript: `PayPal Webhook Event: ${eventType}`,
      stagedPayload: { eventType, resourceId: resource.id, status: resource.status },
      passkeyAssertionId: "PAYPAL_WEBHOOK_SIGNATURE",
      invoiceId,
      status: eventType === "INVOICING.INVOICE.PAID" ? "PAID" : eventType,
      metadata: { eventId: event.id, createTime: event.create_time },
    });

    return res.status(200).json({
      received: true,
      eventType,
      invoiceId,
      recordedAt: new Date().toISOString(),
    });
  } catch (error) {
    console.error("[Webhook Error]:", error);
    return res.status(500).json({ error: "Webhook processing failure: " + error.message });
  }
});

export default router;
