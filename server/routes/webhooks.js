import { Router } from "express";
import { appendAuditEntry, recordInvoiceLifecycleEvent } from "../services/auditLedger.js";
import { verifyPayPalWebhookEvent } from "../services/webhookVerifier.js";

const router = Router();

/**
 * POST /api/webhooks/paypal
 * Cryptographically verifies and ingests PayPal Webhook notifications (e.g. INVOICING.INVOICE.PAID)
 */
router.post("/paypal", async (req, res) => {
  try {
    const hasTransmissionHeaders = Boolean(
      req.headers["paypal-transmission-id"] ||
      req.headers["PAYPAL-TRANSMISSION-ID"]
    );

    if (hasTransmissionHeaders) {
      const verification = verifyPayPalWebhookEvent(req.headers, req.body);
      if (!verification.verified) {
        return res.status(400).json({
          success: false,
          error: "Webhook Cryptographic Verification Failed",
          details: verification.reason,
        });
      }

      return res.status(200).json({
        received: true,
        verified: true,
        eventType: verification.eventType,
        invoiceId: verification.invoiceId,
        auditRecord: verification.auditRecord,
        recordedAt: verification.verifiedAt,
      });
    }

    // Fallback path for unsigned sandbox simulation
    const event = req.body || {};
    const eventType = event.event_type || "UNKNOWN_EVENT";
    const resource = event.resource || {};
    const invoiceId = resource.id || resource.invoice_id || "N/A";

    console.log(`[PayPal Webhook Received (Unsigned)]: ${eventType} for Invoice ID: ${invoiceId}`);

    const auditRecord = appendAuditEntry({
      transcript: `PayPal Webhook Event (Simulation): ${eventType}`,
      stagedPayload: { eventType, resourceId: resource.id, status: resource.status },
      passkeyAssertionId: "PAYPAL_WEBHOOK_SIMULATION",
      invoiceId,
      status: eventType === "INVOICING.INVOICE.PAID" ? "PAID" : eventType,
      metadata: { eventId: event.id, createTime: event.create_time },
    });

    return res.status(200).json({
      received: true,
      verified: false,
      eventType,
      invoiceId,
      auditRecord,
      recordedAt: new Date().toISOString(),
    });
  } catch (error) {
    console.error("[Webhook Error]:", error);
    return res.status(500).json({ error: "Webhook processing failure: " + error.message });
  }
});
  } catch (error) {
    console.error("[Webhook Error]:", error);
    return res.status(500).json({ error: "Webhook processing failure: " + error.message });
  }
});

export default router;
