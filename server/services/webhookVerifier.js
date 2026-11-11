/**
 * PayVoice Cryptographic PayPal Webhook Verifier
 * PayPal AI Hackathon 2026 - Track: Security, Guardrails & Cryptography (Shoury)
 *
 * Implements hardened webhook security for the INVOICING.INVOICE.PAID lifecycle stage:
 *   1. Webhook Replay Protection & Event Idempotency (caches event.id & transmission-id)
 *   2. Strict Timestamp Drift Rejection (rejects events > 5 minutes old)
 *   3. Cryptographic Transmission Signature Verification (HMAC-SHA256 signature verification)
 *   4. Automatic Lifecycle Transition Recording & Independent Checkpointing in Audit Ledger
 */

import crypto from "crypto";
import { recordInvoiceLifecycleEvent } from "./auditLedger.js";

const DEFAULT_WEBHOOK_SECRET = process.env.PAYPAL_WEBHOOK_SECRET || process.env.VAULT_SECRET || "payvoice-webhook-secret-2026";
const MAX_DRIFT_MS = 5 * 60 * 1000; // 5 minutes

// In-memory idempotency caches
const processedEventIds = new Set();
const processedTransmissionIds = new Set();

/**
 * Resets idempotency caches (used strictly in test and benchmark suites)
 */
export function clearWebhookIdempotencyCacheForTesting() {
  processedEventIds.clear();
  processedTransmissionIds.clear();
}

/**
 * Generates an authentic mock signed webhook payload with valid transmission headers
 *
 * @param {object} params
 * @returns {{ headers: object, rawBody: string, event: object }}
 */
export function generateMockSignedWebhook({
  eventType = "INVOICING.INVOICE.PAID",
  invoiceId = "INV2-DEMO-PAYVOICE-01",
  amount = 200.0,
  currency = "USD",
  timestamp = null,
  webhookSecret = DEFAULT_WEBHOOK_SECRET,
  webhookId = "WH-SANDBOX-9901",
} = {}) {
  const eventId = `WH_EVT_${crypto.randomBytes(8).toString("hex").toUpperCase()}`;
  const transmissionId = `TX_${crypto.randomBytes(12).toString("hex").toUpperCase()}`;
  const transmissionTime = timestamp || new Date().toISOString();

  const event = {
    id: eventId,
    event_version: "1.0",
    create_time: transmissionTime,
    resource_type: "invoices",
    event_type: eventType,
    summary: `Invoice ${invoiceId} marked as ${eventType}`,
    resource: {
      id: invoiceId,
      status: "PAID",
      amount: { currency_code: currency, value: Number(amount).toFixed(2) },
      paid_amount: { currency_code: currency, value: Number(amount).toFixed(2) },
      final_currency: currency,
    },
  };

  const rawBody = JSON.stringify(event);
  const bodySha256 = crypto.createHash("sha256").update(rawBody).digest("hex");
  const signaturePreimage = `${transmissionId}|${transmissionTime}|${webhookId}|${bodySha256}`;
  const transmissionSig = crypto.createHmac("sha256", webhookSecret).update(signaturePreimage).digest("hex");

  const headers = {
    "paypal-transmission-id": transmissionId,
    "paypal-transmission-time": transmissionTime,
    "paypal-transmission-sig": transmissionSig,
    "paypal-webhook-id": webhookId,
    "paypal-auth-algo": "HMAC-SHA256",
  };

  return { headers, rawBody, event };
}

/**
 * Cryptographically verifies a PayPal webhook event and commits immutable audit transition
 *
 * @param {object} headers - Incoming HTTP request headers
 * @param {string | object} rawBody - Raw webhook JSON payload
 * @param {string} [customSecret] - Webhook verification secret
 * @returns {{ verified: boolean, reason?: string, event?: object, invoiceId?: string, auditRecord?: object }}
 */
export function verifyPayPalWebhookEvent(headers = {}, rawBody, customSecret = null) {
  const secret = customSecret || DEFAULT_WEBHOOK_SECRET;

  // 1. Normalize headers (case-insensitive)
  const normHeaders = {};
  for (const [k, v] of Object.entries(headers || {})) {
    normHeaders[k.toLowerCase()] = v;
  }

  const transmissionId = normHeaders["paypal-transmission-id"];
  const transmissionTime = normHeaders["paypal-transmission-time"];
  const transmissionSig = normHeaders["paypal-transmission-sig"];
  const webhookId = normHeaders["paypal-webhook-id"] || "WH-SANDBOX-9901";

  if (!transmissionId || !transmissionTime || !transmissionSig) {
    return {
      verified: false,
      reason: "Missing mandatory PayPal transmission signature headers (paypal-transmission-id, paypal-transmission-time, paypal-transmission-sig)",
    };
  }

  // 2. Enforce Timestamp Drift Window (prevent stale/delayed injection)
  const eventTimeMs = new Date(transmissionTime).getTime();
  const now = Date.now();
  if (isNaN(eventTimeMs) || Math.abs(now - eventTimeMs) > MAX_DRIFT_MS) {
    return {
      verified: false,
      reason: `Webhook timestamp drift exceeded: Transmission timestamp is ${Math.round(Math.abs(now - eventTimeMs) / 1000)}s out of sync (maximum allowed window: ${MAX_DRIFT_MS / 1000}s).`,
    };
  }

  // 3. Replay Protection: Check if transmission ID already consumed
  if (processedTransmissionIds.has(transmissionId)) {
    return {
      verified: false,
      reason: `Replay attack detected: Transmission ID '${transmissionId}' has already been processed and consumed.`,
    };
  }

  // Parse raw body if needed
  let event = null;
  let rawBodyStr = "";
  if (typeof rawBody === "string") {
    rawBodyStr = rawBody;
    try {
      event = JSON.parse(rawBody);
    } catch {
      return { verified: false, reason: "Malformed webhook rawBody: Unable to parse JSON" };
    }
  } else if (rawBody && typeof rawBody === "object") {
    event = rawBody;
    rawBodyStr = JSON.stringify(rawBody);
  } else {
    return { verified: false, reason: "Missing or invalid webhook body" };
  }

  const eventId = event.id;
  if (!eventId) {
    return { verified: false, reason: "Malformed webhook payload: Missing event.id" };
  }

  // Replay Protection: Check if event.id already consumed
  if (processedEventIds.has(eventId)) {
    return {
      verified: false,
      reason: `Replay attack detected: Webhook event.id '${eventId}' has already been processed and consumed.`,
    };
  }

  // 4. Verify Cryptographic Signature
  const bodySha256 = crypto.createHash("sha256").update(rawBodyStr).digest("hex");
  const signaturePreimage = `${transmissionId}|${transmissionTime}|${webhookId}|${bodySha256}`;
  const expectedSig = crypto.createHmac("sha256", secret).update(signaturePreimage).digest("hex");

  try {
    const isMatch = crypto.timingSafeEqual(
      Buffer.from(transmissionSig, "hex"),
      Buffer.from(expectedSig, "hex")
    );
    if (!isMatch) {
      return { verified: false, reason: "Cryptographic signature verification failed: Payload hash does not match signature header" };
    }
  } catch {
    return { verified: false, reason: "Invalid transmission signature encoding" };
  }

  // Mark consumed in idempotency cache
  processedTransmissionIds.add(transmissionId);
  processedEventIds.add(eventId);

  // 5. Extract Invoice ID and record state transition in Audit Ledger
  const eventType = event.event_type || "UNKNOWN";
  const resource = event.resource || {};
  const invoiceId = resource.id || resource.invoice?.id || resource.invoice_id || "INV-GENERIC";

  let auditRecord = null;
  if (eventType === "INVOICING.INVOICE.PAID" || eventType.includes("PAID")) {
    auditRecord = recordInvoiceLifecycleEvent(invoiceId, "SENT", "PAID", {
      eventId,
      transmissionId,
      amount: resource.amount?.value,
      currency: resource.amount?.currency_code,
      verifiedAt: new Date().toISOString(),
    });
  }

  return {
    verified: true,
    eventId,
    eventType,
    invoiceId,
    auditRecord,
    verifiedAt: new Date().toISOString(),
  };
}
