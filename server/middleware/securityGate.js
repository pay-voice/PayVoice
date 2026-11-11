/**
 * PayVoice Turnkey Step-Up Security Gate Middleware
 * One-line Express middleware protecting live financial execution routes.
 * Enforces:
 *   1. Prompt-Injection / Untrusted Input Firewall Check
 *   2. Deterministic Money Guide Policy Validation (OPGSP cap, currency, idempotency, read-back)
 *   3. Cryptographic WebAuthn Passkey Assertion Verification (single-use bound to payload hash)
 *   4. Opaque Buyer De-tokenization via PII Vault Boundary
 *   5. Append AUTHORIZED transition to Tamper-Evident Audit Ledger
 */

import { inspectUntrustedInput } from "../services/guardrail.js";
import { evaluateTransactionPolicy } from "../services/moneyGuide.js";
import { resolveBuyerForExecution } from "../services/vault.js";
import { verifyPasskeyAssertion } from "../routes/auth.js";
import { appendAuditEntry } from "../services/auditLedger.js";
import { issueSecurityExecutionTicket } from "../services/secureToolkitWrapper.js";

export function requireStepUpSecurityGate(req, res, next) {
  try {
    const {
      challengeId,
      assertion,
      stagedPayload,
      expectedPayloadHash,
      cameraProof,
      requireCameraLiveness = false,
    } = req.body || {};

    if (!stagedPayload || typeof stagedPayload !== "object") {
      return res.status(400).json({
        success: false,
        error: "Missing required stagedPayload in request body.",
      });
    }

    // 1. Prompt-Injection / Untrusted Input Firewall Check on all text fields
    const fieldsToInspect = [
      stagedPayload.item,
      stagedPayload.note,
      stagedPayload.memo,
      req.body.transcript,
    ].filter(Boolean);

    for (const text of fieldsToInspect) {
      const guard = inspectUntrustedInput(text);
      if (!guard.safe) {
        appendAuditEntry({
          transcript: `Firewall Intercept during Gatekeeper: ${text}`,
          stagedPayload,
          passkeyAssertionId: "GATEKEEPER_FIREWALL_BLOCKED",
          status: "BLOCKED_ATTACK",
          metadata: { blockedPattern: guard.blockedPattern, reason: guard.reason },
        });

        return res.status(400).json({
          success: false,
          error: "Security Firewall Intercept",
          blockedPattern: guard.blockedPattern,
          details: guard.reason,
        });
      }
    }

    // 2. Deterministic Money Guide AI Policy Validation
    const policyResult = evaluateTransactionPolicy(
      {
        buyer_token: stagedPayload.buyerToken,
        item: stagedPayload.item,
        amount: stagedPayload.amount,
        currency: stagedPayload.currency,
        readBackConfirmed: stagedPayload.readBackConfirmed,
      },
      { requireReadBack: true }
    );

    if (!policyResult.approved) {
      appendAuditEntry({
        transcript: "Policy Gatekeeper Violation",
        stagedPayload,
        passkeyAssertionId: "GATEKEEPER_POLICY_REJECTED",
        status: "POLICY_VIOLATION",
        metadata: { violation: policyResult.policyViolation, message: policyResult.message },
      });

      return res.status(422).json({
        success: false,
        error: policyResult.policyViolation,
        message: policyResult.message,
        policySnapshot: policyResult.policySnapshot,
      });
    }

    // 3. Cryptographic WebAuthn Passkey Assertion Verification
    const payloadHashToVerify = expectedPayloadHash || stagedPayload.payloadHash;
    const authResult = verifyPasskeyAssertion({
      challengeId,
      assertion,
      expectedPayloadHash: payloadHashToVerify,
      cameraProof,
      requireCameraLiveness,
      expectedRpId: req.hostname || "localhost",
    });

    if (!authResult.verified) {
      appendAuditEntry({
        transcript: "WebAuthn Assertion Denied at Gatekeeper",
        stagedPayload,
        passkeyAssertionId: "GATEKEEPER_ASSERTION_DENIED",
        status: "WEBAUTHN_REJECTED",
        metadata: { reason: authResult.reason },
      });

      return res.status(403).json({
        success: false,
        error: "WebAuthn Security Gate Denied",
        details: authResult.reason,
      });
    }

    // 4. Boundary De-tokenization: Only decrypt PII with verified assertion ID
    const deTokenizedBuyer = resolveBuyerForExecution(
      stagedPayload.buyerToken,
      authResult.assertionId
    );

    if (!deTokenizedBuyer) {
      return res.status(404).json({
        success: false,
        error: "Buyer de-tokenization failed. Token not found in verified vault.",
      });
    }

    // 5. Issue cryptographic single-use execution ticket for write operations
    const securityExecutionTicket = issueSecurityExecutionTicket({
      assertionId: authResult.assertionId,
      buyerToken: stagedPayload.buyerToken,
      amount: stagedPayload.amount,
      currency: stagedPayload.currency,
      item: stagedPayload.item,
    });

    // 6. Append AUTHORIZED entry to immutable audit ledger
    const auditRecord = appendAuditEntry({
      transcript: `Security Gate Authorized: ${stagedPayload.item} for ${stagedPayload.buyerToken}`,
      stagedPayload,
      passkeyAssertionId: authResult.assertionId,
      invoiceId: "PENDING_DISPATCH",
      status: "AUTHORIZED",
      metadata: {
        buyerToken: stagedPayload.buyerToken,
        amount: stagedPayload.amount,
        currency: stagedPayload.currency,
        assertionId: authResult.assertionId,
        userVerified: authResult.userVerified,
        ticketId: securityExecutionTicket.ticketId,
      },
    });

    // 7. Attach verified, de-tokenized sandbox payload to request for downstream PayPal route
    req.verifiedPayPalPayload = {
      buyerToken: stagedPayload.buyerToken,
      recipientName: deTokenizedBuyer.legalName,
      recipientEmail: deTokenizedBuyer.email,
      item: stagedPayload.item,
      quantity: stagedPayload.quantity || "1",
      amount: stagedPayload.amount,
      currency: stagedPayload.currency,
      assertionId: authResult.assertionId,
      securityExecutionTicket,
      auditRecord,
    };

    return next();
  } catch (error) {
    console.error("[Security Gatekeeper Error]:", error);
    return res.status(500).json({
      success: false,
      error: "Internal Security Gatekeeper failure: " + error.message,
    });
  }
}
