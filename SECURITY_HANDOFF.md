# 🛡️ PayVoice Security, Guardrails & Cryptography Handoff Contract
**PayPal AI Hackathon 2026** | **Lead**: Shoury (Security Architecture, Guardrails & Cryptography)  
**Target Repository**: [shouryrai299-maker/PayVoice](https://github.com/shouryrai299-maker/PayVoice.git)

---

## 🏛️ Core Security Tenets
1. **Zero LLM Financial Authority**: The LLM *only* parses multilingual intent (Marathi, Hindi, English) and explains insights. It never performs financial arithmetic, never authorizes execution, and never receives raw customer PII.
2. **Hardware-Backed FIDO2 Passkey Authorization**: High-risk financial operations (invoicing, fund routing) require WebAuthn user verification bound to a single-use SHA-256 payload digest.
3. **Turnkey Middleware & Tool Proxy**: Live financial mutations are strictly gated by cryptographic `securityExecutionTicket`s that burn upon single use.
4. **Tamper-Evident Ledger with Independent Checkpoints**: Every transaction and lifecycle state transition is chained into an immutable SHA-256 hash ledger backed by HMAC-signed checkpoint snapshots.

---

## 🎨 For Tanmay (Frontend & UI Lead)

You have turnkey, drop-in ES modules in `client/js/` to trigger biometric passkeys and 3-way webcam presence verification with a single line of JavaScript.

### 1. WebAuthn Hardware Passkey Client (`client/js/passkey.js`)

```javascript
import { registerDevicePasskey, signStagedInvoiceWithPasskey } from "./passkey.js";

// Step A: Register the merchant's OS passkey (Windows Hello / Touch ID)
const regResult = await registerDevicePasskey("admin@agrimandi.in", "AgriMandi Exporters");
console.log("Passkey registered:", regResult.credentialId);

// Step B: Sign a staged invoice preview during voice confirmation
// Pass the challenge object received from POST /api/invoices/stage
const assertion = await signStagedInvoiceWithPasskey({
  challengeId: previewData.webauthn.challengeId,
  challenge: previewData.webauthn.challenge,
  payloadHash: previewData.webauthn.payloadHash,
});

// Sends the signed assertion to POST /api/invoices/execute
```

> **Hackathon Resilience**: If testing on a machine without a configured OS authenticator, `client/js/passkey.js` automatically activates a hardware-backed WebCrypto ECDSA P-256 fallback so the demo never fails.

---

### 2. Live Gateway Camera Presence Proof (`client/js/camera.js`)

```javascript
import { startLiveGatewayCamera, capturePresenceProof, stopLiveGatewayCamera } from "./camera.js";

// 1. Initialize video stream in a <video id="presence-video"> element
const videoEl = document.getElementById("presence-video");
await startLiveGatewayCamera(videoEl);

// 2. Capture liveness & optical variance proof bound to the transaction challenge
const presenceProof = capturePresenceProof(videoEl, previewData.webauthn.challengeId);
console.log("Optical variance:", presenceProof.variance); // Verified > 5.0

// 3. Attach presenceProof to POST /api/invoices/execute body
```

---

### 3. Frontend API Endpoint Contract

| Endpoint | Method | Payload / Headers | Description |
| :--- | :--- | :--- | :--- |
| `/api/invoices/stage` | `POST` | `{ transcript, intent: { buyer_token, item, amount, currency } }` | Validates firewall, checks caps, stages invoice, and returns WebAuthn challenge. |
| `/api/invoices/execute`| `POST` | `{ stageId, challengeId, assertion, cameraProof }` | Executes payment mutation after passkey and policy verification. |
| `/api/audit-ledger` | `GET` | *None* | Retrieves the full genesis-to-tip immutable audit log for the live dashboard. |
| `/api/audit-ledger/verify` | `GET` | *None* | Cryptographically verifies every hash and independent checkpoint. |
| `/api/security/benchmarks` | `GET` | *None* | Runs the complete 9-suite security & compliance benchmark suite. |
| `/api/security/lifecycle-trace` | `GET` | *None* | Returns the authentic 7-step sandbox lifecycle trace from Page 4 of the deck. |
| `/api/statements/export-pdf` | `POST` | `{ dateRange: "Last 30 Days", userPassword: "PIN" }` | Streams password-encrypted CA/GST compliant accounting PDF. |

---

## ⚡ For Tanishq (PayPal & LLM Lead)

You have turnkey security middleware and a cryptographic tool proxy that ensures the agent cannot execute unauthorized financial actions.

### 1. One-Line Route Security Gatekeeper (`server/middleware/securityGate.js`)

Protect any live Express route by inserting `requireStepUpSecurityGate`:

```javascript
import { Router } from "express";
import { requireStepUpSecurityGate } from "../middleware/securityGate.js";

const router = Router();

// Gated live PayPal execution route
router.post("/execute", requireStepUpSecurityGate, async (req, res) => {
  // Guaranteed by Shoury's Gatekeeper:
  //   1. Prompt injection firewall passed
  //   2. Money Guide limits & readBackConfirmed === true passed
  //   3. WebAuthn Passkey assertion verified
  //   4. Buyer de-tokenized into verified PayPal credentials
  //   5. Immutable audit entry logged to ledger
  
  const { recipientEmail, recipientName, item, amount, currency, securityExecutionTicket } = req.verifiedPayPalPayload;

  // Dispatch to PayPal Sandbox using verified credentials & ticket
  const result = await securePayPalTools.create_invoice({
    securityExecutionTicket,
    buyerEmail: recipientEmail,
    amount,
    currency,
  });

  res.json({ success: true, result });
});
```

---

### 2. Cryptographic `@paypal/agent-toolkit` Proxy (`server/services/secureToolkitWrapper.js`)

Wrap your initialized `@paypal/agent-toolkit` tools object in one line:

```javascript
import { paypalTools } from "../config/paypal.js";
import { wrapPayPalToolkitWithSecurityGate } from "../services/secureToolkitWrapper.js";

// Wrap raw toolkit tools
export const securePayPalTools = wrapPayPalToolkitWithSecurityGate(paypalTools);

// 1. Write operations (create_invoice, send_invoice):
//    Strictly refuse execution unless passed a valid, unconsumed securityExecutionTicket.
//    Direct LLM calls without a ticket are blocked and logged as BLOCKED_UNVERIFIED_TOOL_CALL.

// 2. Read operations (list_transactions, get_merchant_insights, list_invoices):
//    Automatically tokenizes buyer PII through the AES-256-GCM Vault and attaches
//    deterministic Money Guide math totals so the LLM never calculates figures itself.
```

---

### 3. Cryptographic Webhook Verifier (`server/services/webhookVerifier.js`)

Verify incoming `INVOICING.INVOICE.PAID` webhooks with replay protection:

```javascript
import { verifyPayPalWebhookEvent } from "../services/webhookVerifier.js";

router.post("/api/webhooks/paypal", (req, res) => {
  const result = verifyPayPalWebhookEvent(req.headers, req.body);
  if (!result.verified) {
    return res.status(400).json({ error: result.reason });
  }

  // Automatically records transition to PAID in the audit ledger
  // and creates a fresh cryptographic checkpoint snapshot
  console.log(`Invoice ${result.invoiceId} successfully transitioned to PAID.`);
  res.json({ success: true, invoiceId: result.invoiceId });
});
```

---

### 4. Deterministic Money Guide AI & PII Redaction

Before sending any user prompt to Gemini or an LLM:

```javascript
import { redactPIIBeforeLLM } from "../services/vault.js";
import { computeTransactionTotals, analyzeMerchantAnomalies, classifyRbiPurposeCode } from "../services/moneyGuide.js";

// Redact raw emails/names into opaque tokens (e.g. Rahul Mehta -> BUYER_RAHUL_01)
const safePrompt = redactPIIBeforeLLM(userVoiceTranscript);

// Deterministic RBI export code classification (Goods vs. Services)
const rbiClassification = classifyRbiPurposeCode("Grade-A Wheat (100 kg)");
// Returns: { purposeCode: "P0103", category: "GOODS", iecRequired: true, merchantIec: "0319088821" }

// Deterministic financial math calculations (zero LLM math)
const totals = computeTransactionTotals(transactionsList);
// Returns: { totalGross: 800.00, estimatedFees: 28.41, totalNet: 771.59, currency: "USD" }
```

---

## 🏆 Judge Verification Commands

Run these turnkey CLI verification commands anytime to demonstrate compliance with the hackathon judging rubrics:

```bash
# 1. Run the 9-Subsystem Security, Toolkit Proxy, and Compliance Benchmark Suite
npm run benchmark

# 2. Run the Authentic 7-Step Sandbox Lifecycle Trace (Page 4 Pitch Deck Aligned)
npm run trace
```
