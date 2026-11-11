/**
 * PayVoice Cryptographic @paypal/agent-toolkit Guardrail Proxy
 * PayPal AI Hackathon 2026 - Track: Security, Guardrails & Cryptography (Shoury)
 *
 * Implements a strict cryptographic boundary around @paypal/agent-toolkit:
 *   - Write Operations (create_invoice, send_invoice):
 *       Refuses execution unless accompanied by an unconsumed HMAC-signed securityExecutionTicket
 *       issued after Money Guide AI policy checks, read-back confirmation, and WebAuthn passkey assertion.
 *       Logs any direct or unticketed tool call as BLOCKED_UNVERIFIED_TOOL_CALL in the Audit Ledger.
 *   - Read Operations (list_transactions, get_merchant_insights, list_invoices, get_invoice):
 *       Pipes raw PayPal responses through the AES-256-GCM Vault to tokenize customer PII into
 *       opaque BUYER_* tokens and attaches deterministic Money Guide math summaries so the LLM
 *       never computes financial totals itself.
 */

import crypto from "crypto";
import { appendAuditEntry } from "./auditLedger.js";
import { redactPIIBeforeLLM, listMaskedBuyers, resolveBuyerForExecution } from "./vault.js";
import { computeTransactionTotals, analyzeMerchantAnomalies } from "./moneyGuide.js";

const TICKET_SECRET = process.env.TICKET_SECRET || process.env.VAULT_SECRET || "payvoice-ticket-secret-2026";
const TICKET_TTL_MS = 10 * 60 * 1000; // 10 minutes

// In-memory single-use replay protection sets
const consumedTickets = new Set();
const activeTickets = new Map();

/**
 * Derives a cryptographic HMAC-SHA256 signature for a security ticket
 */
function computeTicketSignature(preimage) {
  return crypto.createHmac("sha256", TICKET_SECRET).update(preimage).digest("hex");
}

/**
 * Issues an HMAC-signed single-use security execution ticket
 * Only callable after Money Guide policy evaluation, read-back confirmation,
 * and WebAuthn hardware passkey verification.
 *
 * @param {object} params
 * @param {string} params.assertionId - Verified WebAuthn assertion ID
 * @param {string} params.buyerToken - Allowlisted buyer token (e.g. BUYER_RAHUL_01)
 * @param {number} params.amount - Validated numeric amount
 * @param {string} params.currency - Validated currency (USD/EUR)
 * @param {string} params.item - Sanitized item description
 * @returns {object} ticket
 */
export function issueSecurityExecutionTicket({ assertionId, buyerToken, amount, currency = "USD", item = "" }) {
  if (!assertionId || typeof assertionId !== "string") {
    throw new Error("Cannot issue security ticket: Missing or invalid WebAuthn assertionId.");
  }
  if (!buyerToken || !buyerToken.startsWith("BUYER_")) {
    throw new Error("Cannot issue security ticket: Missing or un-tokenized buyerToken.");
  }

  const numAmount = Number(amount);
  if (isNaN(numAmount) || numAmount <= 0) {
    throw new Error("Cannot issue security ticket: Invalid non-positive amount.");
  }

  const ticketId = `TICKET_${crypto.randomBytes(12).toString("hex").toUpperCase()}`;
  const issuedAt = Date.now();
  const expiresAt = issuedAt + TICKET_TTL_MS;
  const normCurrency = String(currency).trim().toUpperCase();
  const normItem = String(item).trim();

  const preimage = `${ticketId}|${assertionId}|${buyerToken}|${numAmount.toFixed(2)}|${normCurrency}|${normItem}|${expiresAt}`;
  const signature = computeTicketSignature(preimage);

  const ticket = {
    ticketId,
    assertionId,
    buyerToken,
    amount: numAmount,
    currency: normCurrency,
    item: normItem,
    issuedAt,
    expiresAt,
    signature,
  };

  activeTickets.set(ticketId, ticket);
  return ticket;
}

/**
 * Cryptographically verifies an execution ticket without consuming it
 *
 * @param {object} ticket
 * @param {object} [expectedPayload={}]
 * @returns {{ valid: boolean, reason?: string, ticket?: object }}
 */
export function verifySecurityExecutionTicket(ticket, expectedPayload = {}) {
  if (!ticket || typeof ticket !== "object") {
    return { valid: false, reason: "Missing or null execution ticket" };
  }

  const { ticketId, assertionId, buyerToken, amount, currency, item, expiresAt, signature } = ticket;

  if (!ticketId || !signature) {
    return { valid: false, reason: "Malformed ticket: Missing ticketId or HMAC signature" };
  }

  if (consumedTickets.has(ticketId)) {
    return { valid: false, reason: `Replay attack detected: Ticket '${ticketId}' has already been consumed` };
  }

  if (Date.now() > Number(expiresAt)) {
    return { valid: false, reason: `Execution ticket '${ticketId}' has expired` };
  }

  const numAmount = Number(amount);
  const preimage = `${ticketId}|${assertionId}|${buyerToken}|${numAmount.toFixed(2)}|${currency}|${item}|${expiresAt}`;
  const expectedSig = computeTicketSignature(preimage);

  try {
    const isSigMatch = crypto.timingSafeEqual(Buffer.from(signature, "hex"), Buffer.from(expectedSig, "hex"));
    if (!isSigMatch) {
      return { valid: false, reason: "Cryptographic ticket signature verification failed" };
    }
  } catch {
    return { valid: false, reason: "Invalid ticket signature encoding" };
  }

  // Cross-verify bound parameters if expected payload provided
  if (expectedPayload.buyerToken && expectedPayload.buyerToken !== buyerToken) {
    return { valid: false, reason: `Ticket buyer mismatch: expected ${expectedPayload.buyerToken}, found ${buyerToken}` };
  }

  if (expectedPayload.amount !== undefined) {
    const expAmt = Number(expectedPayload.amount);
    if (!isNaN(expAmt) && Math.abs(expAmt - numAmount) > 0.001) {
      return { valid: false, reason: `Ticket amount mismatch: expected ${expAmt}, found ${numAmount}` };
    }
  }

  if (expectedPayload.currency && expectedPayload.currency.toUpperCase() !== currency) {
    return { valid: false, reason: `Ticket currency mismatch: expected ${expectedPayload.currency}, found ${currency}` };
  }

  return { valid: true, ticket };
}

/**
 * Consumes a security ticket, enforcing strict single-use execution
 *
 * @param {object} ticket
 * @returns {boolean}
 */
export function consumeSecurityExecutionTicket(ticket) {
  const check = verifySecurityExecutionTicket(ticket);
  if (!check.valid) {
    throw new Error(`Cannot consume execution ticket: ${check.reason}`);
  }
  consumedTickets.add(ticket.ticketId);
  activeTickets.delete(ticket.ticketId);
  return true;
}

/**
 * Resets consumed tickets cache (used strictly in test and benchmark suites)
 */
export function clearConsumedTicketsForTesting() {
  consumedTickets.clear();
  activeTickets.clear();
}

/**
 * Wraps @paypal/agent-toolkit tools with the PayVoice cryptographic security boundary
 *
 * @param {object} rawTools - The tools object returned by paypalToolkit.getTools()
 * @returns {object} secureTools
 */
export function wrapPayPalToolkitWithSecurityGate(rawTools = {}) {
  const tools = rawTools || {};
  const isNested = Boolean(tools.invoices || tools.transactions || tools.insights);

  /**
   * Internal guard for write tools: create_invoice and send_invoice
   */
  async function executeGuardedWrite(toolName, underlyingFn, args = {}) {
    const ticket = args.securityExecutionTicket || args.ticket || args._ticket;

    const check = verifySecurityExecutionTicket(ticket, {
      buyerToken: args.buyerToken || args.primaryRecipients?.[0]?.billingInfo?.name?.givenName,
      amount: args.amount || args.items?.[0]?.unitAmount?.value,
      currency: args.currency || args.detail?.currencyCode,
    });

    if (!check.valid) {
      // Record unauthorized tool execution attempt to immutable audit ledger
      appendAuditEntry({
        transcript: `[SECURITY INTERCEPT] Unauthorized attempt to invoke write tool '${toolName}'`,
        stagedPayload: { toolName, argsPreview: { ...args, securityExecutionTicket: undefined } },
        passkeyAssertionId: "UNVERIFIED_DIRECT_TOOL_CALL",
        invoiceId: args.invoiceId || "UNAUTHORIZED",
        status: "BLOCKED_UNVERIFIED_TOOL_CALL",
        metadata: {
          violation: "MISSING_OR_INVALID_SECURITY_EXECUTION_TICKET",
          reason: check.reason,
          interceptedAt: new Date().toISOString(),
        },
      });

      throw new Error(
        `[PayVoice Security Boundary] Execution of write tool '${toolName}' BLOCKED: ${check.reason}. Live financial mutations require an unconsumed WebAuthn-backed securityExecutionTicket.`
      );
    }

    // Single-use burn
    consumeSecurityExecutionTicket(ticket);

    // If underlying function is available, execute it
    if (typeof underlyingFn === "function") {
      return await underlyingFn(args);
    }

    // Default simulated sandbox execution for standalone mock/test mode
    return {
      status: "SUCCESS",
      simulated: true,
      toolName,
      ticketId: ticket.ticketId,
      assertionId: ticket.assertionId,
      executedAt: new Date().toISOString(),
    };
  }

  /**
   * Internal guard for read tools: tokenizes outbound PII and attaches deterministic math
   */
  async function executeGuardedRead(toolName, underlyingFn, args = {}) {
    let result = null;
    if (typeof underlyingFn === "function") {
      result = await underlyingFn(args);
    } else {
      result = { items: [] };
    }

    // 1. Pass response through PII redaction/tokenization
    const resultJson = JSON.stringify(result);
    const redactedJson = redactPIIBeforeLLM(resultJson);
    let sanitizedResult;
    try {
      sanitizedResult = JSON.parse(redactedJson);
    } catch {
      sanitizedResult = result;
    }

    // 2. Attach deterministic math summaries so LLM never calculates financial totals
    if (toolName.includes("transaction") || toolName.includes("invoice")) {
      const txItems = Array.isArray(sanitizedResult)
        ? sanitizedResult
        : sanitizedResult.items || sanitizedResult.transactions || [];

      if (Array.isArray(txItems) && txItems.length > 0) {
        const mathSummary = computeTransactionTotals(txItems);
        const anomalyReport = analyzeMerchantAnomalies(txItems);

        return {
          ...sanitizedResult,
          moneyGuideDeterministicSummary: mathSummary,
          anomalyAlerts: anomalyReport.alerts,
          _payvoiceGuarded: true,
        };
      }
    }

    return {
      ...sanitizedResult,
      _payvoiceGuarded: true,
    };
  }

  // Construct secure wrapper preserving both flat and nested calling styles
  if (isNested) {
    return {
      invoices: {
        create: (args) => executeGuardedWrite("invoices.create", tools.invoices?.create, args),
        send: (args) => executeGuardedWrite("invoices.send", tools.invoices?.send, args),
        get: (args) => executeGuardedRead("invoices.get", tools.invoices?.get, args),
        list: (args) => executeGuardedRead("invoices.list", tools.invoices?.list, args),
      },
      transactions: {
        list: (args) => executeGuardedRead("transactions.list", tools.transactions?.list, args),
      },
      insights: {
        get: (args) => executeGuardedRead("insights.get", tools.insights?.get, args),
      },
      // Convenience flat accessors
      create_invoice: (args) => executeGuardedWrite("create_invoice", tools.invoices?.create, args),
      send_invoice: (args) => executeGuardedWrite("send_invoice", tools.invoices?.send, args),
      get_invoice: (args) => executeGuardedRead("get_invoice", tools.invoices?.get, args),
      list_invoices: (args) => executeGuardedRead("list_invoices", tools.invoices?.list, args),
      list_transactions: (args) => executeGuardedRead("list_transactions", tools.transactions?.list, args),
      get_merchant_insights: (args) => executeGuardedRead("get_merchant_insights", tools.insights?.get, args),
    };
  }

  // Flat wrapper
  return {
    create_invoice: (args) => executeGuardedWrite("create_invoice", tools.create_invoice, args),
    send_invoice: (args) => executeGuardedWrite("send_invoice", tools.send_invoice, args),
    get_invoice: (args) => executeGuardedRead("get_invoice", tools.get_invoice, args),
    list_invoices: (args) => executeGuardedRead("list_invoices", tools.list_invoices, args),
    list_transactions: (args) => executeGuardedRead("list_transactions", tools.list_transactions, args),
    get_merchant_insights: (args) => executeGuardedRead("get_merchant_insights", tools.get_merchant_insights, args),
    // Nested compatibility mapping
    invoices: {
      create: (args) => executeGuardedWrite("invoices.create", tools.create_invoice, args),
      send: (args) => executeGuardedWrite("invoices.send", tools.send_invoice, args),
      get: (args) => executeGuardedRead("invoices.get", tools.get_invoice, args),
      list: (args) => executeGuardedRead("invoices.list", tools.list_invoices, args),
    },
    transactions: {
      list: (args) => executeGuardedRead("transactions.list", tools.list_transactions, args),
    },
    insights: {
      get: (args) => executeGuardedRead("insights.get", tools.get_merchant_insights, args),
    },
  };
}
