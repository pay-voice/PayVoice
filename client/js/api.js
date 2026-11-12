/**
 * PayVoice Centralized API Integration Layer
 * Preserves backend contracts, normalizes errors, enforces timeouts,
 * and never exposes backend secrets or encryption passwords in URLs/logs.
 */

const API_BASE = ""; // Same origin Express server
const DEFAULT_TIMEOUT_MS = 12000;

export class ApiError extends Error {
  constructor(message, { status = 0, code = "API_ERROR", details = null, data = null } = {}) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.details = details;
    this.data = data;
  }
}

/**
 * Reusable JSON fetch wrapper with timeout & error normalization
 */
export async function apiRequest(endpoint, options = {}) {
  const {
    method = "GET",
    body = undefined,
    headers = {},
    timeoutMs = DEFAULT_TIMEOUT_MS,
    signal: externalSignal,
  } = options;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  if (externalSignal) {
    externalSignal.addEventListener("abort", () => controller.abort(), { once: true });
  }

  const fetchOptions = {
    method,
    headers: {
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      ...headers,
    },
    signal: controller.signal,
  };

  if (body !== undefined) {
    fetchOptions.body = typeof body === "string" ? body : JSON.stringify(body);
  }

  try {
    const response = await fetch(`${API_BASE}${endpoint}`, fetchOptions);
    clearTimeout(timer);

    const contentType = response.headers.get("content-type") || "";
    const isJson = contentType.includes("application/json");
    const data = isJson ? await response.json().catch(() => ({})) : await response.text();

    if (!response.ok || (isJson && data && data.success === false)) {
      const message =
        (isJson && (data.message || data.details || data.error)) ||
        `Request failed (${response.status} ${response.statusText})`;
      throw new ApiError(Array.isArray(message) ? message.join("; ") : String(message), {
        status: response.status,
        code: (isJson && (data.error || data.policyViolation || data.blockedPattern)) || `HTTP_${response.status}`,
        details: isJson ? data.details || data.message || null : null,
        data: isJson ? data : null,
      });
    }

    return data;
  } catch (err) {
    clearTimeout(timer);
    if (err instanceof ApiError) throw err;
    if (err.name === "AbortError") {
      throw new ApiError("Request timed out. Please verify the PayVoice server is running.", {
        status: 408,
        code: "REQUEST_TIMEOUT",
      });
    }
    throw new ApiError(err.message || "Network connection failure. Check server connectivity.", {
      status: 0,
      code: "NETWORK_ERROR",
    });
  }
}

/**
 * Centralized API Endpoints
 */
export const api = {
  // System Config
  getConfig: () => apiRequest("/api/config"),

  // Multilingual Intent & Voice
  parseIntent: ({ transcript, language = "auto" }) =>
    apiRequest("/api/ai/parse-intent", {
      method: "POST",
      body: { transcript, language },
    }),

  // Invoices
  stageInvoice: (payload) =>
    apiRequest("/api/invoices/stage", {
      method: "POST",
      body: payload,
    }),

  executeInvoice: (payload) =>
    apiRequest("/api/invoices/execute", {
      method: "POST",
      body: payload,
      timeoutMs: 20000,
    }),

  listInvoices: () => apiRequest("/api/invoices"),

  getInvoiceStatus: (invoiceId) => apiRequest(`/api/invoices/${encodeURIComponent(invoiceId)}/status`),

  simulateInvoicePayment: (invoiceId) =>
    apiRequest(`/api/invoices/${encodeURIComponent(invoiceId)}/simulate-payment`, {
      method: "POST",
    }),

  // WebAuthn Passkey
  getRegisterChallenge: () =>
    apiRequest("/api/auth/register-challenge", {
      method: "POST",
      body: {},
    }),

  verifyRegisterPasskey: (challengeId, credential) =>
    apiRequest("/api/auth/register-verify", {
      method: "POST",
      body: { challengeId, credential },
    }),

  // Transactions & Money Guide Insights
  getTransactions: () => apiRequest("/api/transactions"),
  getCfoInsights: () => apiRequest("/api/transactions/cfo-insights"),
  getMerchantInsights: () => apiRequest("/api/transactions/insights"),

  // Buyers Vault
  getBuyers: () => apiRequest("/api/vault/buyers"),
  registerBuyer: (buyerData) =>
    apiRequest("/api/vault/buyers", {
      method: "POST",
      body: buyerData,
    }),

  // Audit Ledger & Security
  getAuditLedger: () => apiRequest("/api/audit-ledger"),
  verifyAuditLedger: () => apiRequest("/api/audit-ledger/verify"),
  simulateAttack: (attackType, customPayload = null) =>
    apiRequest("/api/security/simulate-attack", {
      method: "POST",
      body: { attackType, customPayload },
    }),
  simulateTamper: (targetIndex = null, maliciousPayload = undefined) =>
    apiRequest("/api/security/simulate-tamper", {
      method: "POST",
      body: { targetIndex, maliciousPayload },
    }),
  restoreLedger: () =>
    apiRequest("/api/security/restore-ledger", {
      method: "POST",
      body: {},
    }),
  runBenchmarks: () => apiRequest("/api/security/benchmarks", { timeoutMs: 30000 }),
  runLifecycleTrace: () => apiRequest("/api/security/lifecycle-trace", { timeoutMs: 25000 }),
  exportAuditBundle: () => apiRequest("/api/security/audit-bundle"),
  runRedTeamSuite: () => apiRequest("/api/security/redteam", { timeoutMs: 30000 }),

  // Encrypted PDF Statements (POST binary blob + cryptographic headers)
  generateStatementPdf: async ({ dateRange = "Last 30 Days", password = "PAYVOICE2026", transactions = undefined }) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 20000);
    try {
      const response = await fetch(`${API_BASE}/api/statements/pdf`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ dateRange, password, transactions }),
        signal: controller.signal,
      });
      clearTimeout(timer);

      if (!response.ok) {
        const errBody = await response.json().catch(() => ({}));
        throw new ApiError(errBody.error || `Statement generation failed (${response.status})`, {
          status: response.status,
          code: "STATEMENT_PDF_ERROR",
          data: errBody,
        });
      }

      const blob = await response.blob();
      const disposition = response.headers.get("content-disposition") || "";
      const filenameMatch = disposition.match(/filename="?([^"]+)"?/i);

      return {
        blob,
        filename: filenameMatch ? filenameMatch[1] : `PayVoice_Statement_${Date.now()}.pdf`,
        checksum: response.headers.get("X-PayVoice-SHA256") || "",
        auditRoot: response.headers.get("X-PayVoice-Audit-Root") || "",
        records: Number(response.headers.get("X-PayVoice-Records") || 0),
        generatedAt: response.headers.get("X-PayVoice-Generated-At") || new Date().toISOString(),
      };
    } catch (err) {
      clearTimeout(timer);
      if (err instanceof ApiError) throw err;
      throw new ApiError(err.message || "Failed to generate encrypted PDF statement", {
        status: 0,
        code: "NETWORK_ERROR",
      });
    }
  },

  // SSE Invoice Stream
  subscribeInvoiceStream: (handlers = {}) => {
    if (!window.EventSource) return null;
    const es = new EventSource(`${API_BASE}/api/invoices/stream`);
    if (handlers.onConnected) es.addEventListener("connected", (e) => handlers.onConnected(JSON.parse(e.data)));
    if (handlers.onStaged) es.addEventListener("invoice_staged", (e) => handlers.onStaged(JSON.parse(e.data)));
    if (handlers.onSent) es.addEventListener("invoice_sent", (e) => handlers.onSent(JSON.parse(e.data)));
    if (handlers.onPaid) es.addEventListener("invoice_paid", (e) => handlers.onPaid(JSON.parse(e.data)));
    if (handlers.onError) es.onerror = handlers.onError;
    return es;
  },
};

