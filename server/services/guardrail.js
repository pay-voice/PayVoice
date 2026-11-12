import crypto from "crypto";
import { appendAuditEntry } from "./auditLedger.js";

/**
 * PayVoice Prompt-Injection & Schema Firewall
 * Treats all voice transcripts, item descriptions, and external invoice memos as untrusted inputs.
 */

const ADVERSARIAL_PATTERNS = [
  { regex: /ignore\s+(all\s+)?(previous\s+)?(rules|instructions|prompts|commands)/i, label: "prompt_injection_override" },
  { regex: /you\s+are\s+now\s+(a\s+)?(system\s+admin|root|super\s*user|developer\s+mode)/i, label: "role_manipulation" },
  { regex: /disregard\s+(all\s+)?(safety\s+)?(safeguards|constraints|limits|guidelines|rules|instructions)/i, label: "safety_bypass" },
  { regex: /bypass\s+(verification|passkey|auth|policy|limits|money\s*guide)/i, label: "auth_bypass_attempt" },
  { regex: /send\s+(\$|usd\s*|eur\s*)?[5-9][0-9]{3,}/i, label: "unauthorized_high_value_force" },
  { regex: /\b(system\s*admin|sudo\s+execute|format\s+drive|api_key|client_secret)\b/i, label: "system_privilege_escalation" },
  { regex: /\b(refund\s+all|transfer\s+all|drain\s+wallet)\b/i, label: "fraudulent_drain_pattern" },
  { regex: /refund\s+(this|the|all|my)?\s*(invoice|payment|transaction|funds|order)/i, label: "unauthorized_refund_request" },
  { regex: /(change|swap|switch|update|replace)\s+(the\s+)?(recipient|payee|beneficiary|destination|email|bank|account)\s+to/i, label: "recipient_swap_attack" },
  { regex: /(send|redirect|transfer|route|pay)\s+(the\s+)?(funds|money|amount|payout|proceeds)\s+to/i, label: "fund_redirection_attack" },
];

const RAW_EMAIL_REGEX = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/;

/**
 * Inspect untrusted inputs (transcripts, memos, descriptions) for adversarial prompt injection
 * @param {string} text - Untrusted user input
 * @returns {{ safe: boolean, blockedPattern: string | null, reason: string }}
 */
export function inspectUntrustedInput(text) {
  if (!text || typeof text !== "string") {
    return { safe: true, blockedPattern: null, reason: "Input is empty or non-string" };
  }

  // 1. Check for raw email injection (adversary attempting to bypass opaque tokenization)
  const emailMatch = text.match(RAW_EMAIL_REGEX);
  if (emailMatch) {
    return {
      safe: false,
      blockedPattern: "raw_email_injection",
      reason: `Direct email '${emailMatch[0]}' detected. Only allowlisted opaque buyer tokens (e.g., BUYER_RAHUL_01) are permitted.`,
    };
  }

  // 2. Check for known adversarial injection patterns
  for (const pattern of ADVERSARIAL_PATTERNS) {
    if (pattern.regex.test(text)) {
      return {
        safe: false,
        blockedPattern: pattern.label,
        reason: `Adversarial prompt injection pattern detected: '${pattern.label}'. Request blocked by PayVoice Firewall.`,
      };
    }
  }

  // 3. Check for suspicious delimiter / script tag injections
  if (/<\s*script\b|javascript\s*:|data\s*:\s*text\/html/i.test(text)) {
    return {
      safe: false,
      blockedPattern: "xss_injection",
      reason: "Suspicious script or HTML tag injection detected.",
    };
  }

  return { safe: true, blockedPattern: null, reason: "Input passed all firewall guardrails." };
}

/**
 * Validate that an intent JSON adheres strictly to expected schema
 * Prevents malicious or malformed keys from passing to backend processors
 * @param {object} intentJson
 * @returns {{ valid: boolean, errors: string[] }}
 */
export function validateIntentSchema(intentJson) {
  const errors = [];

  if (!intentJson || typeof intentJson !== "object") {
    return { valid: false, errors: ["Intent must be a valid JSON object"] };
  }

  const allowedActions = [
    "create_invoice",
    "check_status",
    "send_reminder",
    "export_pdf_statement",
    "financial_insight",
    "list_transactions",
    "get_insights",
    "export_statement",
  ];
  if (!allowedActions.includes(intentJson.action)) {
    errors.push(`Invalid action '${intentJson.action}'. Allowed: ${allowedActions.join(", ")}`);
  }

  if (intentJson.action === "create_invoice") {
    // buyer_token check
    if (!intentJson.buyer_token || typeof intentJson.buyer_token !== "string") {
      errors.push("Missing required field 'buyer_token'");
    } else if (!/^BUYER_[A-Z0-9_]{3,30}$/.test(intentJson.buyer_token.trim().toUpperCase())) {
      errors.push("Invalid 'buyer_token' format. Expected 'BUYER_NAME_XX'");
    }

    // amount check
    const amount = Number(intentJson.amount);
    if (isNaN(amount) || amount <= 0) {
      errors.push("Field 'amount' must be a positive number");
    }

    // currency check
    if (!intentJson.currency || typeof intentJson.currency !== "string") {
      errors.push("Missing required field 'currency'");
    }

    // item check
    if (!intentJson.item || typeof intentJson.item !== "string" || intentJson.item.trim().length === 0) {
      errors.push("Field 'item' must be a non-empty string description");
    }

    // Check item text against untrusted firewall
    const itemGuard = inspectUntrustedInput(intentJson.item);
    if (!itemGuard.safe) {
      errors.push(`Item description failed guardrail: ${itemGuard.reason}`);
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Consented CSV Ledger Formula-Injection Sanitizer & Numeric Validator
 * Protects accounting uploads against OWASP CSV / Spreadsheet Formula Injection
 * (e.g., =cmd|' /C calc'!A0, @SUM(A1:A10), +cmd, -cmd, \t=cmd).
 *
 * @param {string | Array<object> | Array<Array<string>>} csvInput
 * @returns {{ safe: boolean, blockedCell?: string, reason?: string, sanitizedRows?: Array, totalRows?: number }}
 */
export function sanitizeAndValidateCsvLedger(csvInput) {
  if (!csvInput) {
    return { safe: false, reason: "Empty CSV input provided" };
  }

  function isFormulaInjection(val) {
    if (val === null || val === undefined) return false;
    const str = String(val).trim();
    if (str.length === 0) return false;

    // Check dangerous formula prefix chars: =, @, \t, \r
    if (str.startsWith("=") || str.startsWith("@") || str.startsWith("\t") || str.startsWith("\r")) {
      return true;
    }

    // Check + or - prefixes: allowed only if it is a pure numeric number (e.g. -15.00, +250.50)
    if (str.startsWith("+") || str.startsWith("-")) {
      const remainder = str.slice(1).trim();
      if (/[|'"()`\\]|[a-zA-Z]/.test(remainder)) {
        return true;
      }
      if (isNaN(Number(str))) {
        return true;
      }
    }

    // Check for pipe command execution or DDE payload patterns
    if (/\|\s*['"]?\s*\/[a-zA-Z]/i.test(str) || /\bcmd\b|\bpowershell\b|\bcalc\b/i.test(str)) {
      return true;
    }

    return false;
  }

  const sanitizedRows = [];

  if (typeof csvInput === "string") {
    const lines = csvInput.split(/\r?\n/).map((l) => l.trim()).filter((l) => l.length > 0);
    if (lines.length === 0) {
      return { safe: false, reason: "CSV string contains no valid rows" };
    }

    const headerLine = lines[0];
    const headers = headerLine.split(",").map((h) => h.trim().replace(/^["']|["']$/g, "").toLowerCase());

    for (let r = 1; r < lines.length; r++) {
      const rawLine = lines[r];
      const cells = rawLine.split(",").map((c) => c.trim().replace(/^["']|["']$/g, ""));

      for (let c = 0; c < cells.length; c++) {
        const cell = cells[c];
        if (isFormulaInjection(cell)) {
          return {
            safe: false,
            blockedCell: cell,
            row: r + 1,
            column: headers[c] || c + 1,
            reason: `Spreadsheet formula injection detected in CSV row ${r + 1}: '${cell}'. Upload blocked by CSV Firewall.`,
          };
        }
      }

      const rowObj = {};
      headers.forEach((h, idx) => {
        rowObj[h] = cells[idx] || "";
      });

      const amount = Number(rowObj.amount || rowObj.gross || cells[1] || 0);
      const fee = Number(rowObj.fee || rowObj.fees || cells[2] || 0);

      sanitizedRows.push({
        date: rowObj.date || cells[0] || new Date().toISOString().split("T")[0],
        invoiceId: rowObj.invoiceid || rowObj.id || `CSV-TX-${r}`,
        description: rowObj.description || rowObj.item || cells[3] || "Export Goods",
        amount: isNaN(amount) ? 0 : amount,
        fee: isNaN(fee) ? Number((amount * 0.0349 + 0.49).toFixed(2)) : fee,
        currency: (rowObj.currency || cells[4] || "USD").toUpperCase(),
        buyer: rowObj.buyer || rowObj.buyer_token || cells[5] || "BUYER_UNKNOWN",
      });
    }
  } else if (Array.isArray(csvInput)) {
    for (let r = 0; r < csvInput.length; r++) {
      const item = csvInput[r];
      if (Array.isArray(item)) {
        for (const cell of item) {
          if (isFormulaInjection(cell)) {
            return {
              safe: false,
              blockedCell: String(cell),
              row: r + 1,
              reason: `Spreadsheet formula injection detected in array row ${r + 1}: '${cell}'. Upload blocked by CSV Firewall.`,
            };
          }
        }
        const amt = Number(item[1] || 0);
        sanitizedRows.push({
          date: item[0] || new Date().toISOString().split("T")[0],
          invoiceId: `CSV-TX-${r + 1}`,
          description: String(item[3] || item[2] || "Export Goods"),
          amount: isNaN(amt) ? 0 : amt,
          fee: Number(item[2] || (amt * 0.0349 + 0.49).toFixed(2)),
          currency: String(item[4] || "USD").toUpperCase(),
          buyer: String(item[5] || "BUYER_UNKNOWN"),
        });
      } else if (item && typeof item === "object") {
        for (const [key, val] of Object.entries(item)) {
          if (isFormulaInjection(val)) {
            return {
              safe: false,
              blockedCell: String(val),
              field: key,
              row: r + 1,
              reason: `Spreadsheet formula injection detected in field '${key}' (row ${r + 1}): '${val}'. Upload blocked by CSV Firewall.`,
            };
          }
        }
        const amt = Number(item.amount || item.gross || 0);
        sanitizedRows.push({
          date: item.date || new Date().toISOString().split("T")[0],
          invoiceId: item.invoiceId || item.id || `CSV-TX-${r + 1}`,
          description: item.description || item.item || "Export Goods",
          amount: isNaN(amt) ? 0 : amt,
          fee: Number(item.fee || (amt * 0.0349 + 0.49).toFixed(2)),
          currency: (item.currency || "USD").toUpperCase(),
          buyer: item.buyer || item.buyer_token || "BUYER_UNKNOWN",
        });
      }
    }
  }

  return {
    safe: true,
    sanitizedRows,
    totalRows: sanitizedRows.length,
  };
}

// Bounded sliding nonce / audio hash cache for recorded audio replay defense
// Note: Single-process in-memory cache is bounded to 5,000 entries. In multi-instance
// production deployment, a distributed atomic store (e.g., Redis / Spanner) is required.
const seenAudioHashes = new Map(); // hash -> timestampMs
const MAX_AUDIO_AGE_MS = 60 * 1000; // 60 seconds
const CLOCK_SKEW_TOLERANCE_MS = 5 * 1000; // 5 seconds
const MAX_CACHE_SIZE = 5000;

function cleanExpiredAudioHashes() {
  const now = Date.now();
  for (const [h, ts] of seenAudioHashes.entries()) {
    if (now - ts > MAX_AUDIO_AGE_MS) {
      seenAudioHashes.delete(h);
    }
  }
}

export function clearAudioReplayCacheForTesting() {
  seenAudioHashes.clear();
}

/**
 * Recorded Audio Replay Defense
 * Verifies that a voice capture is fresh, has not been replayed, and falls within
 * the acceptable clock-skew window. Prefers raw audio byte SHA-256 hashes.
 *
 * @param {string | Buffer} audioBufferHashOrTranscript - Audio bytes buffer, SHA-256 hex, or raw transcript
 * @param {number | string} timestampMs - Timestamp of audio capture
 * @returns {{ safe: boolean, reason?: string, audioHash?: string }}
 */
export function verifyAudioReplayGuard(audioBufferHashOrTranscript, timestampMs = Date.now()) {
  cleanExpiredAudioHashes();

  if (!audioBufferHashOrTranscript) {
    return { safe: false, reason: "Missing audio capture input for replay verification" };
  }

  let audioHash = "";
  if (Buffer.isBuffer(audioBufferHashOrTranscript)) {
    audioHash = crypto.createHash("sha256").update(audioBufferHashOrTranscript).digest("hex");
  } else if (typeof audioBufferHashOrTranscript === "string") {
    if (/^[a-f0-9]{64}$/i.test(audioBufferHashOrTranscript.trim())) {
      audioHash = audioBufferHashOrTranscript.trim().toLowerCase();
    } else {
      audioHash = crypto.createHash("sha256").update(audioBufferHashOrTranscript.trim()).digest("hex");
    }
  } else {
    return { safe: false, reason: "Invalid audio buffer or transcript type" };
  }

  const now = Date.now();
  const captureTime = Number(timestampMs);

  if (isNaN(captureTime)) {
    return { safe: false, reason: "Invalid audio capture timestamp format" };
  }

  // Reject future timestamps outside clock-skew tolerance
  if (captureTime > now + CLOCK_SKEW_TOLERANCE_MS) {
    appendAuditEntry({
      transcript: "[AUDIO REPLAY DEFENSE] Clock skew anomaly detected",
      stagedPayload: { audioHash, captureTime, now },
      passkeyAssertionId: "REPLAY_GUARD_CLOCK_SKEW",
      status: "BLOCKED_AUDIO_REPLAY",
      metadata: { violation: "FUTURE_TIMESTAMP", clockSkewMs: captureTime - now },
    });
    return {
      safe: false,
      reason: `Audio capture timestamp is in the future (+${captureTime - now}ms). Clock skew exceeds tolerance (${CLOCK_SKEW_TOLERANCE_MS}ms).`,
    };
  }

  // Reject stale voice captures older than 60 seconds
  if (now - captureTime > MAX_AUDIO_AGE_MS) {
    appendAuditEntry({
      transcript: "[AUDIO REPLAY DEFENSE] Stale audio capture detected",
      stagedPayload: { audioHash, ageMs: now - captureTime },
      passkeyAssertionId: "REPLAY_GUARD_STALE",
      status: "BLOCKED_AUDIO_REPLAY",
      metadata: { violation: "STALE_AUDIO_CAPTURE", ageMs: now - captureTime },
    });
    return {
      safe: false,
      reason: `Voice capture expired: Audio was captured ${Math.round((now - captureTime) / 1000)}s ago (max allowed freshness: ${MAX_AUDIO_AGE_MS / 1000}s).`,
    };
  }

  // Check if hash already seen (recorded replay)
  if (seenAudioHashes.has(audioHash)) {
    appendAuditEntry({
      transcript: "[AUDIO REPLAY DEFENSE] Repeated audio capture replay detected",
      stagedPayload: { audioHash },
      passkeyAssertionId: "REPLAY_GUARD_DUPLICATE",
      status: "BLOCKED_AUDIO_REPLAY",
      metadata: { violation: "REPEATED_AUDIO_RECORDING", firstSeenAt: new Date(seenAudioHashes.get(audioHash)).toISOString() },
    });
    return {
      safe: false,
      reason: `Recorded audio replay attack detected: This exact voice capture (hash: ${audioHash.slice(0, 16)}...) was already consumed.`,
    };
  }

  if (seenAudioHashes.size >= MAX_CACHE_SIZE) {
    const oldestKey = seenAudioHashes.keys().next().value;
    seenAudioHashes.delete(oldestKey);
  }

  seenAudioHashes.set(audioHash, now);

  return {
    safe: true,
    audioHash,
    verifiedAt: new Date(now).toISOString(),
  };
}
