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

  const allowedActions = ["create_invoice", "list_transactions", "get_insights", "export_statement"];
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
