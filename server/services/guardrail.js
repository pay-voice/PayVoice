/**
 * PayVoice Prompt-Injection & Schema Firewall
 * Treats all voice transcripts, item descriptions, and external invoice memos as untrusted inputs.
 */

const ADVERSARIAL_PATTERNS = [
  { regex: /ignore\s+(all\s+)?(previous\s+)?(rules|instructions|prompts|commands)/i, label: "prompt_injection_override" },
  { regex: /you\s+are\s+now\s+(a\s+)?(system\s+admin|root|super\s*user|developer\s+mode)/i, label: "role_manipulation" },
  { regex: /disregard\s+(all\s+)?(safeguards|constraints|limits|guidelines)/i, label: "safety_bypass" },
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
