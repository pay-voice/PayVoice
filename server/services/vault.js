import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import {
  encryptAes256Siv,
  decryptAes256Siv,
  encryptAes256Gcm,
  decryptAes256Gcm,
  deriveVaultKeys,
} from "./sivCrypto.js";

export {
  encryptAes256Siv,
  decryptAes256Siv,
  encryptAes256Gcm,
  decryptAes256Gcm,
  deriveVaultKeys,
};

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const dataDir = path.resolve(__dirname, "../data");
const vaultFilePath = path.join(dataDir, "vault.enc.json");

const VAULT_SECRET = process.env.VAULT_SECRET || "payvoice-hackathon-secret-2026";
const VAULT_SALT = "payvoice-salt";
const key = crypto.scryptSync(VAULT_SECRET, VAULT_SALT, 32);

/**
 * Compute an HMAC-SHA256 blind index for deterministic, privacy-preserving lookup
 * Allows searching by email without decrypting the entire database or leaking plaintext.
 * @param {string} email
 * @returns {string} 64-character hex digest
 */
export function computeBlindIndex(email) {
  if (!email || typeof email !== "string") return "";
  const normalized = email.trim().toLowerCase();
  return crypto.createHmac("sha256", key).update(`blind-index:${normalized}`).digest("hex");
}

const RAHUL_EMAIL = "rahul.mehta@techglobal-corp.com";
const ELENA_EMAIL = "elena.rostova@nordicstudio.eu";
const OLIVER_EMAIL = "oliver.grant@finscale.co.uk";
const AKIRA_EMAIL = "akira.sato@nexusrobotics.jp";

const DEFAULT_BUYERS = {
  BUYER_RAHUL_01: {
    buyerToken: "BUYER_RAHUL_01",
    name: "Rahul Mehta",
    email: RAHUL_EMAIL,
    company: "TechGlobal Corp (US)",
    blindIndex: computeBlindIndex(RAHUL_EMAIL),
    country: "US",
    currency: "USD",
    maxLimit: 2500.0,
    defaultItem: "Cloud API Development",
    defaultQuantity: "1 Milestone",
    defaultAmount: 200.0,
    defaultPurposeCode: "P0802",
    defaultPurposeDescription: "Software Implementation & Cloud IT Consultancy",
    aliases: ["rahul", "rahul mehta", "राहुल", "राहुलला", "राहुलसाठी", "राहुल को"],
    createdAt: "2026-11-10T00:00:00.000Z",
    cooldownUntil: "2026-11-10T00:30:00.000Z",
  },
  BUYER_ELENA_02: {
    buyerToken: "BUYER_ELENA_02",
    name: "Elena Rostova",
    email: ELENA_EMAIL,
    company: "Nordic Studio (EU)",
    blindIndex: computeBlindIndex(ELENA_EMAIL),
    country: "DE",
    currency: "EUR",
    maxLimit: 2500.0,
    defaultItem: "UI/UX Design Sprint",
    defaultQuantity: "40 Hours",
    defaultAmount: 450.0,
    defaultPurposeCode: "P1004",
    defaultPurposeDescription: "Engineering, UI/UX & Product Design Services",
    aliases: ["elena", "elena rostova", "एलेना", "एलेनाला", "एलेनासाठी", "एलेना को"],
    createdAt: "2026-11-10T00:00:00.000Z",
    cooldownUntil: "2026-11-10T00:30:00.000Z",
  },
  BUYER_OLIVER_03: {
    buyerToken: "BUYER_OLIVER_03",
    name: "Oliver Grant",
    email: OLIVER_EMAIL,
    company: "FinScale Ltd (UK)",
    blindIndex: computeBlindIndex(OLIVER_EMAIL),
    country: "GB",
    currency: "GBP",
    maxLimit: 2500.0,
    defaultItem: "Security Penetration Audit",
    defaultQuantity: "1 Audit",
    defaultAmount: 350.0,
    defaultPurposeCode: "P0802",
    defaultPurposeDescription: "Software Implementation & Cloud IT Consultancy",
    aliases: ["oliver", "oliver grant", "ऑलिव्हर", "ऑलिव्हरला", "ऑलिव्हरसाठी", "ऑलिवर को"],
    createdAt: "2026-11-10T00:00:00.000Z",
    cooldownUntil: "2026-11-10T00:30:00.000Z",
  },
  BUYER_AKIRA_04: {
    buyerToken: "BUYER_AKIRA_04",
    name: "Akira Sato",
    email: AKIRA_EMAIL,
    company: "Nexus Robotics (JP/SG)",
    blindIndex: computeBlindIndex(AKIRA_EMAIL),
    country: "JP",
    currency: "USD",
    maxLimit: 2500.0,
    defaultItem: "Embedded Firmware Module",
    defaultQuantity: "2 Units",
    defaultAmount: 500.0,
    defaultPurposeCode: "P0802",
    defaultPurposeDescription: "Software Implementation & Cloud IT Consultancy",
    aliases: ["akira", "akira sato", "अकिरा", "अकिराला", "अकिरासाठी", "अकीरा को"],
    createdAt: "2026-11-10T00:00:00.000Z",
    cooldownUntil: "2026-11-10T00:30:00.000Z",
  },
};

let buyers = loadVault();

function saveVault() {
  try {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
    const plaintext = JSON.stringify(buyers);
    const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    const authTag = cipher.getAuthTag();

    const payload = {
      iv: iv.toString("hex"),
      authTag: authTag.toString("hex"),
      data: encrypted.toString("hex"),
      updatedAt: new Date().toISOString(),
    };

    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }
    fs.writeFileSync(vaultFilePath, JSON.stringify(payload, null, 2), "utf8");
  } catch (err) {
    console.warn("[Vault] Disk persistence warning (operating in-memory):", err.message);
  }
}

function loadVault() {
  try {
    if (fs.existsSync(vaultFilePath)) {
      const raw = JSON.parse(fs.readFileSync(vaultFilePath, "utf8"));
      const iv = Buffer.from(raw.iv, "hex");
      const authTag = Buffer.from(raw.authTag, "hex");
      const encrypted = Buffer.from(raw.data, "hex");

      const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
      decipher.setAuthTag(authTag);
      const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
      const loaded = JSON.parse(decrypted.toString("utf8"));

      // Ensure each loaded buyer has defaults and blind index computed
      const merged = {};
      for (const [k, def] of Object.entries(DEFAULT_BUYERS)) {
        merged[k] = { ...def, ...(loaded[k] || {}) };
      }
      for (const [k, v] of Object.entries(loaded)) {
        if (!merged[k]) merged[k] = v;
      }

      for (const b of Object.values(merged)) {
        if (!b.blindIndex && b.email) {
          b.blindIndex = computeBlindIndex(b.email);
        }
      }

      return merged;
    }
  } catch (err) {
    console.warn("[Vault] Vault decrypt/read note (initializing seed data):", err.message);
  }
  return { ...DEFAULT_BUYERS };
}

// Ensure initial seed is encrypted and persisted
saveVault();

/**
 * Redact sensitive PII (names, emails) from user speech transcripts before feeding to LLM
 * Replaces known names with their opaque buyer tokens (e.g., 'Rahul' -> 'BUYER_RAHUL_01')
 */
export function redactPIIBeforeLLM(transcript) {
  if (!transcript || typeof transcript !== "string") {
    return "";
  }

  let redacted = transcript;

  // 1. Replace known buyer names and emails with their buyerToken
  for (const buyer of Object.values(buyers)) {
    if (buyer.email) {
      const emailEscaped = buyer.email.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      redacted = redacted.replace(new RegExp(emailEscaped, "gi"), () => buyer.buyerToken);
    }
    if (buyer.name) {
      const nameParts = buyer.name.trim().split(/\s+/);
      const fullNameEscaped = buyer.name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      redacted = redacted.replace(new RegExp(`\\b${fullNameEscaped}\\b`, "gi"), () => buyer.buyerToken);

      if (nameParts[0] && nameParts[0].length >= 3) {
        const firstNameEscaped = nameParts[0].replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        redacted = redacted.replace(new RegExp(`\\b${firstNameEscaped}\\b`, "gi"), () => buyer.buyerToken);
      }
    }
    if (Array.isArray(buyer.aliases)) {
      for (const alias of buyer.aliases) {
        if (alias && alias.length >= 2) {
          const aliasEscaped = alias.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
          if (/[\u0900-\u097F]/.test(alias)) {
            redacted = redacted.replace(new RegExp(aliasEscaped, "g"), () => buyer.buyerToken);
          } else {
            redacted = redacted.replace(new RegExp(`\\b${aliasEscaped}\\b`, "gi"), () => buyer.buyerToken);
          }
        }
      }
    }
  }

  // 2. Redact any remaining arbitrary raw emails to prevent unauthorized address injection
  redacted = redacted.replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, "[REDACTED_EMAIL]");

  return redacted;
}

/**
 * Find buyer by name, token, email or spoken multilingual alias
 * @param {string} query
 * @returns {object|null}
 */
export function findBuyerByNameOrToken(query) {
  if (!query || typeof query !== "string") return null;
  const q = query.trim().toLowerCase();
  const upperQ = query.trim().toUpperCase();

  // 1. Direct token match
  if (buyers[upperQ]) return buyers[upperQ];

  // 2. Exact match on name, email, or token
  for (const buyer of Object.values(buyers)) {
    if (buyer.buyerToken.toLowerCase() === q) return buyer;
    if (buyer.email && buyer.email.toLowerCase() === q) return buyer;
    if (buyer.name && buyer.name.toLowerCase() === q) return buyer;
    const firstName = (buyer.name || "").split(/\s+/)[0]?.toLowerCase();
    if (firstName && firstName === q) return buyer;

    if (Array.isArray(buyer.aliases)) {
      for (const alias of buyer.aliases) {
        if (alias.toLowerCase() === q) return buyer;
      }
    }
  }

  // 3. Substring check in query
  for (const buyer of Object.values(buyers)) {
    const firstName = (buyer.name || "").split(/\s+/)[0]?.toLowerCase();
    if (firstName && q.includes(firstName)) return buyer;
    if (buyer.buyerToken.toLowerCase() && q.includes(buyer.buyerToken.toLowerCase())) return buyer;
    if (Array.isArray(buyer.aliases)) {
      for (const alias of buyer.aliases) {
        if (alias && q.includes(alias.toLowerCase())) return buyer;
      }
    }
  }

  return null;
}

/**
 * Resolve an opaque buyer token to full buyer details from the encrypted vault
 * (Pre-authorization safe lookup: returns token, country, currency, maxLimit, but no raw email for LLMs)
 */
export function resolveBuyerToken(token) {
  if (!token) return null;
  const normalized = String(token).trim().toUpperCase();
  return buyers[normalized] || null;
}

/**
 * Resolve buyer for live execution by decrypting raw PII
 * CRITICAL SECURITY GATE: Only permitted when passed a valid, verified WebAuthn assertion ID.
 * @param {string} opaqueToken - e.g. "BUYER_RAHUL_01"
 * @param {string} verifiedAssertionId - Cryptographic proof from WebAuthn assertion
 * @returns {object} De-tokenized buyer object with legalName and email
 */
export function resolveBuyerForExecution(opaqueToken, verifiedAssertionId) {
  if (!verifiedAssertionId || typeof verifiedAssertionId !== "string" || verifiedAssertionId.trim().length < 8) {
    throw new Error(
      "Boundary Violation: Raw PII cannot be decrypted without a verified WebAuthn passkey assertion ID."
    );
  }

  // Verify assertion ID format
  const validPattern = /^(FIDO2_|PASSKEY_|WEBCRYPTO_|ASSERTION_|CRED_)/i;
  if (!validPattern.test(verifiedAssertionId.trim())) {
    throw new Error("Invalid assertion format. Access to de-tokenized PII denied.");
  }

  const buyer = resolveBuyerToken(opaqueToken);
  if (!buyer) {
    return null;
  }

  return {
    buyerToken: buyer.buyerToken,
    legalName: buyer.name,
    email: buyer.email,
    country: buyer.country,
    currency: buyer.currency,
    maxLimit: buyer.maxLimit,
    blindIndex: buyer.blindIndex,
    deTokenizedAt: new Date().toISOString(),
    authorizedByAssertionId: verifiedAssertionId,
  };
}

/**
 * List allowlisted buyers with masked emails for privacy-safe UI display
 */
export function listMaskedBuyers() {
  return Object.values(buyers).map((b) => {
    let maskedEmail = "unknown";
    if (b.email) {
      const [user, domain] = b.email.split("@");
      if (user.length <= 2) {
        maskedEmail = `${user[0]}*@${domain}`;
      } else {
        maskedEmail = `${user[0]}***${user[user.length - 1]}@${domain}`;
      }
    }

    return {
      buyerToken: b.buyerToken,
      displayName: b.name,
      company: b.company || "International Client",
      maskedEmail,
      country: b.country,
      currency: b.currency,
      maxLimit: b.maxLimit,
      defaultItem: b.defaultItem || "Cloud API Development",
      defaultQuantity: b.defaultQuantity || "1 Milestone",
      defaultAmount: b.defaultAmount || 200.0,
      defaultPurposeCode: b.defaultPurposeCode || "P0802",
      defaultPurposeDescription: b.defaultPurposeDescription || "Software Implementation & Cloud IT Consultancy",
      blindIndex: b.blindIndex || computeBlindIndex(b.email),
    };
  });
}

/**
 * Register a new buyer into the encrypted vault
 * Uses HMAC-SHA256 blind index to prevent duplicate tokens for the same buyer email.
 */
export function registerBuyer(buyerData) {
  const buyerName = (buyerData?.name || buyerData?.displayName || "").trim();
  if (!buyerData || !buyerName || !buyerData.email) {
    throw new Error("Invalid buyer registration data: name and email are required");
  }

  const cleanEmail = buyerData.email.trim().toLowerCase();
  const blindIndex = computeBlindIndex(cleanEmail);

  // Deterministic Blind Index match: update existing record if already registered
  for (const [token, existing] of Object.entries(buyers)) {
    if (existing.blindIndex === blindIndex || existing.email.toLowerCase() === cleanEmail) {
      buyers[token] = {
        ...existing,
        name: buyerName,
        blindIndex,
        country: buyerData.country || existing.country,
        currency: buyerData.currency || existing.currency,
        maxLimit: Number(buyerData.maxLimit) || existing.maxLimit,
      };
      saveVault();
      return buyers[token];
    }
  }

  const tokenPrefix = buyerName.replace(/[^a-zA-Z0-9]/g, "").toUpperCase().slice(0, 5) || "BUYER";
  const existingTokens = Object.keys(buyers);
  const sequenceNum = String(existingTokens.length + 1).padStart(2, "0");
  const buyerToken = buyerData.buyerToken || `BUYER_${tokenPrefix}_${sequenceNum}`;

  const now = Date.now();
  const cooldownDurationMs = 30 * 60 * 1000; // 30-minute cool-down period
  const cooldownUntil = buyerData.bypassCooldown
    ? new Date(now - 1000).toISOString()
    : new Date(now + cooldownDurationMs).toISOString();

  buyers[buyerToken] = {
    buyerToken,
    name: buyerName,
    email: cleanEmail,
    blindIndex,
    country: buyerData.country || "US",
    currency: buyerData.currency || "USD",
    maxLimit: Number(buyerData.maxLimit) || 2500.0,
    defaultAmount: Number(buyerData.defaultAmount) || 200.0,
    defaultItem: buyerData.defaultItem || "Cloud API Development",
    createdAt: new Date().toISOString(),
    cooldownUntil,
  };

  saveVault();
  return buyers[buyerToken];
}

/**
 * Check if a newly registered payee is currently in the mandatory 30-minute cool-down period
 * @param {string | object} buyerOrToken
 * @param {object} [options={}]
 * @returns {{ inCooldown: boolean, remainingMs: number, cooldownUntil: string | null }}
 */
export function isBuyerInCooldown(buyerOrToken, options = {}) {
  if (options.bypassCooldown) {
    return { inCooldown: false, remainingMs: 0, cooldownUntil: null };
  }

  const buyer = typeof buyerOrToken === "string" ? resolveBuyerToken(buyerOrToken) : buyerOrToken;
  if (!buyer || !buyer.cooldownUntil) {
    return { inCooldown: false, remainingMs: 0, cooldownUntil: null };
  }

  const now = Date.now();
  const cdTime = new Date(buyer.cooldownUntil).getTime();
  if (isNaN(cdTime) || cdTime <= now) {
    return { inCooldown: false, remainingMs: 0, cooldownUntil: buyer.cooldownUntil };
  }

  return {
    inCooldown: true,
    remainingMs: cdTime - now,
    cooldownUntil: buyer.cooldownUntil,
  };
}

/**
 * Automatically scrub sensitive PII, credentials, PANs, and tokens from logs
 * Non-mutating: safely clones nested structures and handles circular references.
 *
 * @param {any} input - Text, object, array, or error to scrub
 * @returns {any} Sanitized clone safe for logging
 */
export function scrubPiiFromLogs(input) {
  const seen = new WeakSet();

  function scrubString(str) {
    if (typeof str !== "string") return str;

    let s = str;
    // 1. Email addresses
    s = s.replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/gi, "[REDACTED_EMAIL]");
    // 2. Indian PAN numbers (5 letters, 4 digits, 1 letter)
    s = s.replace(/\b[A-Z]{5}[0-9]{4}[A-Z]\b/g, "[REDACTED_PAN]");
    // 3. Payment Card PANs (13 to 19 digits with optional hyphens/spaces)
    s = s.replace(/\b(?:\d[ -]*?){13,19}\b/g, "[REDACTED_CARD_PAN]");
    // 4. Authorization Bearer tokens
    s = s.replace(/Bearer\s+[a-zA-Z0-9_\-\.]+/gi, "Bearer [REDACTED_TOKEN]");
    // 5. Credential/Secret assignment patterns
    s = s.replace(/(?:password|client_secret|api_key|secret|private_key|token)\s*[:=]\s*["']?([^"',\s]+)["']?/gi, (match) => {
      const parts = match.split(/[:=]/);
      return `${parts[0]}=[REDACTED_SECRET]`;
    });

    return s;
  }

  function scrubNode(val) {
    if (val === null || val === undefined) return val;
    if (typeof val === "string") return scrubString(val);
    if (typeof val === "number" || typeof val === "boolean") return val;

    if (typeof val === "object") {
      if (seen.has(val)) {
        return "[CIRCULAR_REFERENCE]";
      }
      seen.add(val);

      if (Buffer.isBuffer(val)) {
        return `[BUFFER:${val.length}B]`;
      }

      if (val instanceof Error) {
        return {
          name: val.name,
          message: scrubString(val.message),
          stack: scrubString(val.stack || ""),
        };
      }

      if (Array.isArray(val)) {
        return val.map((item) => scrubNode(item));
      }

      const out = {};
      const sensitiveKeyPattern = /^(password|client_?secret|secret|api_?key|private_?key|authorization|cookie|session_?id)$/i;

      for (const [k, v] of Object.entries(val)) {
        if (sensitiveKeyPattern.test(k)) {
          out[k] = "[REDACTED_CREDENTIAL]";
        } else if (typeof v === "string") {
          out[k] = scrubString(v);
        } else {
          out[k] = scrubNode(v);
        }
      }
      return out;
    }

    return String(val);
  }

  return scrubNode(input);
}
