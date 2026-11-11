import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const dataDir = path.resolve(__dirname, "../data");
const vaultFilePath = path.join(dataDir, "vault.enc.json");

const VAULT_SECRET = process.env.VAULT_SECRET || "payvoice-hackathon-secret-2026";
const VAULT_SALT = "payvoice-salt";
const key = crypto.scryptSync(VAULT_SECRET, VAULT_SALT, 32);

const DEFAULT_BUYERS = {
  BUYER_RAHUL_01: {
    buyerToken: "BUYER_RAHUL_01",
    name: "Rahul Mehta",
    email: "rahul.mehta@exportimport-global.com",
    country: "US",
    currency: "USD",
    maxLimit: 2500.0,
    createdAt: new Date().toISOString(),
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
      return { ...DEFAULT_BUYERS, ...loaded };
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
      redacted = redacted.replace(new RegExp(emailEscaped, "gi"), buyer.buyerToken);
    }
    if (buyer.name) {
      const nameParts = buyer.name.trim().split(/\s+/);
      // Replace full name first
      const fullNameEscaped = buyer.name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      redacted = redacted.replace(new RegExp(`\\b${fullNameEscaped}\\b`, "gi"), buyer.buyerToken);

      // Replace first name if specific (e.g. Rahul)
      if (nameParts[0] && nameParts[0].length >= 3) {
        const firstNameEscaped = nameParts[0].replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        redacted = redacted.replace(new RegExp(`\\b${firstNameEscaped}\\b`, "gi"), buyer.buyerToken);
      }
    }
  }

  // 2. Redact any remaining arbitrary raw emails to prevent unauthorized address injection
  redacted = redacted.replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, "[REDACTED_EMAIL]");

  return redacted;
}

/**
 * Resolve an opaque buyer token to full buyer details from the encrypted vault
 */
export function resolveBuyerToken(token) {
  if (!token) return null;
  const normalized = String(token).trim().toUpperCase();
  return buyers[normalized] || null;
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
      maskedEmail,
      country: b.country,
      currency: b.currency,
      maxLimit: b.maxLimit,
    };
  });
}

/**
 * Register a new buyer into the encrypted vault
 */
export function registerBuyer(buyerData) {
  if (!buyerData || !buyerData.name || !buyerData.email) {
    throw new Error("Invalid buyer registration data: name and email are required");
  }

  const tokenPrefix = buyerData.name.replace(/[^a-zA-Z0-9]/g, "").toUpperCase().slice(0, 5) || "BUYER";
  const existingTokens = Object.keys(buyers);
  const sequenceNum = String(existingTokens.length + 1).padStart(2, "0");
  const buyerToken = buyerData.buyerToken || `BUYER_${tokenPrefix}_${sequenceNum}`;

  buyers[buyerToken] = {
    buyerToken,
    name: buyerData.name.trim(),
    email: buyerData.email.trim().toLowerCase(),
    country: buyerData.country || "US",
    currency: buyerData.currency || "USD",
    maxLimit: Number(buyerData.maxLimit) || 2500.0,
    createdAt: new Date().toISOString(),
  };

  saveVault();
  return buyers[buyerToken];
}
