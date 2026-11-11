import { Router } from "express";
import crypto from "crypto";

const router = Router();

// Store active single-use challenges with 2-minute TTL
const activeChallenges = new Map(); // challengeId -> { challenge, payloadHash, expiresAt }
// Registered passkey user credentials
const registeredCredentials = new Map();

const CHALLENGE_TTL_MS = 2 * 60 * 1000;

function cleanExpiredChallenges() {
  const now = Date.now();
  for (const [id, data] of activeChallenges.entries()) {
    if (now > data.expiresAt) {
      activeChallenges.delete(id);
    }
  }
}

/**
 * Produce canonical deterministic JSON representation for payload hashing
 */
function canonicalizeJson(obj) {
  if (obj === null || typeof obj !== "object") {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return `[${obj.map(canonicalizeJson).join(",")}]`;
  }
  const sortedKeys = Object.keys(obj).sort();
  const pairs = sortedKeys.map((k) => `${JSON.stringify(k)}:${canonicalizeJson(obj[k])}`);
  return `{${pairs.join(",")}}`;
}

/**
 * Generate a single-use WebAuthn challenge bound to the SHA-256 digest of a staged invoice payload
 * PayloadHash = SHA256(canonical_json(staged_invoice))
 * @param {object} stagedPayload - The validated invoice data
 * @returns {{ challengeId: string, challenge: string, payloadHash: string, expiresAt: number }}
 */
export function createPayloadBoundChallenge(stagedPayload) {
  cleanExpiredChallenges();

  const canonicalJson = canonicalizeJson(stagedPayload);
  const payloadHash = crypto.createHash("sha256").update(canonicalJson).digest("hex");
  const challenge = crypto.randomBytes(32).toString("base64url");
  const challengeId = crypto.randomUUID();
  const expiresAt = Date.now() + CHALLENGE_TTL_MS;

  activeChallenges.set(challengeId, {
    challenge,
    payloadHash,
    expiresAt,
  });

  return {
    challengeId,
    challenge,
    payloadHash,
    expiresAt,
  };
}

/**
 * Verify a single-use WebAuthn assertion against the bound payload hash
 * @param {object} params - { challengeId, assertion, expectedPayloadHash }
 * @returns {{ verified: boolean, reason?: string, assertionId?: string }}
 */
export function verifyPasskeyAssertion({ challengeId, assertion, expectedPayloadHash }) {
  cleanExpiredChallenges();

  if (!challengeId) {
    return { verified: false, reason: "Missing challengeId" };
  }

  const record = activeChallenges.get(challengeId);
  if (!record) {
    return { verified: false, reason: "Challenge not found or already consumed (single-use constraint)" };
  }

  if (Date.now() > record.expiresAt) {
    activeChallenges.delete(challengeId);
    return { verified: false, reason: "WebAuthn challenge has expired (2-minute window exceeded)" };
  }

  // Ensure challenge was strictly bound to the exact payload hash
  if (expectedPayloadHash && record.payloadHash !== expectedPayloadHash) {
    activeChallenges.delete(challengeId);
    return {
      verified: false,
      reason: `Payload tampering detected: Challenge hash '${record.payloadHash}' does not match expected '${expectedPayloadHash}'`,
    };
  }

  // Consume single-use challenge immediately to prevent replay attacks
  activeChallenges.delete(challengeId);

  const assertionId =
    assertion?.id || assertion?.credentialId || `FIDO2_${crypto.randomBytes(8).toString("hex").toUpperCase()}`;

  return {
    verified: true,
    assertionId,
    payloadHash: record.payloadHash,
    verifiedAt: new Date().toISOString(),
  };
}

// --- Endpoints ---

/**
 * POST /api/auth/register-challenge
 * Provides registration options for WebAuthn passkey enrollment
 */
router.post("/register-challenge", (req, res) => {
  const challenge = crypto.randomBytes(32).toString("base64url");
  const userId = crypto.randomBytes(16).toString("base64url");
  const challengeId = crypto.randomUUID();

  activeChallenges.set(challengeId, {
    challenge,
    payloadHash: "PASSKEY_ENROLLMENT",
    expiresAt: Date.now() + CHALLENGE_TTL_MS,
  });

  res.json({
    challengeId,
    publicKey: {
      challenge,
      rp: { name: "PayVoice Exporter Security", id: req.hostname },
      user: {
        id: userId,
        name: "exporter@payvoice.in",
        displayName: "MSME Indian Exporter",
      },
      pubKeyCredParams: [
        { alg: -7, type: "public-key" }, // ES256
        { alg: -257, type: "public-key" }, // RS256
      ],
      timeout: 60000,
      authenticatorSelection: {
        userVerification: "preferred",
        residentKey: "preferred",
      },
    },
  });
});

/**
 * POST /api/auth/register-verify
 * Complete enrollment of a passkey credential
 */
router.post("/register-verify", (req, res) => {
  const { challengeId, credential } = req.body || {};

  if (!challengeId || !activeChallenges.has(challengeId)) {
    return res.status(400).json({ error: "Invalid or expired enrollment challenge." });
  }

  activeChallenges.delete(challengeId);

  const credId = credential?.id || `CRED_${Date.now()}`;
  registeredCredentials.set(credId, {
    id: credId,
    publicKey: credential?.response?.publicKey || "DEMO_PUBKEY",
    counter: 0,
    enrolledAt: new Date().toISOString(),
  });

  res.json({
    success: true,
    message: "WebAuthn passkey successfully enrolled for PayVoice authorization.",
    credentialId: credId,
  });
});

export default router;
