/**
 * PayVoice Standards-Compliant AES-256-SIV (RFC 5297) & AES-256-GCM Cryptographic Engine
 * PayPal AI Hackathon 2026 - Track: Security, Guardrails & Cryptography (Shoury)
 *
 * Implements:
 *   1. RFC 5297 AES-256-SIV (Synthetic Initialization Vector Authenticated Encryption)
 *      - S2V deterministic vector authenticator using AES-256-CMAC (RFC 4493)
 *      - Two independent 256-bit subkeys (K1 for S2V/CMAC, K2 for CTR encryption)
 *      - Synthetic IV masking (clearing bits 31 and 63 per RFC 5297 Sec 2.6)
 *      - Full authenticated associated data (AAD) support
 *      - Constant-time verification before returning plaintext (fails closed on tamper)
 *   2. AES-256-GCM with unique 96-bit nonces, 128-bit authentication tags, and strict AAD validation
 */

import crypto from "crypto";

const SIV_VERSION = "aes-256-siv-rfc5297-v1";
const GCM_VERSION = "aes-256-gcm-v1";

const DEFAULT_SECRET = process.env.VAULT_SECRET || "payvoice-hackathon-secret-2026";
const DEFAULT_SALT = "payvoice-siv-salt-v4";

/**
 * Derives a 512-bit master key (K1 || K2) for AES-256-SIV and a 256-bit key for AES-256-GCM
 */
export function deriveVaultKeys(secret = DEFAULT_SECRET, salt = DEFAULT_SALT) {
  const sivKey512 = crypto.scryptSync(secret, `${salt}:siv`, 64);
  const gcmKey256 = crypto.scryptSync(secret, `${salt}:gcm`, 32);
  return {
    sivKey: sivKey512,
    k1: sivKey512.subarray(0, 32), // 256-bit S2V CMAC key
    k2: sivKey512.subarray(32, 64), // 256-bit CTR encryption key
    gcmKey: gcmKey256,
  };
}

const defaultKeys = deriveVaultKeys();

/* =========================================================================
 * RFC 4493: AES-256-CMAC Primitives
 * ========================================================================= */

function aesEcbEncryptBlock(key, block16) {
  const cipher = crypto.createCipheriv("aes-256-ecb", key, null);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(block16), cipher.final()]);
}

function shiftLeftOneBit(buf16) {
  const shifted = Buffer.alloc(16);
  const msb = (buf16[0] & 0x80) >> 7;
  for (let i = 0; i < 15; i++) {
    shifted[i] = ((buf16[i] << 1) | (buf16[i + 1] >> 7)) & 0xff;
  }
  shifted[15] = (buf16[15] << 1) & 0xff;
  return { shifted, msb };
}

function dbl(buf16) {
  const { shifted, msb } = shiftLeftOneBit(buf16);
  if (msb === 1) {
    shifted[15] ^= 0x87; // R_128 constant for GF(2^128)
  }
  return shifted;
}

function xorBuffers(a, b) {
  const len = Math.min(a.length, b.length);
  const out = Buffer.alloc(len);
  for (let i = 0; i < len; i++) {
    out[i] = a[i] ^ b[i];
  }
  return out;
}

/**
 * Derives subkeys K1 and K2 for AES-CMAC
 */
function generateCmacSubkeys(key256) {
  const zeroBlock = Buffer.alloc(16, 0);
  const L = aesEcbEncryptBlock(key256, zeroBlock);
  const K1 = dbl(L);
  const K2 = dbl(K1);
  return { K1, K2 };
}

/**
 * Computes AES-256-CMAC (RFC 4493) over a message buffer
 */
export function aes256Cmac(key256, message) {
  const msgBuf = Buffer.isBuffer(message) ? message : Buffer.from(String(message), "utf8");
  const { K1, K2 } = generateCmacSubkeys(key256);

  const n = Math.ceil(msgBuf.length / 16) || 1;
  const isComplete = msgBuf.length > 0 && msgBuf.length % 16 === 0;

  let mLast = Buffer.alloc(16);
  if (isComplete) {
    const lastBlock = msgBuf.subarray((n - 1) * 16, n * 16);
    mLast = xorBuffers(lastBlock, K1);
  } else {
    const rem = msgBuf.subarray((n - 1) * 16);
    const padded = Buffer.alloc(16, 0);
    rem.copy(padded);
    padded[rem.length] = 0x80;
    mLast = xorBuffers(padded, K2);
  }

  let X = Buffer.alloc(16, 0);
  for (let i = 0; i < n - 1; i++) {
    const block = msgBuf.subarray(i * 16, (i + 1) * 16);
    X = aesEcbEncryptBlock(key256, xorBuffers(X, block));
  }
  return aesEcbEncryptBlock(key256, xorBuffers(X, mLast));
}

/* =========================================================================
 * RFC 5297: S2V Vector Authenticator
 * ========================================================================= */

/**
 * Computes S2V over a vector of inputs (RFC 5297 Section 2.4)
 */
export function s2v(key256, vectors = []) {
  if (vectors.length === 0) {
    const zeroPad = Buffer.alloc(16, 0);
    zeroPad[0] = 0x80;
    return aes256Cmac(key256, zeroPad);
  }

  let D = aes256Cmac(key256, Buffer.alloc(16, 0));
  for (let i = 0; i < vectors.length - 1; i++) {
    D = xorBuffers(dbl(D), aes256Cmac(key256, vectors[i]));
  }

  const Sn = vectors[vectors.length - 1];
  let T;
  if (Sn.length >= 16) {
    T = Buffer.from(Sn);
    for (let i = 0; i < 16; i++) {
      T[T.length - 16 + i] ^= D[i];
    }
  } else {
    const padded = Buffer.alloc(16, 0);
    Sn.copy(padded);
    padded[Sn.length] = 0x80;
    T = xorBuffers(dbl(D), padded);
  }
  return aes256Cmac(key256, T);
}

/* =========================================================================
 * RFC 5297: AES-256-SIV Encryption & Decryption
 * ========================================================================= */

/**
 * Encrypt plaintext using standards-compliant AES-256-SIV (RFC 5297)
 *
 * @param {string | Buffer} plaintext - Plaintext data to encrypt
 * @param {string | Buffer | Array<string|Buffer>} [associatedData] - Optional associated data vectors
 * @param {Buffer} [customKey512] - 512-bit master key (K1 || K2)
 * @returns {{ version: string, syntheticIv: string, ciphertext: string, associatedDataHash: string, serialized: string }}
 */
export function encryptAes256Siv(plaintext, associatedData = null, customKey512 = null) {
  const ptBuf = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(String(plaintext), "utf8");
  const key = customKey512 || defaultKeys.sivKey;
  if (!Buffer.isBuffer(key) || key.length !== 64) {
    throw new Error("AES-256-SIV requires a 512-bit (64-byte) key (256-bit K1 + 256-bit K2).");
  }

  const k1 = key.subarray(0, 32);
  const k2 = key.subarray(32, 64);

  // Normalize associated data into vector list
  const vectors = [];
  if (associatedData !== null && associatedData !== undefined) {
    if (Array.isArray(associatedData)) {
      for (const item of associatedData) {
        vectors.push(Buffer.isBuffer(item) ? item : Buffer.from(String(item), "utf8"));
      }
    } else {
      vectors.push(Buffer.isBuffer(associatedData) ? associatedData : Buffer.from(String(associatedData), "utf8"));
    }
  }
  // The final vector input to S2V is the plaintext
  vectors.push(ptBuf);

  // 1. Derive synthetic IV (V) via S2V
  const V = s2v(k1, vectors);

  // 2. Derive initial counter Q by clearing bits 31 and 63 per RFC 5297 Sec 2.6
  const Q = Buffer.from(V);
  Q[8] &= 0x7f;
  Q[12] &= 0x7f;

  // 3. Encrypt plaintext using AES-256-CTR with key K2 and counter Q
  const cipher = crypto.createCipheriv("aes-256-ctr", k2, Q);
  const ciphertext = Buffer.concat([cipher.update(ptBuf), cipher.final()]);

  const adHash = crypto.createHash("sha256").update(Buffer.concat(vectors.slice(0, -1))).digest("hex");

  const syntheticIvHex = V.toString("hex");
  const ciphertextHex = ciphertext.toString("hex");

  return {
    version: SIV_VERSION,
    syntheticIv: syntheticIvHex,
    ciphertext: ciphertextHex,
    associatedDataHash: adHash,
    serialized: `${SIV_VERSION}:${syntheticIvHex}:${ciphertextHex}:${adHash}`,
  };
}

/**
 * Decrypt ciphertext using standards-compliant AES-256-SIV (RFC 5297)
 * Strictly verifies the synthetic IV before returning decrypted plaintext.
 *
 * @param {object | string} sivPayload - Output from encryptAes256Siv or compact string
 * @param {string | Buffer | Array<string|Buffer>} [associatedData] - Associated data used during encryption
 * @param {Buffer} [customKey512] - 512-bit master key (K1 || K2)
 * @returns {Buffer} Decrypted plaintext buffer
 */
export function decryptAes256Siv(sivPayload, associatedData = null, customKey512 = null) {
  let syntheticIvHex = "";
  let ciphertextHex = "";

  if (typeof sivPayload === "string") {
    const parts = sivPayload.split(":");
    if (parts.length >= 3 && parts[0] === SIV_VERSION) {
      syntheticIvHex = parts[1];
      ciphertextHex = parts[2];
    } else {
      throw new Error("Invalid serialized AES-256-SIV string format.");
    }
  } else if (sivPayload && typeof sivPayload === "object") {
    syntheticIvHex = sivPayload.syntheticIv;
    ciphertextHex = sivPayload.ciphertext;
  } else {
    throw new Error("Missing or malformed AES-256-SIV payload.");
  }

  if (!syntheticIvHex || !ciphertextHex) {
    throw new Error("Malformed AES-256-SIV payload: missing syntheticIv or ciphertext.");
  }

  const V = Buffer.from(syntheticIvHex, "hex");
  const ciphertext = Buffer.from(ciphertextHex, "hex");

  if (V.length !== 16) {
    throw new Error("Invalid AES-256-SIV synthetic IV length (must be 16 bytes).");
  }

  const key = customKey512 || defaultKeys.sivKey;
  if (!Buffer.isBuffer(key) || key.length !== 64) {
    throw new Error("AES-256-SIV requires a 512-bit (64-byte) key.");
  }

  const k1 = key.subarray(0, 32);
  const k2 = key.subarray(32, 64);

  // Derive counter Q
  const Q = Buffer.from(V);
  Q[8] &= 0x7f;
  Q[12] &= 0x7f;

  // Decrypt candidate plaintext
  const decipher = crypto.createDecipheriv("aes-256-ctr", k2, Q);
  const candidatePlaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

  // Reconstruct vector sequence
  const vectors = [];
  if (associatedData !== null && associatedData !== undefined) {
    if (Array.isArray(associatedData)) {
      for (const item of associatedData) {
        vectors.push(Buffer.isBuffer(item) ? item : Buffer.from(String(item), "utf8"));
      }
    } else {
      vectors.push(Buffer.isBuffer(associatedData) ? associatedData : Buffer.from(String(associatedData), "utf8"));
    }
  }
  vectors.push(candidatePlaintext);

  // Authenticate synthetic IV
  const Vprime = s2v(k1, vectors);

  if (!crypto.timingSafeEqual(V, Vprime)) {
    throw new Error(
      "AES-256-SIV authentication failed: Synthetic IV mismatch. Ciphertext or associated data has been tampered with."
    );
  }

  return candidatePlaintext;
}

/* =========================================================================
 * AES-256-GCM Authenticated Encryption & Decryption
 * ========================================================================= */

/**
 * Encrypt plaintext using AES-256-GCM with unique 96-bit nonce and authentication tag
 *
 * @param {string | Buffer} plaintext
 * @param {string | Buffer} [associatedData]
 * @param {Buffer} [customKey256]
 * @returns {{ version: string, iv: string, authTag: string, ciphertext: string, associatedDataHash: string, serialized: string }}
 */
export function encryptAes256Gcm(plaintext, associatedData = null, customKey256 = null) {
  const ptBuf = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(String(plaintext), "utf8");
  const key = customKey256 || defaultKeys.gcmKey;

  if (!Buffer.isBuffer(key) || key.length !== 32) {
    throw new Error("AES-256-GCM requires a 256-bit (32-byte) key.");
  }

  const iv = crypto.randomBytes(12); // Standard 96-bit nonce
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

  let adBuf = Buffer.alloc(0);
  if (associatedData !== null && associatedData !== undefined) {
    adBuf = Buffer.isBuffer(associatedData) ? associatedData : Buffer.from(String(associatedData), "utf8");
    cipher.setAAD(adBuf);
  }

  const ciphertext = Buffer.concat([cipher.update(ptBuf), cipher.final()]);
  const authTag = cipher.getAuthTag();

  const ivHex = iv.toString("hex");
  const authTagHex = authTag.toString("hex");
  const ciphertextHex = ciphertext.toString("hex");
  const adHash = crypto.createHash("sha256").update(adBuf).digest("hex");

  return {
    version: GCM_VERSION,
    iv: ivHex,
    authTag: authTagHex,
    ciphertext: ciphertextHex,
    associatedDataHash: adHash,
    serialized: `${GCM_VERSION}:${ivHex}:${authTagHex}:${ciphertextHex}:${adHash}`,
  };
}

/**
 * Decrypt ciphertext using AES-256-GCM with authentication tag and AAD verification
 *
 * @param {object | string} gcmPayload
 * @param {string | Buffer} [associatedData]
 * @param {Buffer} [customKey256]
 * @returns {Buffer} Decrypted plaintext buffer
 */
export function decryptAes256Gcm(gcmPayload, associatedData = null, customKey256 = null) {
  let ivHex = "";
  let authTagHex = "";
  let ciphertextHex = "";

  if (typeof gcmPayload === "string") {
    const parts = gcmPayload.split(":");
    if (parts.length >= 4 && parts[0] === GCM_VERSION) {
      ivHex = parts[1];
      authTagHex = parts[2];
      ciphertextHex = parts[3];
    } else {
      throw new Error("Invalid serialized AES-256-GCM string format.");
    }
  } else if (gcmPayload && typeof gcmPayload === "object") {
    ivHex = gcmPayload.iv;
    authTagHex = gcmPayload.authTag;
    ciphertextHex = gcmPayload.ciphertext;
  } else {
    throw new Error("Missing or malformed AES-256-GCM payload.");
  }

  const iv = Buffer.from(ivHex, "hex");
  const authTag = Buffer.from(authTagHex, "hex");
  const ciphertext = Buffer.from(ciphertextHex, "hex");

  if (iv.length !== 12) {
    throw new Error("Invalid AES-256-GCM IV length (must be 12 bytes / 96 bits).");
  }
  if (authTag.length !== 16) {
    throw new Error("Invalid AES-256-GCM authentication tag length (must be 16 bytes).");
  }

  const key = customKey256 || defaultKeys.gcmKey;
  if (!Buffer.isBuffer(key) || key.length !== 32) {
    throw new Error("AES-256-GCM requires a 256-bit (32-byte) key.");
  }

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);

  if (associatedData !== null && associatedData !== undefined) {
    const adBuf = Buffer.isBuffer(associatedData) ? associatedData : Buffer.from(String(associatedData), "utf8");
    decipher.setAAD(adBuf);
  }

  try {
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return plaintext;
  } catch (err) {
    throw new Error(
      "AES-256-GCM authentication failed: Ciphertext, IV, AAD or authentication tag has been tampered with."
    );
  }
}
