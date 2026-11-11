import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const dataDir = path.resolve(__dirname, "../data");
const checkpointFilePath = path.join(dataDir, "auditCheckpoints.json");

const CHECKPOINT_SECRET = process.env.CHECKPOINT_SECRET || "payvoice-immutable-checkpoint-2026";
const GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

const ledgerFilePath = path.join(dataDir, "auditLedger.json");

const GENESIS_RECORD = {
  index: 0,
  timestamp: "2026-11-10T00:00:00.000Z",
  prevHash: "N/A",
  transcriptHash: "GENESIS_TRANSCRIPT",
  stagedPayloadHash: "GENESIS_PAYLOAD",
  passkeyAssertionId: "GENESIS_ROOT",
  invoiceId: "GENESIS_INV_ROOT",
  status: "INITIALIZED",
  rowHash: GENESIS_HASH,
  metadata: { note: "PayVoice Tamper-Evident Audit Ledger Genesis Block" },
};

function sha256(str) {
  return crypto.createHash("sha256").update(String(str)).digest("hex");
}

function computeHmacSignature(content) {
  return crypto.createHmac("sha256", CHECKPOINT_SECRET).update(String(content)).digest("hex");
}

/**
 * Load persisted ledger from disk or initialize with Genesis
 */
function loadLedger() {
  try {
    if (fs.existsSync(ledgerFilePath)) {
      const raw = fs.readFileSync(ledgerFilePath, "utf8");
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed) && parsed.length > 0) {
        return parsed;
      }
    }
  } catch (err) {
    console.warn("[AuditLedger] Ledger load notice:", err.message);
  }
  return [{ ...GENESIS_RECORD }];
}

function persistLedger() {
  try {
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }
    fs.writeFileSync(ledgerFilePath, JSON.stringify(auditLedger, null, 2), "utf8");
  } catch (err) {
    console.warn("[AuditLedger] Ledger persist warning:", err.message);
  }
}

/**
 * In-memory + persisted tamper-evident sequential hash chain
 */
const auditLedger = loadLedger();
let ledgerBackup = null;

// Ensure initial ledger is persisted
if (!fs.existsSync(ledgerFilePath)) {
  persistLedger();
}

/**
 * Load persisted checkpoints from disk
 */
function loadCheckpoints() {
  try {
    if (fs.existsSync(checkpointFilePath)) {
      const raw = fs.readFileSync(checkpointFilePath, "utf8");
      return JSON.parse(raw);
    }
  } catch (err) {
    console.warn("[AuditLedger] Checkpoint load notice:", err.message);
  }
  return [];
}

/**
 * Save an independent cryptographic checkpoint to server/data/auditCheckpoints.json
 */
export function createCheckpoint(triggerReason = "MANUAL") {
  try {
    const checkpoints = loadCheckpoints();
    const entryCount = auditLedger.length;
    const tipHash = auditLedger[entryCount - 1].rowHash;

    // Calculate Merkle root of all block hashes
    const combinedHashes = auditLedger.map((b) => b.rowHash).join(":");
    const merkleRoot = sha256(combinedHashes);

    const checkpointId = `cp_${Date.now()}_${entryCount}`;
    const timestamp = new Date().toISOString();
    const signaturePayload = `${checkpointId}:${entryCount}:${tipHash}:${merkleRoot}:${timestamp}`;
    const hmacSignature = computeHmacSignature(signaturePayload);

    const newCheckpoint = {
      checkpointId,
      entryCount,
      tipHash,
      merkleRoot,
      hmacSignature,
      triggerReason,
      timestamp,
    };

    // Filter out existing checkpoint for the exact same height to prevent conflicting duplicate checkpoints
    const updatedCheckpoints = checkpoints.filter((c) => c.entryCount !== entryCount);
    updatedCheckpoints.push(newCheckpoint);

    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }
    fs.writeFileSync(checkpointFilePath, JSON.stringify(updatedCheckpoints, null, 2), "utf8");
    return newCheckpoint;
  } catch (err) {
    console.warn("[AuditLedger] Checkpoint write warning:", err.message);
    return null;
  }
}

/**
 * Reset ledger and checkpoints to a clean Genesis baseline
 */
export function resetAuditLedger() {
  auditLedger.length = 0;
  auditLedger.push({ ...GENESIS_RECORD });
  persistLedger();

  const combinedHashes = auditLedger.map((b) => b.rowHash).join(":");
  const merkleRoot = sha256(combinedHashes);
  const checkpointId = `cp_genesis_${Date.now()}`;
  const timestamp = new Date().toISOString();
  const signaturePayload = `${checkpointId}:1:${GENESIS_HASH}:${merkleRoot}:${timestamp}`;
  const hmacSignature = computeHmacSignature(signaturePayload);

  const genesisCheckpoint = {
    checkpointId,
    entryCount: 1,
    tipHash: GENESIS_HASH,
    merkleRoot,
    hmacSignature,
    triggerReason: "GENESIS_BOOT",
    timestamp,
  };

  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }
  fs.writeFileSync(checkpointFilePath, JSON.stringify([genesisCheckpoint], null, 2), "utf8");
  ledgerBackup = null;
  return { reset: true, totalRecords: 1 };
}

// Initialize first checkpoint on boot if none exists
if (loadCheckpoints().length === 0) {
  createCheckpoint("GENESIS_BOOT");
}

/**
 * Append an immutable entry to the cryptographic hash chain
 * Formula strictly computes:
 * rowHash = SHA256(prevHash + "|" + transcriptHash + "|" + stagedPayloadHash + "|" + passkeyAssertionId + "|" + status + "|" + timestamp)
 *
 * @param {object} entry
 * @returns {object} The created audit record
 */
export function appendAuditEntry({
  transcript = "",
  stagedPayload = {},
  passkeyAssertionId = "N/A",
  invoiceId = "N/A",
  status = "STAGED",
  metadata = {},
}) {
  const lastBlock = auditLedger[auditLedger.length - 1];
  const prevHash = lastBlock.rowHash;

  const transcriptHash = sha256(transcript || "NONE");
  const stagedPayloadHash = sha256(JSON.stringify(stagedPayload || {}));
  const timestamp = new Date().toISOString();

  const preimage = `${prevHash}|${transcriptHash}|${stagedPayloadHash}|${passkeyAssertionId}|${status}|${timestamp}`;
  const rowHash = sha256(preimage);

  const newRecord = {
    index: auditLedger.length,
    timestamp,
    prevHash,
    transcriptHash,
    stagedPayloadHash,
    passkeyAssertionId,
    invoiceId,
    status,
    rowHash,
    metadata,
  };

  auditLedger.push(newRecord);
  persistLedger();

  // Checkpoint snapshot triggered every 5 entries or on critical AUTHORIZED / PAID transitions
  if (auditLedger.length % 5 === 0 || status === "AUTHORIZED" || status === "PAID" || status === "INVOICE_SENT") {
    createCheckpoint(`STATUS_${status}`);
  }

  return newRecord;
}

/**
 * Helper to record invoice lifecycle transitions cryptographically
 * e.g., DRAFT -> SENT -> PAID
 */
export function recordInvoiceLifecycleEvent(invoiceId, fromState, toState, metadata = {}) {
  const status = `LIFECYCLE_${toState.toUpperCase()}`;
  const record = appendAuditEntry({
    transcript: `Invoice Lifecycle Transition: ${fromState} -> ${toState}`,
    stagedPayload: { invoiceId, fromState, toState, ...metadata },
    passkeyAssertionId: metadata.assertionId || "LIFECYCLE_GATE",
    invoiceId,
    status,
    metadata: { ...metadata, transition: `${fromState} -> ${toState}` },
  });

  // Force immediate checkpoint
  createCheckpoint(`TRANSITION_${toState}`);
  return record;
}

/**
 * Return all records in the audit ledger
 */
export function getAuditLedger() {
  return [...auditLedger];
}

/**
 * Re-evaluate every single hash in the chain from Genesis to tip AND
 * cross-verify against independent audit checkpoints to catch full ledger rewrite / truncation attacks.
 *
 * @returns {{ valid: boolean, totalRecords: number, verifiedAt: string, brokenIndex?: number, checkpointsVerified: number }}
 */
export function verifyLedgerIntegrity() {
  const total = auditLedger.length;
  const verifiedAt = new Date().toISOString();

  if (total === 0) {
    return { valid: false, totalRecords: 0, verifiedAt, error: "Empty ledger" };
  }

  // 1. Genesis verification
  if (auditLedger[0].rowHash !== GENESIS_HASH) {
    return { valid: false, totalRecords: total, verifiedAt, brokenIndex: 0, error: "Genesis row hash compromised" };
  }

  // 2. Sequential block-by-block hash verification
  for (let i = 1; i < total; i++) {
    const current = auditLedger[i];
    const previous = auditLedger[i - 1];

    if (current.prevHash !== previous.rowHash) {
      return {
        valid: false,
        totalRecords: total,
        verifiedAt,
        brokenIndex: i,
        error: `Broken link at index ${i}: prevHash mismatch. Expected '${previous.rowHash}', found '${current.prevHash}'`,
      };
    }

    const preimage = `${current.prevHash}|${current.transcriptHash}|${current.stagedPayloadHash}|${current.passkeyAssertionId}|${current.status}|${current.timestamp}`;
    const expectedHash = sha256(preimage);

    if (current.rowHash !== expectedHash) {
      return {
        valid: false,
        totalRecords: total,
        verifiedAt,
        brokenIndex: i,
        error: `Tampering detected at row index ${i}! Stored hash does not match computed digest.`,
      };
    }
  }

  // 3. Cross-Verification against independent checkpoints (anti-truncation & anti-rewrite)
  const checkpoints = loadCheckpoints();
  let validCheckpoints = 0;

  for (const cp of checkpoints) {
    // A. Verify Checkpoint HMAC signature
    const signaturePayload = `${cp.checkpointId}:${cp.entryCount}:${cp.tipHash}:${cp.merkleRoot}:${cp.timestamp}`;
    const expectedSig = computeHmacSignature(signaturePayload);
    if (cp.hmacSignature !== expectedSig) {
      return {
        valid: false,
        totalRecords: total,
        verifiedAt,
        error: `Checkpoint signature compromised at checkpoint '${cp.checkpointId}'`,
      };
    }

    // B. Detect Ledger Truncation attack
    if (total < cp.entryCount) {
      return {
        valid: false,
        totalRecords: total,
        verifiedAt,
        error: `Ledger truncation attack detected: Checkpoint requires ${cp.entryCount} entries, but ledger only has ${total}.`,
      };
    }

    // C. Detect Full-Chain Rewrite attack
    const recordedTip = auditLedger[cp.entryCount - 1]?.rowHash;
    if (recordedTip !== cp.tipHash) {
      return {
        valid: false,
        totalRecords: total,
        verifiedAt,
        error: `Ledger rewrite attack detected: Historical block at index ${cp.entryCount - 1} hash '${recordedTip}' does not match checkpoint tip '${cp.tipHash}'.`,
      };
    }

    validCheckpoints++;
  }

  return {
    valid: true,
    totalRecords: total,
    chainRoot: auditLedger[total - 1].rowHash,
    checkpointsVerified: validCheckpoints,
    verifiedAt,
  };
}

/**
 * Demo Simulation: Injects a bit-flip / payload alteration into an audit entry
 */
export function tamperAuditEntry(targetIndex = null, tamperedPayload = '{"amount": 9999.00, "attacker": "evil@hacker.com"}') {
  if (auditLedger.length <= 1) {
    appendAuditEntry({
      transcript: "Demo Transaction for Tamper Testing",
      stagedPayload: { amount: 100.0, item: "Standard Export Goods" },
      status: "COMPLETED",
    });
  }

  if (!ledgerBackup) {
    ledgerBackup = JSON.parse(JSON.stringify(auditLedger));
  }

  const idx = targetIndex !== null && targetIndex >= 0 && targetIndex < auditLedger.length
    ? targetIndex
    : auditLedger.length - 1;

  const original = { ...auditLedger[idx] };
  auditLedger[idx].stagedPayloadHash = sha256(tamperedPayload);
  auditLedger[idx].metadata = {
    ...auditLedger[idx].metadata,
    SIMULATED_TAMPER: true,
    injectedAt: new Date().toISOString(),
    tamperedPayload,
  };

  return {
    tampered: true,
    index: idx,
    originalHash: original.rowHash,
    tamperedPayloadHash: auditLedger[idx].stagedPayloadHash,
    notice: "Simulated bit-flip injected. Running /api/audit-ledger/verify will now fail.",
  };
}

/**
 * Demo Simulation: Restores clean audit ledger from pristine backup
 */
export function restoreAuditLedger() {
  if (ledgerBackup) {
    auditLedger.length = 0;
    auditLedger.push(...JSON.parse(JSON.stringify(ledgerBackup)));
    ledgerBackup = null;
    persistLedger();
    return {
      restored: true,
      totalRecords: auditLedger.length,
      message: "Audit ledger restored to pristine state. Hash chain integrity restored.",
    };
  }

  return {
    restored: false,
    totalRecords: auditLedger.length,
    message: "No active tampering state found. Ledger is already in original state.",
  };
}
