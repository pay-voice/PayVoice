import crypto from "crypto";

const GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

/**
 * In-memory tamper-evident sequential hash chain
 * Initialized with an immutable Genesis Block
 */
const auditLedger = [
  {
    index: 0,
    timestamp: new Date().toISOString(),
    prevHash: "N/A",
    transcriptHash: "GENESIS_TRANSCRIPT",
    stagedPayloadHash: "GENESIS_PAYLOAD",
    passkeyAssertionId: "GENESIS_ROOT",
    invoiceId: "GENESIS_INV_ROOT",
    status: "INITIALIZED",
    rowHash: GENESIS_HASH,
    metadata: { note: "PayVoice Tamper-Evident Audit Ledger Genesis Block" },
  },
];

function sha256(str) {
  return crypto.createHash("sha256").update(String(str)).digest("hex");
}

/**
 * Append an immutable entry to the cryptographic hash chain
 * rowHash = SHA256(prevHash + "|" + transcriptHash + "|" + stagedPayloadHash + "|" + passkeyAssertionId + "|" + status + "|" + timestamp)
 * @param {object} entry
 * @returns {object} The created audit record
 */
export function appendAuditEntry({ transcript = "", stagedPayload = {}, passkeyAssertionId = "N/A", invoiceId = "N/A", status = "STAGED", metadata = {} }) {
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
  return newRecord;
}

/**
 * Return all records in the audit ledger
 */
export function getAuditLedger() {
  return [...auditLedger];
}

/**
 * Re-evaluate every single hash in the chain from Genesis to tip
 * Detects any in-flight database tampering, row insertion, or bit flips
 * @returns {{ valid: boolean, totalRecords: number, verifiedAt: string, brokenIndex?: number }}
 */
export function verifyLedgerIntegrity() {
  const total = auditLedger.length;
  const verifiedAt = new Date().toISOString();

  if (total === 0) {
    return { valid: false, totalRecords: 0, verifiedAt, error: "Empty ledger" };
  }

  // Genesis verification
  if (auditLedger[0].rowHash !== GENESIS_HASH) {
    return { valid: false, totalRecords: total, verifiedAt, brokenIndex: 0, error: "Genesis row hash compromised" };
  }

  for (let i = 1; i < total; i++) {
    const current = auditLedger[i];
    const previous = auditLedger[i - 1];

    // Check back-link pointer
    if (current.prevHash !== previous.rowHash) {
      return {
        valid: false,
        totalRecords: total,
        verifiedAt,
        brokenIndex: i,
        error: `Broken link at index ${i}: prevHash mismatch. Expected '${previous.rowHash}', found '${current.prevHash}'`,
      };
    }

    // Recompute row hash from values
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

  return {
    valid: true,
    totalRecords: total,
    chainRoot: auditLedger[total - 1].rowHash,
    verifiedAt,
  };
}
