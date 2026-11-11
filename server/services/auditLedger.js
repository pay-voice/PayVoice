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

let ledgerBackup = null;

/**
 * Demo Simulation: Injects a bit-flip / payload alteration into an audit entry
 * Used during live hackathon judging to demonstrate real-time cryptographic tampering detection.
 * @param {number} [targetIndex] - Index to tamper with (defaults to latest non-genesis entry)
 * @param {string} [tamperedPayload] - Malicious value to inject
 * @returns {object} Tampered record details
 */
export function tamperAuditEntry(targetIndex = null, tamperedPayload = '{"amount": 9999.00, "attacker": "evil@hacker.com"}') {
  if (auditLedger.length <= 1) {
    // If only genesis exists, create an entry first so we can tamper with it
    appendAuditEntry({
      transcript: "Demo Transaction for Tamper Testing",
      stagedPayload: { amount: 100.0, item: "Standard Export Goods" },
      status: "COMPLETED",
    });
  }

  // Save clean snapshot before tampering
  if (!ledgerBackup) {
    ledgerBackup = JSON.parse(JSON.stringify(auditLedger));
  }

  const idx = targetIndex !== null && targetIndex >= 0 && targetIndex < auditLedger.length
    ? targetIndex
    : auditLedger.length - 1;

  const original = { ...auditLedger[idx] };
  // Inject malicious bit-flip without re-computing the rowHash
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
 * @returns {{ restored: boolean, totalRecords: number, message: string }}
 */
export function restoreAuditLedger() {
  if (ledgerBackup) {
    auditLedger.length = 0;
    auditLedger.push(...JSON.parse(JSON.stringify(ledgerBackup)));
    ledgerBackup = null;
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

