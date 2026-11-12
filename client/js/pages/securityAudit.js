/**
 * Page 8: Security & Audit Dashboard
 * Displays WebAuthn passkey state, guardrail policies, interactive firewall simulator,
 * SHA-256 hash-chained audit ledger, tamper verification, and benchmark runner.
 */

import { api } from "../api.js";
import { store } from "../store.js";
import { registerDevicePasskey } from "../passkey.js";
import {
  escapeHtml,
  formatDateTime,
  truncateHash,
  getStatusBadgeClass,
  openModal,
  closeModal,
  showToast,
} from "../utils.js";

let ledgerSearch = "";
let ledgerStatusFilter = "ALL";
let lastSimResult = null;
let lastBenchmarkReport = null;

export function renderSecurityAuditPage(mount) {
  const state = store.getState();
  const ledger = state.auditLedger || [];
  const verify = state.ledgerVerification;
  const buyers = state.buyers || [];
  const hasWebAuthn = Boolean(window.PublicKeyCredential);

  const statuses = Array.from(new Set(ledger.map((r) => r.status)));
  const blockedCount = ledger.filter((r) =>
    ["FIREWALL_BLOCKED", "POLICY_VIOLATION", "WEBAUTHN_REJECTED", "BLOCKED_ATTACK", "BLOCKED_UNVERIFIED_TOOL_CALL", "BLOCKED_AUDIO_REPLAY"].includes(
      r.status
    )
  ).length;

  const filteredLedger = ledger
    .filter((row) => {
      const q = ledgerSearch.toLowerCase();
      const matchSearch =
        !q ||
        String(row.status).toLowerCase().includes(q) ||
        String(row.invoiceId || "").toLowerCase().includes(q) ||
        String(row.passkeyAssertionId || "").toLowerCase().includes(q) ||
        String(row.rowHash || "").toLowerCase().includes(q);
      const matchStatus = ledgerStatusFilter === "ALL" || row.status === ledgerStatusFilter;
      return matchSearch && matchStatus;
    })
    .slice()
    .reverse();

  const isFrozen = Boolean(state.killSwitch?.frozen);

  mount.innerHTML = `
    <div class="page-header">
      <div class="page-header-copy">
        <h1>Security & Audit</h1>
        <p>FIDO2 WebAuthn posture, prompt-injection firewall & tamper-evident SHA-256 hash chain</p>
      </div>
      <div class="page-header-actions">
        <button type="button" class="btn ${isFrozen ? "btn-primary" : "btn-danger"}" id="sec-kill-switch-btn">
          ${isFrozen ? "Resume Agent" : "Emergency Kill Switch"}
        </button>
        <button type="button" class="btn btn-secondary" id="sec-export-bundle-btn">Export Audit Bundle</button>
        <button type="button" class="btn btn-primary" id="sec-verify-chain-btn">Verify Hash Chain</button>
      </div>
    </div>

    <div class="kpi-grid">
      <div class="metric-card">
        <div class="metric-label">WebAuthn Passkey</div>
        <div class="metric-value" style="font-size:1.15rem;">${state.passkeyEnrolledId ? "Enrolled" : hasWebAuthn ? "Browser Ready" : "Fallback Mode"}</div>
        <div class="metric-foot">${state.passkeyEnrolledId ? escapeHtml(truncateHash(state.passkeyEnrolledId, 20)) : "ECDSA P-256 / FIDO2"}</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Allowlisted Buyers</div>
        <div class="metric-value tabular-nums">${buyers.length}</div>
        <div class="metric-foot">AES-256-GCM encrypted vault</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Blocked / Rejected Events</div>
        <div class="metric-value error tabular-nums">${blockedCount}</div>
        <div class="metric-foot">Firewall, OPGSP & replay shields</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Hash-Chain Integrity</div>
        <div class="metric-value ${verify ? (verify.valid ? "success" : "error") : ""}" style="font-size:1.15rem;">
          ${verify ? (verify.valid ? "PRISTINE" : "TAMPERED") : `${ledger.length} Blocks`}
        </div>
        <div class="metric-foot">${verify ? `${verify.totalRecords} verified &bull; ${verify.checkpointsVerified || 0} checkpoints` : "Click Verify Hash Chain"}</div>
      </div>
    </div>

    ${
      verify
        ? `
      <div class="alert ${verify.valid ? "alert-success" : "alert-error"}" role="status">
        <div class="alert-content">
          <span class="alert-title">${verify.valid ? "Cryptographic Audit Chain Verified Intact" : "Tampering or Chain Break Detected!"}</span>
          <span>
            ${
              verify.valid
                ? `Verified ${verify.totalRecords} sequential blocks from Genesis and ${verify.checkpointsVerified} HMAC-signed checkpoints. Tip hash: ${truncateHash(verify.chainRoot, 24)}`
                : `${verify.error || "Hash mismatch detected"} (Broken index: ${verify.brokenIndex ?? "N/A"})`
            }
          </span>
        </div>
      </div>`
        : ""
    }

    <div class="grid-2">
      <!-- Interactive Firewall & Policy Attack Simulator -->
      <div class="card">
        <div class="card-header">
          <div>
            <h2 class="card-title">Guardrail & Firewall Simulator</h2>
            <div class="card-subtitle">Trigger real backend security checks via <code>POST /api/security/simulate-attack</code></div>
          </div>
          <span class="badge badge-purple">Live Red-Team</span>
        </div>

        <div class="form-group">
          <label class="form-label" for="sec-attack-select">Select Adversarial Vector</label>
          <select id="sec-attack-select">
            <option value="prompt_injection">Prompt Injection Override ("Ignore all previous rules...")</option>
            <option value="untrusted_email">Raw Email Injection (attacker-hacker@rogue-phishing.org)</option>
            <option value="domestic_inr_violation">Domestic INR Transfer (₹50,000 INR — OPGSP Blocked)</option>
            <option value="over_cap_5000">Over-Cap Export Invoice ($5,000 USD &gt; $2,500 Cap)</option>
            <option value="replay_challenge">Single-Use WebAuthn Challenge Replay Attack</option>
            <option value="duplicate_invoice">15-Min Sliding Window Duplicate Invoice</option>
          </select>
        </div>

        <div style="display:flex;gap:10px;flex-wrap:wrap;">
          <button type="button" class="btn btn-danger" id="sec-run-attack-btn">Test Firewall Block</button>
          <button type="button" class="btn btn-secondary" id="sec-enroll-pk-btn">Enroll Device Passkey</button>
        </div>

        ${
          lastSimResult
            ? `
          <div class="alert ${lastSimResult.blocked ? "alert-success" : "alert-error"}">
            <div class="alert-content">
              <span class="alert-title">${lastSimResult.blocked ? `BLOCKED by ${escapeHtml(lastSimResult.blockedBy)}` : "NOT BLOCKED"}</span>
              <span>${escapeHtml(lastSimResult.reason)}</span>
            </div>
          </div>`
            : ""
        }
      </div>

      <!-- Tamper Demo & Automated Security Suite -->
      <div class="card">
        <div class="card-header">
          <div>
            <h2 class="card-title">Tamper Detection & Security Suite</h2>
            <div class="card-subtitle">Demonstrate bit-flip detection and run backend adversarial benchmarks</div>
          </div>
          <span class="badge badge-info">SHA-256 + HMAC</span>
        </div>

        <div style="display:flex;gap:8px;flex-wrap:wrap;">
          <button type="button" class="btn btn-secondary btn-sm" id="sec-tamper-btn">Inject Demo Bit-Flip</button>
          <button type="button" class="btn btn-secondary btn-sm" id="sec-restore-btn">Restore Pristine Ledger</button>
          <button type="button" class="btn btn-primary btn-sm" id="sec-benchmarks-btn">Run Automated Benchmarks</button>
        </div>

        ${
          lastBenchmarkReport
            ? `
          <div class="alert ${lastBenchmarkReport.status === "ALL_PASS" ? "alert-success" : "alert-warning"}">
            <div class="alert-content">
              <span class="alert-title">Benchmark Suite: ${lastBenchmarkReport.passed}/${lastBenchmarkReport.totalTests} Passed (${lastBenchmarkReport.executionTimeMs}ms)</span>
              <span>Block rate: ${escapeHtml(lastBenchmarkReport.blockRatePercent)}</span>
            </div>
          </div>
          <div style="max-height:150px;overflow-y:auto;display:flex;flex-direction:column;gap:4px;">
            ${(lastBenchmarkReport.benchmarks || [])
              .map(
                (b) => `
              <div class="policy-check-row">
                <span>${escapeHtml(b.name || b.id || "Check")}</span>
                <span class="badge ${b.status === "PASS" ? "badge-success" : "badge-error"}">${escapeHtml(b.status)}</span>
              </div>`
              )
              .join("")}
          </div>`
            : `<p class="section-desc">Use <strong>Inject Demo Bit-Flip</strong> followed by <strong>Verify Hash Chain</strong> to observe immediate cryptographic tamper detection, then restore the ledger cleanly.</p>`
        }
      </div>
    </div>

    <!-- Full Audit Ledger Table -->
    <div class="card">
      <div class="card-header">
        <div>
          <h2 class="card-title">Immutable Hash-Chained Audit Ledger</h2>
          <div class="card-subtitle">RowHash_n = SHA-256(PrevHash | TranscriptHash | PayloadHash | AssertionID | Status | Timestamp)</div>
        </div>
        <button type="button" class="btn btn-ghost btn-sm" id="sec-refresh-ledger">Refresh</button>
      </div>

      <div class="toolbar">
        <div class="search-input-wrap">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>
          <input type="search" id="sec-ledger-search" placeholder="Search status, invoice ID, assertion, or hash..." value="${escapeHtml(ledgerSearch)}" aria-label="Search audit ledger" />
        </div>
        <select id="sec-ledger-filter" class="filter-select" aria-label="Filter audit events by status">
          <option value="ALL">All Event Types (${ledger.length})</option>
          ${statuses.map((s) => `<option value="${escapeHtml(s)}" ${ledgerStatusFilter === s ? "selected" : ""}>${escapeHtml(s)}</option>`).join("")}
        </select>
      </div>

      ${
        filteredLedger.length
          ? `
        <div class="table-responsive" tabindex="0" role="region" aria-label="Cryptographic audit ledger table">
          <table>
            <thead>
              <tr>
                <th>#</th>
                <th>Timestamp</th>
                <th>Event Status</th>
                <th>Invoice / Ref</th>
                <th>Assertion / Actor</th>
                <th>Row Hash (SHA-256)</th>
                <th style="text-align:right;">Inspect</th>
              </tr>
            </thead>
            <tbody>
              ${filteredLedger
                .slice(0, 25)
                .map(
                  (row) => `
                <tr>
                  <td class="text-xs-mono">#${row.index}</td>
                  <td class="text-xs">${formatDateTime(row.timestamp)}</td>
                  <td><span class="badge ${getStatusBadgeClass(row.status)}">${escapeHtml(row.status)}</span></td>
                  <td class="text-xs-mono">${escapeHtml(row.invoiceId || "N/A")}</td>
                  <td class="text-xs-mono">${escapeHtml(truncateHash(row.passkeyAssertionId, 18))}</td>
                  <td class="text-xs-mono" style="color:var(--color-brand-primary);">${escapeHtml(truncateHash(row.rowHash, 18))}</td>
                  <td style="text-align:right;">
                    <button type="button" class="btn btn-secondary btn-sm" data-audit-idx="${row.index}">Details</button>
                  </td>
                </tr>`
                )
                .join("")}
            </tbody>
          </table>
        </div>`
          : `<div class="empty-state"><p>No audit events match your filter.</p></div>`
      }
    </div>
  `;

  // Wire controls
  document.getElementById("sec-ledger-search")?.addEventListener("input", (e) => {
    ledgerSearch = e.target.value;
    renderSecurityAuditPage(mount);
  });
  document.getElementById("sec-ledger-filter")?.addEventListener("change", (e) => {
    ledgerStatusFilter = e.target.value;
    renderSecurityAuditPage(mount);
  });

  document.getElementById("sec-verify-chain-btn")?.addEventListener("click", async () => {
    try {
      const res = await api.verifyAuditLedger();
      store.setState({ ledgerVerification: res });
      renderSecurityAuditPage(mount);
      showToast({
        title: res.valid ? "Audit Chain Pristine" : "Integrity Alert",
        message: res.valid ? `${res.totalRecords} blocks verified.` : res.error,
        type: res.valid ? "success" : "error",
      });
    } catch (err) {
      showToast({ title: "Verification Failed", message: err.message, type: "error" });
    }
  });

  document.getElementById("sec-run-attack-btn")?.addEventListener("click", async () => {
    const attackType = document.getElementById("sec-attack-select")?.value;
    const btn = document.getElementById("sec-run-attack-btn");
    btn.disabled = true;
    btn.textContent = "Testing...";
    try {
      lastSimResult = await api.simulateAttack(attackType);
      const ledgerRes = await api.getAuditLedger();
      store.setState({ auditLedger: ledgerRes.ledger || [] });
      renderSecurityAuditPage(mount);
      showToast({
        title: lastSimResult.blocked ? "Attack Blocked by Firewall" : "Simulation Finished",
        message: lastSimResult.blockedBy,
        type: lastSimResult.blocked ? "success" : "warning",
      });
    } catch (err) {
      showToast({ title: "Simulation Error", message: err.message, type: "error" });
      btn.disabled = false;
      btn.textContent = "Test Firewall Block";
    }
  });

  document.getElementById("sec-enroll-pk-btn")?.addEventListener("click", async () => {
    const btn = document.getElementById("sec-enroll-pk-btn");
    btn.disabled = true;
    btn.textContent = "Enrolling...";
    try {
      const res = await registerDevicePasskey();
      store.setState({ passkeyEnrolledId: res.credentialId });
      renderSecurityAuditPage(mount);
      showToast({ title: "Passkey Enrolled", message: res.message, type: "success" });
    } catch (err) {
      showToast({ title: "Enrollment Error", message: err.message, type: "error" });
      btn.disabled = false;
      btn.textContent = "Enroll Device Passkey";
    }
  });

  document.getElementById("sec-tamper-btn")?.addEventListener("click", async () => {
    try {
      await api.simulateTamper();
      const [ledgerRes, verRes] = await Promise.all([api.getAuditLedger(), api.verifyAuditLedger()]);
      store.setState({ auditLedger: ledgerRes.ledger || [], ledgerVerification: verRes });
      renderSecurityAuditPage(mount);
      showToast({ title: "Simulated Bit-Flip Injected", message: "Verification now detects tampering.", type: "warning" });
    } catch (err) {
      showToast({ title: "Tamper Error", message: err.message, type: "error" });
    }
  });

  document.getElementById("sec-restore-btn")?.addEventListener("click", async () => {
    try {
      await api.restoreLedger();
      const [ledgerRes, verRes] = await Promise.all([api.getAuditLedger(), api.verifyAuditLedger()]);
      store.setState({ auditLedger: ledgerRes.ledger || [], ledgerVerification: verRes });
      renderSecurityAuditPage(mount);
      showToast({ title: "Ledger Restored", message: "Pristine hash chain restored.", type: "success" });
    } catch (err) {
      showToast({ title: "Restore Error", message: err.message, type: "error" });
    }
  });

  document.getElementById("sec-benchmarks-btn")?.addEventListener("click", async () => {
    const btn = document.getElementById("sec-benchmarks-btn");
    btn.disabled = true;
    btn.textContent = "Running Suite...";
    try {
      lastBenchmarkReport = await api.runBenchmarks();
      const ledgerRes = await api.getAuditLedger();
      store.setState({ auditLedger: ledgerRes.ledger || [] });
      renderSecurityAuditPage(mount);
      showToast({
        title: "Benchmarks Complete",
        message: `${lastBenchmarkReport.passed}/${lastBenchmarkReport.totalTests} tests passed.`,
        type: "success",
      });
    } catch (err) {
      showToast({ title: "Benchmark Error", message: err.message, type: "error" });
      btn.disabled = false;
      btn.textContent = "Run Automated Benchmarks";
    }
  });

  document.getElementById("sec-kill-switch-btn")?.addEventListener("click", async () => {
    const nextFrozen = !Boolean(store.getState().killSwitch?.frozen);
    try {
      const res = await api.toggleKillSwitch(
        nextFrozen,
        nextFrozen ? "Emergency freeze toggled from Security & Audit console" : "Agent resumed from Security & Audit console"
      );
      const ledgerRes = await api.getAuditLedger().catch(() => null);
      store.setState({
        killSwitch: { frozen: Boolean(res.frozen), reason: res.reason || "", frozenAt: res.frozenAt || null },
        ...(ledgerRes ? { auditLedger: ledgerRes.ledger || [] } : {}),
      });
      renderSecurityAuditPage(mount);
      showToast({
        title: res.frozen ? "Agent Frozen (Kill Switch Active)" : "Agent Operations Resumed",
        message: res.message,
        type: res.frozen ? "warning" : "success",
      });
    } catch (err) {
      showToast({ title: "Kill Switch Error", message: err.message, type: "error" });
    }
  });

  document.getElementById("sec-export-bundle-btn")?.addEventListener("click", async () => {
    try {
      const res = await api.exportAuditBundle();
      const blob = new Blob([JSON.stringify(res.bundle, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `payvoice-audit-bundle-${Date.now()}.json`;
      document.body.appendChild(a);
      a.click();
      URL.revokeObjectURL(url);
      a.remove();
      showToast({ title: "Audit Proof Bundle Exported", message: `${res.bundle.totalRecords} blocks exported.`, type: "success" });
    } catch (err) {
      showToast({ title: "Export Error", message: err.message, type: "error" });
    }
  });

  document.getElementById("sec-refresh-ledger")?.addEventListener("click", async () => {
    try {
      const res = await api.getAuditLedger();
      store.setState({ auditLedger: res.ledger || [] });
      renderSecurityAuditPage(mount);
    } catch (err) {
      showToast({ title: "Refresh Error", message: err.message, type: "error" });
    }
  });

  mount.querySelectorAll("[data-audit-idx]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const idx = Number(btn.getAttribute("data-audit-idx"));
      const row = ledger.find((r) => r.index === idx);
      if (!row) return;
      openModal({
        title: `Audit Ledger Block #${row.index}`,
        size: "lg",
        bodyHtml: `
          <div class="kv-grid">
            <div class="kv-item"><div class="kv-label">Status</div><div class="kv-val">${escapeHtml(row.status)}</div></div>
            <div class="kv-item"><div class="kv-label">Timestamp</div><div class="kv-val">${formatDateTime(row.timestamp)}</div></div>
            <div class="kv-item"><div class="kv-label">Invoice ID</div><div class="kv-val" style="font-family:var(--font-mono);">${escapeHtml(row.invoiceId || "N/A")}</div></div>
            <div class="kv-item"><div class="kv-label">Passkey Assertion ID</div><div class="kv-val" style="font-family:var(--font-mono);">${escapeHtml(row.passkeyAssertionId)}</div></div>
          </div>
          <div><div class="form-label" style="margin-bottom:4px;">Row Hash (SHA-256)</div><div class="mono-box">${escapeHtml(row.rowHash)}</div></div>
          <div><div class="form-label" style="margin-bottom:4px;">Previous Block Hash</div><div class="mono-box">${escapeHtml(row.prevHash)}</div></div>
          <div><div class="form-label" style="margin-bottom:4px;">Staged Payload Hash</div><div class="mono-box">${escapeHtml(row.stagedPayloadHash)}</div></div>
          <div><div class="form-label" style="margin-bottom:4px;">Metadata</div><pre class="mono-box" style="white-space:pre-wrap;">${escapeHtml(JSON.stringify(row.metadata || {}, null, 2))}</pre></div>
        `,
        footerHtml: `<button type="button" class="btn btn-primary" id="aud-close">Close</button>`,
        onMount: () => document.getElementById("aud-close")?.addEventListener("click", closeModal),
      });
    });
  });
}

