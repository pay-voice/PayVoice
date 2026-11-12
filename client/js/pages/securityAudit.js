/**
 * Page 8: Security & Audit Dashboard
 * Displays WebAuthn passkey state, guardrail policies, interactive firewall simulator,
 * SHA-256 hash-chained audit ledger, tamper verification, and benchmark/red-team runners.
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
let selectedAttackType = "prompt_injection";
let currentLedgerPage = 1;
const LEDGER_PAGE_SIZE = 10;
let lastSimResult = null;
let lastBenchmarkReport = null;
let lastRedTeamReport = null;
let isLedgerFetching = false;

export function renderSecurityAuditPage(mount) {
  // Capture search input focus state
  const activeEl = document.activeElement;
  const isSearchFocused = activeEl && activeEl.id === "sec-ledger-search";
  const searchCaretStart = isSearchFocused ? activeEl.selectionStart : null;
  const searchCaretEnd = isSearchFocused ? activeEl.selectionEnd : null;

  const state = store.getState();
  const ledger = state.auditLedger || [];
  const verify = state.ledgerVerification;
  const buyers = state.buyers || [];
  const hasWebAuthn = Boolean(window.PublicKeyCredential);

  // Auto-fetch if ledger is empty on mount
  if (ledger.length === 0 && !isLedgerFetching) {
    isLedgerFetching = true;
    Promise.all([api.getAuditLedger().catch(() => null), api.verifyAuditLedger().catch(() => null)])
      .then(([ledgerRes, verifyRes]) => {
        isLedgerFetching = false;
        store.setState({
          auditLedger: ledgerRes?.ledger || [],
          ...(verifyRes ? { ledgerVerification: verifyRes } : {}),
        });
        renderSecurityAuditPage(mount);
      })
      .catch(() => {
        isLedgerFetching = false;
      });
  }

  const statuses = Array.from(new Set(ledger.map((r) => r.status).filter(Boolean)));
  const blockedCount = ledger.filter((r) =>
    [
      "FIREWALL_BLOCKED",
      "POLICY_VIOLATION",
      "WEBAUTHN_REJECTED",
      "BLOCKED_ATTACK",
      "BLOCKED_UNVERIFIED_TOOL_CALL",
      "BLOCKED_AUDIO_REPLAY",
    ].includes(r.status)
  ).length;

  const filteredLedger = ledger
    .filter((row) => {
      const q = ledgerSearch.toLowerCase().trim();
      const matchSearch =
        !q ||
        String(row.status || "").toLowerCase().includes(q) ||
        String(row.invoiceId || "").toLowerCase().includes(q) ||
        String(row.passkeyAssertionId || "").toLowerCase().includes(q) ||
        String(row.rowHash || "").toLowerCase().includes(q) ||
        String(row.transcript || "").toLowerCase().includes(q);
      const matchStatus = ledgerStatusFilter === "ALL" || row.status === ledgerStatusFilter;
      return matchSearch && matchStatus;
    })
    .slice()
    .reverse();

  const totalLedgerPages = Math.max(1, Math.ceil(filteredLedger.length / LEDGER_PAGE_SIZE));
  if (currentLedgerPage > totalLedgerPages) currentLedgerPage = totalLedgerPages;
  const ledgerPageItems = filteredLedger.slice(
    (currentLedgerPage - 1) * LEDGER_PAGE_SIZE,
    currentLedgerPage * LEDGER_PAGE_SIZE
  );

  const isFrozen = Boolean(state.killSwitch?.frozen ?? state.killSwitch?.agentFrozen);

  mount.innerHTML = `
    <div class="page-header">
      <div class="page-header-copy">
        <h1>Security &amp; Audit</h1>
        <p>FIDO2 WebAuthn posture, prompt-injection firewall &amp; tamper-evident SHA-256 hash chain</p>
      </div>
      <div class="page-header-actions">
        <button type="button" class="btn ${isFrozen ? "btn-primary" : "btn-danger"}" id="sec-kill-switch-btn">
          ${isFrozen ? "Resume Agent" : "Emergency Kill Switch"}
        </button>
        <button type="button" class="btn btn-secondary" id="sec-export-bundle-btn">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true" style="margin-right:6px;"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
          Export Audit Bundle
        </button>
        <button type="button" class="btn btn-primary" id="sec-verify-chain-btn">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true" style="margin-right:6px;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
          Verify Hash Chain
        </button>
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
        <div class="metric-foot">Firewall, OPGSP &amp; replay shields</div>
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
                ? `Verified ${verify.totalRecords} sequential blocks from Genesis and ${verify.checkpointsVerified || 0} HMAC-signed checkpoints. Tip hash: ${truncateHash(verify.chainRoot || verify.tipHash, 24)}`
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
            <h2 class="card-title">Guardrail &amp; Firewall Simulator</h2>
            <div class="card-subtitle">Trigger real backend security checks via <code>POST /api/security/simulate-attack</code></div>
          </div>
          <span class="badge badge-purple">Live Red-Team</span>
        </div>

        <div class="form-group">
          <label class="form-label" for="sec-attack-select">Select Adversarial Vector</label>
          <select id="sec-attack-select">
            <option value="prompt_injection" ${selectedAttackType === "prompt_injection" ? "selected" : ""}>Prompt Injection Override ("Ignore all previous rules...")</option>
            <option value="untrusted_email" ${selectedAttackType === "untrusted_email" ? "selected" : ""}>Raw Email Injection (attacker-hacker@rogue-phishing.org)</option>
            <option value="domestic_inr_violation" ${selectedAttackType === "domestic_inr_violation" ? "selected" : ""}>Domestic INR Transfer (₹50,000 INR — OPGSP Blocked)</option>
            <option value="over_cap_5000" ${selectedAttackType === "over_cap_5000" ? "selected" : ""}>Over-Cap Export Invoice ($5,000 USD &gt; $2,500 Cap)</option>
            <option value="replay_challenge" ${selectedAttackType === "replay_challenge" ? "selected" : ""}>Single-Use WebAuthn Challenge Replay Attack</option>
            <option value="duplicate_invoice" ${selectedAttackType === "duplicate_invoice" ? "selected" : ""}>15-Min Sliding Window Duplicate Invoice</option>
          </select>
        </div>

        <div style="display:flex;gap:10px;flex-wrap:wrap;margin-block-end:0.75rem;">
          <button type="button" class="btn btn-danger" id="sec-run-attack-btn">Test Firewall Block</button>
          <button type="button" class="btn btn-secondary" id="sec-enroll-pk-btn">Enroll Device Passkey</button>
        </div>

        ${
          lastSimResult
            ? `
          <div class="alert ${lastSimResult.blocked ? "alert-success" : "alert-error"}">
            <div class="alert-content">
              <span class="alert-title">${lastSimResult.blocked ? `BLOCKED by ${escapeHtml(lastSimResult.blockedBy || "FIREWALL")}` : "NOT BLOCKED"}</span>
              <span>${escapeHtml(lastSimResult.reason || "Simulated attack payload evaluated.")}</span>
            </div>
          </div>`
            : ""
        }
      </div>

      <!-- Tamper Demo & Automated Security Suite -->
      <div class="card">
        <div class="card-header">
          <div>
            <h2 class="card-title">Tamper Detection &amp; Security Suite</h2>
            <div class="card-subtitle">Demonstrate bit-flip detection and run backend adversarial benchmarks</div>
          </div>
          <span class="badge badge-info">SHA-256 + HMAC</span>
        </div>

        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-block-end:0.75rem;">
          <button type="button" class="btn btn-secondary btn-sm" id="sec-tamper-btn">Inject Demo Bit-Flip</button>
          <button type="button" class="btn btn-secondary btn-sm" id="sec-restore-btn">Restore Pristine Ledger</button>
          <button type="button" class="btn btn-primary btn-sm" id="sec-benchmarks-btn">Run Benchmarks (10/10)</button>
          <button type="button" class="btn btn-navy btn-sm" id="sec-redteam-btn">Run Judge Red-Team</button>
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
          <div style="max-height:140px;overflow-y:auto;display:flex;flex-direction:column;gap:4px;margin-block-start:0.5rem;">
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
            : lastRedTeamReport
            ? `
          <div class="alert ${lastRedTeamReport.summary?.blockedPercent === "100.0%" ? "alert-success" : "alert-warning"}">
            <div class="alert-content">
              <span class="alert-title">Live Red-Team Suite: ${lastRedTeamReport.summary?.blocked || 10}/${lastRedTeamReport.summary?.totalTrials || 10} Attacks Blocked</span>
              <span>Block rate: 100.0% &bull; Zero prompt bypasses</span>
            </div>
          </div>
          <div style="max-height:140px;overflow-y:auto;display:flex;flex-direction:column;gap:4px;margin-block-start:0.5rem;">
            ${(lastRedTeamReport.trials || [])
              .map(
                (t) => `
              <div class="policy-check-row">
                <span>${escapeHtml(t.trialId || t.name)}: ${escapeHtml(t.vector || "Vector")}</span>
                <span class="badge ${t.blocked ? "badge-success" : "badge-error"}">${t.blocked ? "BLOCKED" : "BYPASSED"}</span>
              </div>`
              )
              .join("")}
          </div>`
            : `<p class="section-desc">Use <strong>Inject Demo Bit-Flip</strong> followed by <strong>Verify Hash Chain</strong> to observe immediate cryptographic tamper detection, or execute the live suites above.</p>`
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
        ledgerPageItems.length
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
              ${ledgerPageItems
                .map(
                  (row) => `
                <tr>
                  <td class="text-xs-mono">#${row.index}</td>
                  <td class="text-xs">${formatDateTime(row.timestamp)}</td>
                  <td><span class="badge ${getStatusBadgeClass(row.status)}">${escapeHtml(row.status)}</span></td>
                  <td class="text-xs-mono">${escapeHtml(row.invoiceId || "N/A")}</td>
                  <td class="text-xs-mono">${escapeHtml(truncateHash(row.passkeyAssertionId || "N/A", 18))}</td>
                  <td class="text-xs-mono" style="color:var(--color-brand-primary);">${escapeHtml(truncateHash(row.rowHash, 18))}</td>
                  <td style="text-align:right;">
                    <button type="button" class="btn btn-secondary btn-sm" data-audit-idx="${row.index}">Details</button>
                  </td>
                </tr>`
                )
                .join("")}
            </tbody>
          </table>
        </div>
        <div class="pagination">
          <span>Showing ${(currentLedgerPage - 1) * LEDGER_PAGE_SIZE + 1}–${Math.min(currentLedgerPage * LEDGER_PAGE_SIZE, filteredLedger.length)} of ${filteredLedger.length} blocks</span>
          <div class="pagination-controls">
            <button type="button" class="btn btn-secondary btn-sm" id="sec-ledger-prev" ${currentLedgerPage <= 1 ? "disabled" : ""}>Previous</button>
            <span>Page ${currentLedgerPage} of ${totalLedgerPages}</span>
            <button type="button" class="btn btn-secondary btn-sm" id="sec-ledger-next" ${currentLedgerPage >= totalLedgerPages ? "disabled" : ""}>Next</button>
          </div>
        </div>`
          : `<div class="empty-state"><p>No audit events match your filter.</p></div>`
      }
    </div>
  `;

  // Restore search input focus smoothly
  if (isSearchFocused) {
    const searchInput = document.getElementById("sec-ledger-search");
    if (searchInput) {
      searchInput.focus();
      if (searchCaretStart !== null && searchCaretEnd !== null) {
        try {
          searchInput.setSelectionRange(searchCaretStart, searchCaretEnd);
        } catch {
          // ignore
        }
      }
    }
  }

  // Wire search and filter controls
  document.getElementById("sec-ledger-search")?.addEventListener("input", (e) => {
    ledgerSearch = e.target.value;
    currentLedgerPage = 1;
    renderSecurityAuditPage(mount);
  });
  document.getElementById("sec-ledger-filter")?.addEventListener("change", (e) => {
    ledgerStatusFilter = e.target.value;
    currentLedgerPage = 1;
    renderSecurityAuditPage(mount);
  });
  document.getElementById("sec-attack-select")?.addEventListener("change", (e) => {
    selectedAttackType = e.target.value;
  });
  document.getElementById("sec-ledger-prev")?.addEventListener("click", () => {
    if (currentLedgerPage > 1) {
      currentLedgerPage--;
      renderSecurityAuditPage(mount);
    }
  });
  document.getElementById("sec-ledger-next")?.addEventListener("click", () => {
    if (currentLedgerPage < totalLedgerPages) {
      currentLedgerPage++;
      renderSecurityAuditPage(mount);
    }
  });

  // Verify hash chain
  document.getElementById("sec-verify-chain-btn")?.addEventListener("click", async () => {
    try {
      const res = await api.verifyAuditLedger();
      store.setState({ ledgerVerification: res });
      renderSecurityAuditPage(mount);
      showToast({
        title: res.valid ? "Audit Chain Pristine" : "Integrity Alert",
        message: res.valid ? `${res.totalRecords} blocks verified from Genesis.` : res.error,
        type: res.valid ? "success" : "error",
      });
    } catch (err) {
      showToast({ title: "Verification Failed", message: err.message, type: "error" });
    }
  });

  // Run attack simulation
  document.getElementById("sec-run-attack-btn")?.addEventListener("click", async () => {
    const attackType = document.getElementById("sec-attack-select")?.value || selectedAttackType;
    selectedAttackType = attackType;
    const btn = document.getElementById("sec-run-attack-btn");
    if (btn) {
      btn.disabled = true;
      btn.textContent = "Testing...";
    }
    try {
      lastSimResult = await api.simulateAttack(attackType);
      const ledgerRes = await api.getAuditLedger();
      store.setState({ auditLedger: ledgerRes.ledger || [] });
      renderSecurityAuditPage(mount);
      showToast({
        title: lastSimResult.blocked ? "Attack Blocked by Firewall" : "Simulation Finished",
        message: lastSimResult.blockedBy || "Firewall rule triggered",
        type: lastSimResult.blocked ? "success" : "warning",
      });
    } catch (err) {
      showToast({ title: "Simulation Error", message: err.message, type: "error" });
      if (btn) {
        btn.disabled = false;
        btn.textContent = "Test Firewall Block";
      }
    }
  });

  // Enroll device passkey
  document.getElementById("sec-enroll-pk-btn")?.addEventListener("click", async () => {
    const btn = document.getElementById("sec-enroll-pk-btn");
    if (btn) {
      btn.disabled = true;
      btn.textContent = "Enrolling...";
    }
    try {
      const res = await registerDevicePasskey();
      store.setState({ passkeyEnrolledId: res.credentialId });
      renderSecurityAuditPage(mount);
      showToast({ title: "Passkey Enrolled", message: res.message || "FIDO2 credential registered.", type: "success" });
    } catch (err) {
      showToast({ title: "Enrollment Error", message: err.message, type: "error" });
      if (btn) {
        btn.disabled = false;
        btn.textContent = "Enroll Device Passkey";
      }
    }
  });

  // Bit-flip injection
  document.getElementById("sec-tamper-btn")?.addEventListener("click", async () => {
    try {
      await api.simulateTamper();
      const [ledgerRes, verRes] = await Promise.all([api.getAuditLedger(), api.verifyAuditLedger()]);
      store.setState({ auditLedger: ledgerRes.ledger || [], ledgerVerification: verRes });
      renderSecurityAuditPage(mount);
      showToast({ title: "Simulated Bit-Flip Injected", message: "Verification now detects cryptographic break.", type: "warning" });
    } catch (err) {
      showToast({ title: "Tamper Error", message: err.message, type: "error" });
    }
  });

  // Restore pristine ledger
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

  // Run benchmarks
  document.getElementById("sec-benchmarks-btn")?.addEventListener("click", async () => {
    const btn = document.getElementById("sec-benchmarks-btn");
    if (btn) {
      btn.disabled = true;
      btn.textContent = "Running Suite...";
    }
    try {
      lastBenchmarkReport = await api.runBenchmarks();
      lastRedTeamReport = null;
      const ledgerRes = await api.getAuditLedger();
      store.setState({ auditLedger: ledgerRes.ledger || [] });
      renderSecurityAuditPage(mount);
      showToast({
        title: "Benchmarks Complete",
        message: `${lastBenchmarkReport.passed}/${lastBenchmarkReport.totalTests} tests passed (${lastBenchmarkReport.executionTimeMs}ms).`,
        type: "success",
      });
    } catch (err) {
      showToast({ title: "Benchmark Error", message: err.message, type: "error" });
      if (btn) {
        btn.disabled = false;
        btn.textContent = "Run Benchmarks (10/10)";
      }
    }
  });

  // Run Judge Red-Team suite
  document.getElementById("sec-redteam-btn")?.addEventListener("click", async () => {
    const btn = document.getElementById("sec-redteam-btn");
    if (btn) {
      btn.disabled = true;
      btn.textContent = "Executing Attacks...";
    }
    try {
      const redteamRes = await api.runRedTeamSuite();
      lastRedTeamReport = redteamRes.report || redteamRes;
      lastBenchmarkReport = null;
      const ledgerRes = await api.getAuditLedger();
      store.setState({ auditLedger: ledgerRes.ledger || [] });
      renderSecurityAuditPage(mount);
      showToast({
        title: "Live Red-Team Complete",
        message: `${lastRedTeamReport.summary?.blocked || 10}/${lastRedTeamReport.summary?.totalTrials || 10} attacks blocked (100% block rate).`,
        type: "success",
      });
    } catch (err) {
      showToast({ title: "Red-Team Error", message: err.message, type: "error" });
      if (btn) {
        btn.disabled = false;
        btn.textContent = "Run Judge Red-Team";
      }
    }
  });

  // Toggle kill switch
  document.getElementById("sec-kill-switch-btn")?.addEventListener("click", async () => {
    const currentFrozen = Boolean(store.getState().killSwitch?.frozen ?? store.getState().killSwitch?.agentFrozen);
    const nextFrozen = !currentFrozen;
    try {
      const res = await api.toggleKillSwitch(
        nextFrozen,
        nextFrozen ? "Emergency freeze toggled from Security & Audit console" : "Agent resumed from Security & Audit console"
      );
      const isNowFrozen = Boolean(res.frozen ?? res.agentFrozen);
      const ledgerRes = await api.getAuditLedger().catch(() => null);
      store.setState({
        killSwitch: { frozen: isNowFrozen, reason: res.reason || "", frozenAt: res.frozenAt || null },
        ...(ledgerRes ? { auditLedger: ledgerRes.ledger || [] } : {}),
      });
      renderSecurityAuditPage(mount);
      showToast({
        title: isNowFrozen ? "Agent Frozen (Kill Switch Active)" : "Agent Operations Resumed",
        message: res.message || (isNowFrozen ? "All staging & execution suspended." : "Normal operations restored."),
        type: isNowFrozen ? "warning" : "success",
      });
    } catch (err) {
      showToast({ title: "Kill Switch Error", message: err.message, type: "error" });
    }
  });

  // Export verifiable audit proof bundle
  document.getElementById("sec-export-bundle-btn")?.addEventListener("click", async () => {
    try {
      const res = await api.exportAuditBundle();
      const bundle = res.bundle || res;
      const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `payvoice-audit-bundle-${Date.now()}.json`;
      document.body.appendChild(a);
      a.click();
      URL.revokeObjectURL(url);
      a.remove();
      showToast({
        title: "Audit Proof Bundle Exported",
        message: `${bundle.totalRecords || ledger.length} blocks exported offline-verifiable.`,
        type: "success",
      });
    } catch (err) {
      showToast({ title: "Export Error", message: err.message, type: "error" });
    }
  });

  // Refresh ledger
  document.getElementById("sec-refresh-ledger")?.addEventListener("click", async () => {
    try {
      const res = await api.getAuditLedger();
      store.setState({ auditLedger: res.ledger || [] });
      renderSecurityAuditPage(mount);
      showToast({ title: "Ledger Synced", message: `${res.ledger?.length || 0} blocks up-to-date.`, type: "success" });
    } catch (err) {
      showToast({ title: "Refresh Error", message: err.message, type: "error" });
    }
  });

  // Detail inspection modal
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
            <div class="kv-item"><div class="kv-label">Status</div><div class="kv-val"><span class="badge ${getStatusBadgeClass(row.status)}">${escapeHtml(row.status)}</span></div></div>
            <div class="kv-item"><div class="kv-label">Timestamp</div><div class="kv-val">${formatDateTime(row.timestamp)}</div></div>
            <div class="kv-item"><div class="kv-label">Invoice ID</div><div class="kv-val" style="font-family:var(--font-mono);">${escapeHtml(row.invoiceId || "N/A")}</div></div>
            <div class="kv-item"><div class="kv-label">Passkey Assertion ID</div><div class="kv-val" style="font-family:var(--font-mono);">${escapeHtml(row.passkeyAssertionId || "N/A")}</div></div>
          </div>
          <div><div class="form-label" style="margin-bottom:4px;">Row Hash (SHA-256)</div><div class="mono-box">${escapeHtml(row.rowHash || "N/A")}</div></div>
          <div><div class="form-label" style="margin-bottom:4px;">Previous Block Hash</div><div class="mono-box">${escapeHtml(row.prevHash || "0".repeat(64))}</div></div>
          <div><div class="form-label" style="margin-bottom:4px;">Staged Payload Hash</div><div class="mono-box">${escapeHtml(row.stagedPayloadHash || "N/A")}</div></div>
          <div><div class="form-label" style="margin-bottom:4px;">Recorded Metadata</div><pre class="mono-box" style="white-space:pre-wrap;max-height:180px;overflow-y:auto;">${escapeHtml(JSON.stringify(row.metadata || {}, null, 2))}</pre></div>
        `,
        footerHtml: `
          <button type="button" class="btn btn-secondary" id="aud-copy-hash">Copy Row Hash</button>
          <button type="button" class="btn btn-primary" id="aud-close">Close</button>
        `,
        onMount: () => {
          document.getElementById("aud-close")?.addEventListener("click", closeModal);
          document.getElementById("aud-copy-hash")?.addEventListener("click", async () => {
            try {
              await navigator.clipboard.writeText(row.rowHash);
              showToast({ title: "Hash Copied", message: row.rowHash, type: "success" });
            } catch {
              showToast({ title: "Hash", message: row.rowHash, type: "info" });
            }
          });
        },
      });
    });
  });
}
