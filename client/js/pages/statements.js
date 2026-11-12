/**
 * Page 6: Encrypted Statements
 * Generates AES-256 password-protected CA/GST accounting PDF statements via POST /api/statements/pdf.
 * Never exposes encryption passwords in URLs or logs.
 */

import { api } from "../api.js";
import { store } from "../store.js";
import { escapeHtml, formatDateTime, truncateHash, showToast } from "../utils.js";

let isGenerating = false;
let lastError = "";
let lastGenerated = null;

export function renderStatementsPage(mount) {
  const state = store.getState();
  const history = state.generatedStatements || [];

  mount.innerHTML = `
    <div class="page-header">
      <div class="page-header-copy">
        <h1>Encrypted Statements</h1>
        <p>Generate password-locked CA/GST Rule 96A PDF accounting statements with embedded Merkle audit roots</p>
      </div>
    </div>

    <div class="grid-12-7-5">
      <div class="card">
        <div class="card-header">
          <div>
            <h2 class="card-title">Generate Encrypted Statement</h2>
            <div class="card-subtitle">PDFKit AES-256 document encryption & deterministic line-item parity verification</div>
          </div>
          <span class="badge badge-purple">CA / GST Rule 96A</span>
        </div>

        <form id="stmt-form" class="settings-section">
          <div class="grid-2" style="gap:14px;">
            <div class="form-group">
              <label class="form-label" for="stmt-range">Statement Period</label>
              <select id="stmt-range">
                <option value="Last 30 Days">Last 30 Days</option>
                <option value="Last 7 Days">Last 7 Days</option>
                <option value="Last 90 Days">Last 90 Days (Quarter)</option>
                <option value="October 2026">October 2026</option>
                <option value="November 2026">November 2026</option>
                <option value="This Year">Year to Date (2026)</option>
              </select>
            </div>

            <div class="form-group">
              <label class="form-label" for="stmt-custom-query">Or Spoken / Custom Period Query</label>
              <input id="stmt-custom-query" type="text" placeholder="e.g., last 7 days, October 2026, quarter" />
            </div>
          </div>

          <div class="form-group">
            <label class="form-label" for="stmt-password">PDF Unlock Password / PIN</label>
            <div style="display:flex;gap:8px;">
              <input id="stmt-password" type="password" value="PAYVOICE2026" autocomplete="new-password" required style="flex:1;" />
              <button type="button" class="btn btn-secondary" id="stmt-toggle-pw" aria-label="Toggle password visibility">Show</button>
            </div>
            <span class="form-hint">Sent exclusively inside the encrypted POST request body — never placed in URLs or browser logs.</span>
          </div>

          ${
            lastError
              ? `<div class="alert alert-error" role="alert"><div class="alert-content"><span class="alert-title">Generation Failed</span><span>${escapeHtml(lastError)}</span></div></div>`
              : ""
          }

          ${
            lastGenerated
              ? `
            <div class="alert alert-success" role="status">
              <div class="alert-content">
                <span class="alert-title">Encrypted PDF Downloaded: ${escapeHtml(lastGenerated.filename)}</span>
                <div class="text-xs-mono" style="margin-block-start:0.25rem;">
                  <div>SHA-256: ${escapeHtml(truncateHash(lastGenerated.checksum, 32))}</div>
                  <div>Audit Root: ${escapeHtml(truncateHash(lastGenerated.auditRoot, 32))}</div>
                  <div>Records Reconciled: ${lastGenerated.records} &bull; Generated: ${formatDateTime(lastGenerated.generatedAt)}</div>
                </div>
              </div>
            </div>`
              : ""
          }

          <div style="display:flex;justify-content:flex-end;">
            <button type="submit" class="btn btn-navy btn-lg" id="stmt-submit-btn" ${isGenerating ? "disabled" : ""}>
              ${isGenerating ? `<span class="spinner"></span> Encrypting & Downloading...` : "Generate & Download Encrypted PDF"}
            </button>
          </div>
        </form>
      </div>

      <div style="display:flex;flex-direction:column;gap:20px;">
        <div class="card">
          <div class="card-header">
            <h2 class="card-title">Security & Compliance Properties</h2>
            <span class="badge badge-success">AES-256</span>
          </div>
          <div class="policy-check-list">
            <div class="policy-check-row">
              <span><strong>PDF Password Lock</strong></span>
              <span class="badge badge-info">User + Owner Key</span>
            </div>
            <div class="policy-check-row">
              <span><strong>Mathematical Parity Check</strong></span>
              <span class="badge badge-success">Node.js Reconciled</span>
            </div>
            <div class="policy-check-row">
              <span><strong>Tamper-Evident Footer</strong></span>
              <span class="badge badge-purple">SHA-256 + HMAC</span>
            </div>
            <div class="policy-check-row">
              <span><strong>Print / Modify Restrictions</strong></span>
              <span class="badge badge-neutral">Read-Only Export</span>
            </div>
          </div>
          <p class="text-sm text-muted">
            Every statement export is cryptographically recorded in the PayVoice Audit Ledger with its SHA-256 file checksum and active chain root hash.
          </p>
        </div>

        <div class="card">
          <div class="card-header">
            <h2 class="card-title">Session Export History</h2>
            <span class="badge badge-neutral">${history.length} File(s)</span>
          </div>
          ${
            history.length
              ? `
            <div style="display:flex;flex-direction:column;gap:8px;">
              ${history
                .map(
                  (item) => `
                <div class="policy-check-row" style="flex-direction:column;align-items:flex-start;gap:4px;">
                  <div style="display:flex;justify-content:space-between;width:100%;align-items:center;gap:8px;flex-wrap:wrap;">
                    <strong style="overflow-wrap:anywhere;">${escapeHtml(item.filename)}</strong>
                    <span class="badge badge-success">${escapeHtml(item.dateRange)}</span>
                  </div>
                  <div class="text-2xs-mono text-muted">
                    SHA-256: ${escapeHtml(truncateHash(item.checksum, 24))} &bull; ${item.records} records
                  </div>
                </div>`
                )
                .join("")}
            </div>`
              : `<div class="empty-state" style="padding:20px;"><p>No statements exported in this session yet.</p></div>`
          }
        </div>
      </div>
    </div>
  `;

  document.getElementById("stmt-toggle-pw")?.addEventListener("click", (e) => {
    const pwInput = document.getElementById("stmt-password");
    if (!pwInput) return;
    const isPw = pwInput.type === "password";
    pwInput.type = isPw ? "text" : "password";
    e.currentTarget.textContent = isPw ? "Hide" : "Show";
  });

  document.getElementById("stmt-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const custom = document.getElementById("stmt-custom-query")?.value.trim();
    const dateRange = custom || document.getElementById("stmt-range")?.value || "Last 30 Days";
    const password = document.getElementById("stmt-password")?.value || "PAYVOICE2026";

    isGenerating = true;
    lastError = "";
    renderStatementsPage(mount);

    try {
      const result = await api.generateStatementPdf({ dateRange, password });

      // Trigger download
      const url = URL.createObjectURL(result.blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = result.filename;
      document.body.appendChild(a);
      a.click();
      URL.revokeObjectURL(url);
      a.remove();

      lastGenerated = { ...result, dateRange };
      const prev = store.getState().generatedStatements || [];
      store.setState({
        generatedStatements: [lastGenerated, ...prev],
      });

      // Refresh audit ledger since backend logs STATEMENT_EXPORTED
      api.getAuditLedger().then((res) => store.setState({ auditLedger: res.ledger || [] })).catch(() => {});

      store.addNotification({
        title: "Encrypted Statement Generated",
        message: `${result.filename} (${result.records} records) exported with SHA-256 verification.`,
        severity: "success",
      });
      showToast({ title: "Encrypted PDF Ready", message: `Downloaded ${result.filename}`, type: "success" });
    } catch (err) {
      lastError = err.message || "Failed to generate encrypted PDF statement.";
      showToast({ title: "Export Blocked", message: lastError, type: "error" });
    } finally {
      isGenerating = false;
      renderStatementsPage(mount);
    }
  });
}

