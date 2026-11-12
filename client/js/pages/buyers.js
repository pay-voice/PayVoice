/**
 * Page 7: Buyers Vault Management
 * Manages allowlisted international buyers stored in the AES-256-GCM encrypted vault.
 * Displays opaque buyerTokens and masked emails — never exposes unnecessary PII.
 */

import { api } from "../api.js";
import { store } from "../store.js";
import { navigateTo } from "../router.js";
import { openInvoicePreviewModal } from "../components/invoicePreviewModal.js";
import {
  escapeHtml,
  formatCurrency,
  truncateHash,
  openModal,
  closeModal,
  showToast,
} from "../utils.js";

let searchQuery = "";
let currencyFilter = "ALL";

export function renderBuyersPage(mount) {
  const buyers = store.getState().buyers || [];
  const currencies = Array.from(new Set(buyers.map((b) => String(b.currency || "USD").toUpperCase())));

  const filtered = buyers.filter((b) => {
    const q = searchQuery.toLowerCase();
    const matchSearch =
      !q ||
      String(b.displayName).toLowerCase().includes(q) ||
      String(b.buyerToken).toLowerCase().includes(q) ||
      String(b.company || "").toLowerCase().includes(q) ||
      String(b.country || "").toLowerCase().includes(q);
    const matchCurr = currencyFilter === "ALL" || String(b.currency).toUpperCase() === currencyFilter;
    return matchSearch && matchCurr;
  });

  mount.innerHTML = `
    <div class="page-header">
      <div class="page-header-copy">
        <h1>Buyers Vault</h1>
        <p>AES-256-GCM tokenized allowlist — LLMs only see opaque <code>BUYER_*</code> identifiers</p>
      </div>
      <div class="page-header-actions">
        <button type="button" class="btn btn-secondary" id="buyers-sync-btn">Sync Vault</button>
        <button type="button" class="btn btn-primary" id="buyers-add-btn">Enroll New Buyer</button>
      </div>
    </div>

    <div class="card">
      <div class="toolbar">
        <div class="search-input-wrap">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>
          <input type="search" id="buyers-search" placeholder="Search buyer name, token, company, or country..." value="${escapeHtml(searchQuery)}" aria-label="Search buyers" />
        </div>
        <div class="toolbar-group">
          <select id="buyers-curr-filter" class="filter-select" aria-label="Filter buyers by currency">
            <option value="ALL">All Currencies</option>
            ${currencies.map((c) => `<option value="${c}" ${currencyFilter === c ? "selected" : ""}>${c}</option>`).join("")}
          </select>
          <span class="badge badge-success">${buyers.length} Allowlisted</span>
        </div>
      </div>

      ${
        filtered.length
          ? `
        <div class="buyers-grid">
          ${filtered
            .map(
              (b) => `
            <article class="buyer-card">
              <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:8px;">
                <div>
                  <h3 style="font-size:16px;">${escapeHtml(b.displayName)}</h3>
                  <div style="font-size:12px;color:var(--color-text-tertiary);">${escapeHtml(b.company || "International Client")}</div>
                </div>
                <span class="badge badge-info">${escapeHtml(b.country)} &bull; ${escapeHtml(b.currency)}</span>
              </div>

              <div class="kv-grid" style="gap:8px;">
                <div class="kv-item" style="padding:8px;">
                  <div class="kv-label">Opaque Token</div>
                  <div class="kv-val" style="font-family:var(--font-mono);font-size:12px;">${escapeHtml(b.buyerToken)}</div>
                </div>
                <div class="kv-item" style="padding:8px;">
                  <div class="kv-label">Masked Email</div>
                  <div class="kv-val" style="font-size:12px;">${escapeHtml(b.maskedEmail)}</div>
                </div>
              </div>

              <div style="font-size:12px;color:var(--color-text-secondary);">
                Default Contract: <strong>${escapeHtml(b.defaultItem || "Cloud API Development")}</strong> (${formatCurrency(b.defaultAmount || 200, b.currency)})
              </div>

              <div style="display:flex;gap:8px;margin-top:auto;">
                <button type="button" class="btn btn-secondary btn-sm" style="flex:1;" data-buyer-detail="${escapeHtml(b.buyerToken)}">Inspect</button>
                <button type="button" class="btn btn-primary btn-sm" style="flex:1;" data-buyer-bill="${escapeHtml(b.buyerToken)}">Quick Stage</button>
              </div>
            </article>`
            )
            .join("")}
        </div>`
          : `
        <div class="empty-state">
          <p>No allowlisted buyers match your search.</p>
        </div>`
      }
    </div>
  `;

  document.getElementById("buyers-search")?.addEventListener("input", (e) => {
    searchQuery = e.target.value;
    renderBuyersPage(mount);
  });
  document.getElementById("buyers-curr-filter")?.addEventListener("change", (e) => {
    currencyFilter = e.target.value;
    renderBuyersPage(mount);
  });
  document.getElementById("buyers-sync-btn")?.addEventListener("click", async () => {
    try {
      const res = await api.getBuyers();
      store.setState({ buyers: res.buyers || [] });
      renderBuyersPage(mount);
      showToast({ title: "Buyer Vault Synced", type: "success" });
    } catch (err) {
      showToast({ title: "Sync Error", message: err.message, type: "error" });
    }
  });
  document.getElementById("buyers-add-btn")?.addEventListener("click", () => openEnrollBuyerModal(mount));

  mount.querySelectorAll("[data-buyer-detail]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const token = btn.getAttribute("data-buyer-detail");
      const b = buyers.find((x) => x.buyerToken === token);
      if (!b) return;
      openModal({
        title: `Buyer Vault Record: ${b.buyerToken}`,
        bodyHtml: `
          <div class="kv-grid">
            <div class="kv-item"><div class="kv-label">Legal Name</div><div class="kv-val">${escapeHtml(b.displayName)}</div></div>
            <div class="kv-item"><div class="kv-label">Opaque Token</div><div class="kv-val" style="font-family:var(--font-mono);">${escapeHtml(b.buyerToken)}</div></div>
            <div class="kv-item"><div class="kv-label">Masked Email (PII Protected)</div><div class="kv-val">${escapeHtml(b.maskedEmail)}</div></div>
            <div class="kv-item"><div class="kv-label">Allowlist Cap</div><div class="kv-val">$${Number(b.maxLimit || 2500).toFixed(2)} USD</div></div>
            <div class="kv-item"><div class="kv-label">Country & Currency</div><div class="kv-val">${escapeHtml(b.country)} &bull; ${escapeHtml(b.currency)}</div></div>
            <div class="kv-item"><div class="kv-label">RBI Default Code</div><div class="kv-val">${escapeHtml(b.defaultPurposeCode || "P0802")}</div></div>
          </div>
          <div>
            <div class="form-label" style="margin-bottom:4px;">HMAC-SHA256 Blind Index (Privacy-Preserving Lookup)</div>
            <div class="mono-box">${escapeHtml(b.blindIndex || "—")}</div>
          </div>
        `,
        footerHtml: `<button type="button" class="btn btn-primary" id="bd-close">Close</button>`,
        onMount: () => document.getElementById("bd-close")?.addEventListener("click", closeModal),
      });
    });
  });

  mount.querySelectorAll("[data-buyer-bill]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const token = btn.getAttribute("data-buyer-bill");
      const b = buyers.find((x) => x.buyerToken === token);
      if (!b) return;
      btn.disabled = true;
      btn.textContent = "Staging...";
      try {
        const staged = await api.stageInvoice({
          transcript: `Bill ${b.displayName} ${b.defaultAmount || 200} ${b.currency} for ${b.defaultItem || "Cloud API Development"}`,
          language: store.getState().language,
          intent: {
            action: "create_invoice",
            buyer_token: b.buyerToken,
            item: b.defaultItem || "Cloud API Development",
            amount: b.defaultAmount || 200,
            currency: b.currency || "USD",
            quantity: b.defaultQuantity || "1 Milestone",
          },
        });
        store.setState({ currentStaged: staged });
        openInvoicePreviewModal(staged, {
          onExecuted: () => navigateTo("invoices"),
        });
      } catch (err) {
        showToast({ title: "Staging Blocked", message: err.message, type: "error" });
      } finally {
        btn.disabled = false;
        btn.textContent = "Quick Stage";
      }
    });
  });
}

function openEnrollBuyerModal(mount) {
  openModal({
    title: "Enroll Overseas Buyer in Encrypted Vault",
    bodyHtml: `
      <div class="alert alert-info">
        <div class="alert-content">
          <span class="alert-title">AES-256-GCM + HMAC Blind Index</span>
          <span>Buyer email addresses are encrypted at rest and assigned an opaque <code>BUYER_*</code> token so raw PII never enters LLM prompts.</span>
        </div>
      </div>
      <form id="enroll-buyer-form" class="settings-section">
        <div class="grid-2" style="gap:12px;">
          <div class="form-group">
            <label class="form-label" for="eb-name">Buyer Full Name</label>
            <input id="eb-name" type="text" placeholder="e.g., Priya Nair" required />
          </div>
          <div class="form-group">
            <label class="form-label" for="eb-email">Overseas PayPal Email</label>
            <input id="eb-email" type="email" placeholder="buyer@company.com" required />
          </div>
        </div>
        <div class="grid-3" style="gap:12px;">
          <div class="form-group">
            <label class="form-label" for="eb-country">Country Code</label>
            <input id="eb-country" type="text" value="US" maxlength="2" required />
          </div>
          <div class="form-group">
            <label class="form-label" for="eb-currency">Preferred Currency</label>
            <select id="eb-currency">
              <option value="USD">USD</option>
              <option value="EUR">EUR</option>
              <option value="GBP">GBP</option>
              <option value="AUD">AUD</option>
              <option value="CAD">CAD</option>
              <option value="SGD">SGD</option>
            </select>
          </div>
          <div class="form-group">
            <label class="form-label" for="eb-limit">Max Invoice Cap (USD)</label>
            <input id="eb-limit" type="number" min="1" max="2500" value="2500" required />
          </div>
        </div>
        <div id="eb-error"></div>
      </form>
    `,
    footerHtml: `
      <button type="button" class="btn btn-secondary" id="eb-cancel">Cancel</button>
      <button type="button" class="btn btn-primary" id="eb-submit">Encrypt & Enroll Buyer</button>
    `,
    onMount: () => {
      document.getElementById("eb-cancel")?.addEventListener("click", closeModal);
      document.getElementById("eb-submit")?.addEventListener("click", async () => {
        const btn = document.getElementById("eb-submit");
        const errBox = document.getElementById("eb-error");
        const name = document.getElementById("eb-name").value.trim();
        const email = document.getElementById("eb-email").value.trim();
        const country = document.getElementById("eb-country").value.trim().toUpperCase();
        const currency = document.getElementById("eb-currency").value;
        const maxLimit = Number(document.getElementById("eb-limit").value);

        if (!name || !email) {
          errBox.innerHTML = `<div class="alert alert-error"><div class="alert-content"><span>Name and email are required.</span></div></div>`;
          return;
        }

        btn.disabled = true;
        btn.textContent = "Encrypting...";
        errBox.innerHTML = "";

        try {
          await api.registerBuyer({ name, email, country, currency, maxLimit });
          const listRes = await api.getBuyers();
          store.setState({ buyers: listRes.buyers || [] });
          closeModal();
          renderBuyersPage(mount);
          showToast({ title: "Buyer Enrolled", message: `${name} added to AES-256-GCM allowlist.`, type: "success" });
        } catch (err) {
          btn.disabled = false;
          btn.textContent = "Encrypt & Enroll Buyer";
          errBox.innerHTML = `<div class="alert alert-error"><div class="alert-content"><span>${escapeHtml(err.message)}</span></div></div>`;
        }
      });
    },
  });
}

