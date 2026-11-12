/**
 * PayVoice Invoice Preview, Deterministic Policy Review & Confirmation Modal
 * Allows inspection, permitted field editing (re-staged via backend), audible read-back,
 * and explicit merchant confirmation before opening the WebAuthn Passkey modal.
 */

import { api } from "../api.js";
import { store } from "../store.js";
import { openModal, closeModal, escapeHtml, speakReadBack, stopReadBack, showToast } from "../utils.js";
import { openPasskeyAuthModal } from "./passkeyModal.js";

export function openInvoicePreviewModal(stagedData, { onExecuted, onRestaged } = {}) {
  if (!stagedData || !stagedData.previewCard) return;

  let activeData = stagedData;
  let isEditing = false;

  const renderBody = () => {
    const card = activeData.previewCard || {};
    const payload = activeData.stagedPayload || {};
    const lang = store.getState().language || "en";
    const readBackText = activeData.readBackMessages?.[lang] || activeData.readBackMessages?.en || "";

    if (isEditing) {
      return `
        <div class="alert alert-info">
          <div class="alert-content">
            <span class="alert-title">Edit Staged Invoice Fields</span>
            <span>Changes will re-run deterministic Node.js Money Guide validation and issue a fresh WebAuthn challenge bound to the updated SHA-256 digest.</span>
          </div>
        </div>
        <form id="edit-staged-form" class="settings-section">
          <div class="grid-2" style="gap:12px;">
            <div class="form-group">
              <label class="form-label" for="edit-buyer-token">Buyer Token</label>
              <input id="edit-buyer-token" type="text" value="${escapeHtml(payload.buyerToken || card.buyerToken)}" readonly style="opacity:0.75;" />
              <span class="form-hint">Buyer identity is locked to the verified allowlist token.</span>
            </div>
            <div class="form-group">
              <label class="form-label" for="edit-currency">Export Currency</label>
              <select id="edit-currency">
                ${["USD", "EUR", "GBP", "AUD", "CAD", "SGD", "JPY", "CHF", "AED"]
                  .map((c) => `<option value="${c}" ${c === payload.currency ? "selected" : ""}>${c}</option>`)
                  .join("")}
              </select>
            </div>
          </div>
          <div class="grid-2" style="gap:12px;">
            <div class="form-group">
              <label class="form-label" for="edit-amount">Invoice Amount (Max $2,500 USD eq.)</label>
              <input id="edit-amount" type="number" step="0.01" min="0.01" value="${escapeHtml(payload.amount)}" required />
            </div>
            <div class="form-group">
              <label class="form-label" for="edit-quantity">Quantity / Milestone</label>
              <input id="edit-quantity" type="text" value="${escapeHtml(payload.quantity || "1 Milestone")}" required />
            </div>
          </div>
          <div class="form-group">
            <label class="form-label" for="edit-item">Service / Deliverable Description</label>
            <input id="edit-item" type="text" value="${escapeHtml(payload.item)}" required />
          </div>
          <div id="edit-stage-error"></div>
        </form>
      `;
    }

    return `
      <div class="invoice-sheet">
        <div class="invoice-sheet-head">
          <div>
            <span class="badge badge-warning" style="margin-bottom:6px;">Staged &bull; Awaiting Merchant Confirmation</span>
            <h3 style="font-size:1.15rem;">${escapeHtml(card.buyerDisplayName)}</h3>
            <p style="font-size:13px;">${escapeHtml(card.buyerToken)} &bull; ${escapeHtml(card.buyerCompany)} (${escapeHtml(card.buyerCountry)})</p>
          </div>
          <div class="invoice-total-amount">
            <div>${escapeHtml(card.amountFormatted)}</div>
            <div style="font-size:12px;color:var(--color-success);font-weight:600;">${escapeHtml(card.estInrFormatted)}</div>
          </div>
        </div>

        <div class="kv-grid">
          <div class="kv-item">
            <div class="kv-label">Service Deliverable</div>
            <div class="kv-val">${escapeHtml(card.item)}</div>
          </div>
          <div class="kv-item">
            <div class="kv-label">Quantity / Term</div>
            <div class="kv-val">${escapeHtml(card.quantity)} &bull; Net 15</div>
          </div>
        </div>

        <div class="policy-check-list">
          <div class="policy-check-row">
            <span><strong>Buyer Allowlist & Opaque Token</strong> (${escapeHtml(card.buyerToken)})</span>
            <span class="badge badge-success">PASS</span>
          </div>
          <div class="policy-check-row">
            <span><strong>OPGSP Single-Invoice Cap</strong> (&le; $2,500 USD equivalent)</span>
            <span class="badge badge-success">PASS</span>
          </div>
          <div class="policy-check-row">
            <span><strong>Foreign Export Currency & Duplicate Check</strong> (${escapeHtml(card.currency)})</span>
            <span class="badge badge-success">PASS</span>
          </div>
          <div class="policy-check-row">
            <span><strong>RBI Purpose Code & GST LUT</strong> (${escapeHtml(card.rbiPurposeCode)})</span>
            <span class="badge badge-purple">${escapeHtml(card.rbiPurposeCode)}</span>
          </div>
          ${
            card.levelLabel
              ? `
          <div class="policy-check-row">
            <span><strong>4-Tier Risk Assessment</strong> (Score ${Number(card.riskScore ?? 25)}/100${card.amountDeviationWarning ? ` &bull; ${escapeHtml(card.deviationRatio || ">2")}x baseline` : ""})</span>
            <span class="badge ${Number(card.riskScore ?? 25) > 75 ? "badge-error" : Number(card.riskScore ?? 25) > 30 ? "badge-warning" : "badge-success"}">${escapeHtml(card.levelLabel)}</span>
          </div>`
              : ""
          }
        </div>

        <div>
          <div class="form-label" style="margin-bottom:4px;">Audible Read-Back Summary (${escapeHtml(lang.toUpperCase())})</div>
          <div style="background:var(--color-surface);border:1px solid var(--color-border);border-radius:var(--radius-lg);padding:10px 12px;font-size:13px;display:flex;align-items:center;justify-content:space-between;gap:10px;">
            <span>"${escapeHtml(readBackText)}"</span>
            <div style="display:flex;gap:6px;flex-shrink:0;">
              <button type="button" class="btn btn-secondary btn-sm" id="preview-play-audio">Play</button>
              <button type="button" class="btn btn-ghost btn-sm" id="preview-stop-audio">Stop</button>
            </div>
          </div>
        </div>

        <div>
          <div class="form-label" style="margin-bottom:4px;">Payload SHA-256 Digest (Challenge-Bound)</div>
          <div class="mono-box">${escapeHtml(card.payloadHash)}</div>
        </div>
      </div>
    `;
  };

  const renderFooter = () => {
    if (isEditing) {
      return `
        <button type="button" class="btn btn-secondary" id="edit-cancel-btn">Back to Preview</button>
        <button type="button" class="btn btn-primary" id="edit-save-btn">Re-Validate & Stage</button>
      `;
    }
    return `
      <button type="button" class="btn btn-ghost" id="preview-cancel-btn">Cancel</button>
      <button type="button" class="btn btn-secondary" id="preview-edit-btn">Edit Details</button>
      <button type="button" class="btn btn-success" id="preview-confirm-btn">Confirm & Authorize Passkey</button>
    `;
  };

  openModal({
    title: "Invoice Preview & Explicit Confirmation",
    size: "lg",
    bodyHtml: renderBody(),
    footerHtml: renderFooter(),
    onMount: ({ bodyEl, footerEl }) => {
      const bindEvents = () => {
        if (isEditing) {
          document.getElementById("edit-cancel-btn")?.addEventListener("click", () => {
            isEditing = false;
            bodyEl.innerHTML = renderBody();
            footerEl.innerHTML = renderFooter();
            bindEvents();
          });
          document.getElementById("edit-save-btn")?.addEventListener("click", async () => {
            const btn = document.getElementById("edit-save-btn");
            const errBox = document.getElementById("edit-stage-error");
            const newAmount = Number(document.getElementById("edit-amount").value);
            const newCurrency = document.getElementById("edit-currency").value;
            const newQuantity = document.getElementById("edit-quantity").value.trim();
            const newItem = document.getElementById("edit-item").value.trim();

            btn.disabled = true;
            btn.textContent = "Validating...";
            errBox.innerHTML = "";

            try {
              const restaged = await api.stageInvoice({
                transcript: `Edited staged invoice: ${newItem} for ${newAmount} ${newCurrency}`,
                language: store.getState().language,
                intent: {
                  action: "create_invoice",
                  buyer_token: activeData.stagedPayload.buyerToken,
                  item: newItem,
                  amount: newAmount,
                  currency: newCurrency,
                  quantity: newQuantity,
                },
              });

              activeData = restaged;
              store.setState({ currentStaged: restaged });
              if (typeof onRestaged === "function") onRestaged(restaged);

              isEditing = false;
              bodyEl.innerHTML = renderBody();
              footerEl.innerHTML = renderFooter();
              bindEvents();
              showToast({ title: "Invoice Re-Validated", message: "Fresh WebAuthn challenge generated.", type: "success" });
            } catch (err) {
              btn.disabled = false;
              btn.textContent = "Re-Validate & Stage";
              errBox.innerHTML = `<div class="alert alert-error"><div class="alert-content"><span class="alert-title">${escapeHtml(err.code || "Policy Rejected")}</span><span>${escapeHtml(err.message)}</span></div></div>`;
            }
          });
          return;
        }

        document.getElementById("preview-play-audio")?.addEventListener("click", () => {
          const lang = store.getState().language || "en";
          const txt = activeData.readBackMessages?.[lang] || activeData.readBackMessages?.en;
          const res = speakReadBack(txt, lang);
          if (!res.supported) {
            showToast({ title: "Speech Synthesis Unavailable", message: "Browser does not support SpeechSynthesis playback.", type: "warning" });
          }
        });
        document.getElementById("preview-stop-audio")?.addEventListener("click", stopReadBack);
        document.getElementById("preview-cancel-btn")?.addEventListener("click", () => {
          stopReadBack();
          closeModal();
        });
        document.getElementById("preview-edit-btn")?.addEventListener("click", () => {
          stopReadBack();
          isEditing = true;
          bodyEl.innerHTML = renderBody();
          footerEl.innerHTML = renderFooter();
          bindEvents();
        });
        document.getElementById("preview-confirm-btn")?.addEventListener("click", () => {
          stopReadBack();
          closeModal();
          openPasskeyAuthModal(activeData, { onSuccess: onExecuted });
        });
      };

      bindEvents();
    },
    onClose: stopReadBack,
  });
}

