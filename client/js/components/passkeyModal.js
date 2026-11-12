/**
 * PayVoice WebAuthn Step-Up Passkey Modal Component
 * Enforces explicit hardware/WebCrypto authorization tied to SHA-256(stagedPayload).
 * Never displays success before backend verification completes.
 */

import { api } from "../api.js";
import { store } from "../store.js";
import { signStagedInvoiceWithPasskey, registerDevicePasskey } from "../passkey.js";
import { openModal, closeModal, escapeHtml, truncateHash, showToast } from "../utils.js";

export function openPasskeyAuthModal(stagedData, { onSuccess, onCancel } = {}) {
  if (!stagedData || !stagedData.webauthn) {
    showToast({ title: "No Staged Invoice", message: "Stage an invoice before requesting passkey verification.", type: "warning" });
    return;
  }

  const { stageId, previewCard, webauthn } = stagedData;
  const hasWebAuthn = Boolean(window.PublicKeyCredential && navigator.credentials?.get);
  let timerInterval = null;
  let completed = false;

  const renderBody = (status = "ready", message = "") => {
    const remainingSec = Math.max(0, Math.floor((webauthn.expiresAt - Date.now()) / 1000));
    const mins = String(Math.floor(remainingSec / 60)).padStart(2, "0");
    const secs = String(remainingSec % 60).padStart(2, "0");
    const expired = remainingSec <= 0;

    let iconClass = "passkey-icon-ring";
    let heading = "Verify Biometric Passkey";
    let subtext = "Authorize this staged cross-border invoice with your FIDO2 device passkey (TouchID, Windows Hello, or hardware key).";

    if (status === "authenticating") {
      heading = "Waiting for Device Authenticator...";
      subtext = "Complete the biometric or device PIN prompt from your browser/OS.";
    } else if (status === "verifying_backend") {
      heading = "Verifying Signature & Dispatching...";
      subtext = "Backend is verifying the challenge-bound assertion and executing via PayPal Sandbox.";
    } else if (status === "success") {
      iconClass = "passkey-icon-ring success";
      heading = "Passkey Verified & Invoice Sent";
      subtext = message || "Cryptographic assertion verified by backend.";
    } else if (status === "error" || expired) {
      iconClass = "passkey-icon-ring error";
      heading = expired ? "Challenge Expired (2-Min TTL)" : "Passkey Authorization Failed";
      subtext = expired ? "The single-use WebAuthn challenge expired. Re-stage the invoice to issue a fresh challenge." : message;
    }

    return `
      <div class="passkey-hero-box">
        <div class="${iconClass}">
          <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <path d="m9 12 2 2 4-4"/>
          </svg>
        </div>
        <div>
          <h3 style="font-size:1.1rem;">${escapeHtml(heading)}</h3>
          <p class="section-desc" style="margin-block-start:0.25rem;">${escapeHtml(subtext)}</p>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;justify-content:center;">
          <span class="badge ${hasWebAuthn ? "badge-info" : "badge-warning"}">
            ${hasWebAuthn ? "WebAuthn FIDO2 Available (with WebCrypto P-256 fallback)" : "WebAuthn Unavailable — Using WebCrypto ECDSA P-256 Fallback"}
          </span>
          <span class="badge ${expired ? "badge-error" : "badge-neutral"}" id="pk-ttl-badge">
            Challenge TTL: <span id="pk-ttl-val" class="tabular-nums">${mins}:${secs}</span>
          </span>
        </div>
      </div>

      <div class="kv-grid">
        <div class="kv-item">
          <div class="kv-label">Buyer & Amount</div>
          <div class="kv-val">${escapeHtml(previewCard?.buyerDisplayName || "")} &bull; ${escapeHtml(previewCard?.amountFormatted || "")}</div>
        </div>
        <div class="kv-item">
          <div class="kv-label">Challenge ID</div>
          <div class="kv-val text-xs-mono">${escapeHtml(webauthn.challengeId)}</div>
        </div>
      </div>

      <div>
        <div class="form-label" style="margin-bottom:4px;">Bound Payload SHA-256 Digest</div>
        <div class="mono-box">${escapeHtml(webauthn.payloadHash)}</div>
      </div>

      ${
        status === "error"
          ? `<div class="alert alert-error"><div class="alert-content"><span class="alert-title">Authorization Rejected</span><span>${escapeHtml(message)}</span></div></div>`
          : ""
      }
      ${
        !hasWebAuthn
          ? `<div class="alert alert-info"><div class="alert-content"><span class="alert-title">Environment Note</span><span>This browser context will sign the challenge using hardware-backed WebCrypto ECDSA P-256 fallback and submit it for backend verification.</span></div></div>`
          : ""
      }
    `;
  };

  const renderFooter = (status = "ready") => {
    const expired = Date.now() >= webauthn.expiresAt;
    if (status === "success") {
      return `<button type="button" class="btn btn-primary" id="pk-done-btn">Done</button>`;
    }
    const busy = status === "authenticating" || status === "verifying_backend";
    return `
      <button type="button" class="btn btn-ghost" id="pk-enroll-btn" ${busy ? "disabled" : ""}>Enroll Device Passkey</button>
      <button type="button" class="btn btn-secondary" id="pk-cancel-btn" ${busy ? "disabled" : ""}>Cancel</button>
      <button type="button" class="btn btn-success" id="pk-verify-btn" ${busy || expired ? "disabled" : ""}>
        ${busy ? `<span class="spinner" aria-hidden="true"></span> Processing...` : status === "error" ? "Retry Passkey Verification" : "Verify & Authorize Invoice"}
      </button>
    `;
  };

  openModal({
    title: "Step-Up WebAuthn Passkey Authorization",
    bodyHtml: renderBody("ready"),
    footerHtml: renderFooter("ready"),
    onMount: ({ bodyEl, footerEl }) => {
      const updateView = (status, msg = "") => {
        bodyEl.innerHTML = renderBody(status, msg);
        footerEl.innerHTML = renderFooter(status);
        wireFooterEvents();
      };

      const startTimer = () => {
        if (timerInterval) clearInterval(timerInterval);
        timerInterval = setInterval(() => {
          const remaining = Math.max(0, Math.floor((webauthn.expiresAt - Date.now()) / 1000));
          const ttlEl = document.getElementById("pk-ttl-val");
          const badgeEl = document.getElementById("pk-ttl-badge");
          if (ttlEl) {
            const m = String(Math.floor(remaining / 60)).padStart(2, "0");
            const s = String(remaining % 60).padStart(2, "0");
            ttlEl.textContent = `${m}:${s}`;
          }
          if (remaining <= 0) {
            clearInterval(timerInterval);
            if (!completed) {
              if (badgeEl) badgeEl.className = "badge badge-error";
              updateView("error", "WebAuthn challenge expired (2-minute limit). Please re-stage the invoice.");
            }
          }
        }, 1000);
      };

      const handleAuthorize = async () => {
        if (Date.now() >= webauthn.expiresAt) {
          updateView("error", "Challenge expired. Re-stage the invoice to continue.");
          return;
        }
        try {
          updateView("authenticating");
          const assertion = await signStagedInvoiceWithPasskey({
            challengeId: webauthn.challengeId,
            challenge: webauthn.challenge,
            payloadHash: webauthn.payloadHash,
          });

          updateView("verifying_backend");
          const autoSettleSeconds = store.getState().autoSettleDemo ? 5 : 0;
          const result = await api.executeInvoice({
            stageId,
            challengeId: webauthn.challengeId,
            assertion,
            expectedPayloadHash: webauthn.payloadHash,
            autoSettleSeconds,
          });

          completed = true;
          clearInterval(timerInterval);

          // Update store with newly executed invoice
          const currentInvoices = store.getState().invoices || [];
          if (result.invoiceRecord) {
            store.setState({
              invoices: [result.invoiceRecord, ...currentInvoices.filter((i) => i.invoiceId !== result.invoiceId)],
              currentStaged: null,
            });
          }

          store.addNotification({
            title: "Invoice Dispatched to PayPal",
            message: `${result.invoiceId} (${previewCard?.amountFormatted}) verified by passkey ${truncateHash(result.assertionId, 16)}.`,
            severity: "success",
          });

          updateView(
            "success",
            `Invoice ${result.invoiceId} dispatched via PayPal Sandbox (${result.status}). Assertion ID: ${result.assertionId}`
          );

          showToast({
            title: "Invoice Authorized & Sent",
            message: `${result.invoiceId} transitioned DRAFT → SENT.`,
            type: "success",
          });

          if (typeof onSuccess === "function") {
            onSuccess(result);
          }
        } catch (err) {
          updateView("error", err.message || "Passkey verification failed on backend.");
          showToast({
            title: "Authorization Blocked",
            message: err.message,
            type: "error",
          });
        }
      };

      const wireFooterEvents = () => {
        const verifyBtn = document.getElementById("pk-verify-btn");
        const cancelBtn = document.getElementById("pk-cancel-btn");
        const enrollBtn = document.getElementById("pk-enroll-btn");
        const doneBtn = document.getElementById("pk-done-btn");

        if (verifyBtn) verifyBtn.addEventListener("click", handleAuthorize);
        if (cancelBtn) {
          cancelBtn.addEventListener("click", () => {
            closeModal();
            if (typeof onCancel === "function") onCancel();
          });
        }
        if (doneBtn) doneBtn.addEventListener("click", closeModal);
        if (enrollBtn) {
          enrollBtn.addEventListener("click", async () => {
            enrollBtn.disabled = true;
            enrollBtn.textContent = "Enrolling...";
            try {
              const res = await registerDevicePasskey();
              store.setState({ passkeyEnrolledId: res.credentialId });
              showToast({
                title: "Device Passkey Enrolled",
                message: `Credential ${truncateHash(res.credentialId, 18)} active.`,
                type: "success",
              });
              enrollBtn.textContent = "Passkey Enrolled ✓";
            } catch (err) {
              showToast({ title: "Enrollment Failed", message: err.message, type: "error" });
              enrollBtn.disabled = false;
              enrollBtn.textContent = "Enroll Device Passkey";
            }
          });
        }
      };

      startTimer();
      wireFooterEvents();
    },
    onClose: () => {
      if (timerInterval) clearInterval(timerInterval);
    },
  });
}

