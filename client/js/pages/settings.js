/**
 * Page 9: Settings
 * Merchant regulatory profile (read-only from backend), language, theme,
 * voice/passkey preferences — strictly reflecting supported capabilities.
 */

import { store } from "../store.js";
import { setThemePreference, getResolvedTheme } from "../theme.js";
import { registerDevicePasskey } from "../passkey.js";
import { escapeHtml, truncateHash, showToast } from "../utils.js";

export function renderSettingsPage(mount) {
  const state = store.getState();
  const cfg = state.config || {};
  const reg = state.cfoInsights?.regulatoryCompliance || {};
  const hasWebAuthn = Boolean(window.PublicKeyCredential);

  mount.innerHTML = `
    <div class="page-header">
      <div class="page-header-copy">
        <h1>Settings</h1>
        <p>Configure language, appearance, voice read-back, and WebAuthn passkey enrollment</p>
      </div>
    </div>

    <div class="grid-2">
      <!-- Merchant & Backend Environment Profile -->
      <div class="card">
        <div class="card-header">
          <div>
            <h2 class="card-title">Merchant & Regulatory Profile</h2>
            <div class="card-subtitle">Synchronized from backend <code>/api/config</code> & OPGSP policy engine</div>
          </div>
          <span class="badge ${cfg.environment === "live" ? "badge-success" : "badge-warning"}">${escapeHtml((cfg.environment || "sandbox").toUpperCase())}</span>
        </div>

        <div class="kv-grid">
          <div class="kv-item">
            <div class="kv-label">Portal Corridor</div>
            <div class="kv-val">${escapeHtml(cfg.corridor || "India MSME Cross-Border Exporter Portal")}</div>
          </div>
          <div class="kv-item">
            <div class="kv-label">Agent Build</div>
            <div class="kv-val">${escapeHtml(cfg.agent || "PayVoice v1.0.0")}</div>
          </div>
          <div class="kv-item">
            <div class="kv-label">DGFT IEC Code</div>
            <div class="kv-val" style="font-family:var(--font-mono);">${escapeHtml(reg.iecCode || "0319088821")}</div>
          </div>
          <div class="kv-item">
            <div class="kv-label">PayPal OAuth Status</div>
            <div class="kv-val">${cfg.isConfigured ? "Live Sandbox Keys Configured" : "Local Sandbox Demo Mode"}</div>
          </div>
        </div>

        <p class="form-hint">
          Regulatory credentials (IEC, GST Rule 96A LUT, PayPal API keys) are governed by server-side environment variables and cannot be altered from the client browser.
        </p>
      </div>

      <!-- Theme & Language Preferences -->
      <div class="card">
        <div class="card-header">
          <h2 class="card-title">Appearance & Language</h2>
          <span class="badge badge-info">Saved Locally</span>
        </div>

        <div class="form-group">
          <label class="form-label" for="set-theme">Color Theme (Currently: ${escapeHtml(getResolvedTheme().toUpperCase())})</label>
          <select id="set-theme">
            <option value="system" ${state.theme === "system" ? "selected" : ""}>System Preference</option>
            <option value="light" ${state.theme === "light" ? "selected" : ""}>Light Mode</option>
            <option value="dark" ${state.theme === "dark" ? "selected" : ""}>Dark Mode</option>
          </select>
        </div>

        <div class="form-group">
          <label class="form-label" for="set-language">Default Voice & Read-Back Language</label>
          <select id="set-language">
            <option value="mr" ${state.language === "mr" ? "selected" : ""}>Marathi (मराठी)</option>
            <option value="hi" ${state.language === "hi" ? "selected" : ""}>Hindi (हिंदी)</option>
            <option value="en" ${state.language === "en" ? "selected" : ""}>English (US / UK)</option>
          </select>
        </div>
      </div>

      <!-- Voice & Authorization Behavior -->
      <div class="card">
        <div class="card-header">
          <h2 class="card-title">Voice & Sandbox Settlement Controls</h2>
        </div>

        <div class="switch-row">
          <div>
            <strong>Automatic Audible Read-Back</strong>
            <div class="form-hint">Automatically speak localized invoice summary when staged via Voice Assistant.</div>
          </div>
          <label class="switch">
            <input type="checkbox" id="set-autoread" ${state.autoReadBack ? "checked" : ""} aria-label="Automatic audible read-back" />
            <span class="switch-slider"></span>
          </label>
        </div>

        <hr style="border:none;border-top:1px solid var(--color-border-subtle);" />

        <div class="switch-row">
          <div>
            <strong>Sandbox Auto-Settle Demo Timer (5s)</strong>
            <div class="form-hint">Automatically transitions executed sandbox invoices from SENT to PAID after 5 seconds.</div>
          </div>
          <label class="switch">
            <input type="checkbox" id="set-autosettle" ${state.autoSettleDemo ? "checked" : ""} aria-label="Sandbox auto-settle timer" />
            <span class="switch-slider"></span>
          </label>
        </div>
      </div>

      <!-- Passkey & Security Management -->
      <div class="card">
        <div class="card-header">
          <h2 class="card-title">Passkey & WebAuthn Device</h2>
          <span class="badge ${hasWebAuthn ? "badge-success" : "badge-warning"}">${hasWebAuthn ? "FIDO2 Supported" : "WebCrypto Fallback"}</span>
        </div>

        <div class="kv-item">
          <div class="kv-label">Enrolled Credential ID</div>
          <div class="kv-val" style="font-family:var(--font-mono);font-size:12px;">
            ${state.passkeyEnrolledId ? escapeHtml(truncateHash(state.passkeyEnrolledId, 32)) : "Not yet enrolled in this browser session"}
          </div>
        </div>

        <div style="display:flex;gap:10px;flex-wrap:wrap;">
          <button type="button" class="btn btn-primary" id="set-enroll-pk">Enroll / Refresh Device Passkey</button>
        </div>
      </div>
    </div>
  `;

  document.getElementById("set-theme")?.addEventListener("change", (e) => {
    const resolved = setThemePreference(e.target.value);
    showToast({ title: "Theme Updated", message: `Active theme: ${resolved}`, type: "success" });
    renderSettingsPage(mount);
  });

  document.getElementById("set-language")?.addEventListener("change", (e) => {
    const lang = e.target.value;
    store.setState({ language: lang });
    const topSel = document.getElementById("topbar-lang-select");
    if (topSel) topSel.value = lang;
    showToast({ title: "Language Saved", message: `Voice & read-back set to ${lang.toUpperCase()}`, type: "success" });
  });

  document.getElementById("set-autoread")?.addEventListener("change", (e) => {
    store.setState({ autoReadBack: e.target.checked });
  });

  document.getElementById("set-autosettle")?.addEventListener("change", (e) => {
    store.setState({ autoSettleDemo: e.target.checked });
  });

  document.getElementById("set-enroll-pk")?.addEventListener("click", async () => {
    const btn = document.getElementById("set-enroll-pk");
    btn.disabled = true;
    btn.textContent = "Enrolling Passkey...";
    try {
      const res = await registerDevicePasskey();
      store.setState({ passkeyEnrolledId: res.credentialId });
      showToast({ title: "Passkey Active", message: res.message, type: "success" });
      renderSettingsPage(mount);
    } catch (err) {
      showToast({ title: "Enrollment Failed", message: err.message, type: "error" });
      btn.disabled = false;
      btn.textContent = "Enroll / Refresh Device Passkey";
    }
  });
}

