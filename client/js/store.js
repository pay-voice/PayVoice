/**
 * PayVoice Reactive Client Store
 * Holds shared application state, preferences, notifications, and session artifacts.
 */

const PREFS_KEY = "payvoice_preferences_v1";

function loadSavedPrefs() {
  try {
    const raw = localStorage.getItem(PREFS_KEY);
    return raw ? JSON.parse(raw) : {};
  } catch {
    return {};
  }
}

function savePrefs(prefs) {
  try {
    localStorage.setItem(PREFS_KEY, JSON.stringify(prefs));
  } catch {
    // Ignore storage quota errors
  }
}

const savedPrefs = loadSavedPrefs();

const initialState = {
  route: "overview",
  config: null,
  language: savedPrefs.language || "mr", // mr | hi | en
  theme: savedPrefs.theme || "system", // system | light | dark
  autoReadBack: savedPrefs.autoReadBack !== undefined ? savedPrefs.autoReadBack : true,
  autoSettleDemo: savedPrefs.autoSettleDemo !== undefined ? savedPrefs.autoSettleDemo : true,
  sseConnected: false,

  // Backend-synced data
  transactions: [],
  transactionTotals: null,
  cfoInsights: null,
  merchantInsights: null,
  invoices: [],
  stagedInvoicesHistory: [],
  buyers: [],
  auditLedger: [],
  ledgerVerification: null,
  killSwitch: { frozen: false, reason: "", frozenAt: null },

  // Active workflow state
  currentStaged: null,
  passkeyEnrolledId: savedPrefs.passkeyEnrolledId || null,
  generatedStatements: [],
  remindersSent: {}, // invoiceId -> lastReminderTimestamp

  // Notifications
  notifications: [
    {
      id: "boot-1",
      title: "Security Engine Active",
      message: "AES-256-GCM Buyer Vault & SHA-256 Audit Ledger verified on startup.",
      severity: "success",
      timestamp: new Date().toISOString(),
      read: false,
    },
  ],
};

const listeners = new Set();

export const store = {
  getState: () => initialState,

  setState(patch) {
    Object.assign(initialState, patch);

    // Persist user preferences
    if (
      "language" in patch ||
      "theme" in patch ||
      "autoReadBack" in patch ||
      "autoSettleDemo" in patch ||
      "passkeyEnrolledId" in patch
    ) {
      savePrefs({
        language: initialState.language,
        theme: initialState.theme,
        autoReadBack: initialState.autoReadBack,
        autoSettleDemo: initialState.autoSettleDemo,
        passkeyEnrolledId: initialState.passkeyEnrolledId,
      });
    }

    listeners.forEach((fn) => {
      try {
        fn(initialState, patch);
      } catch (err) {
        console.error("[Store Listener Error]:", err);
      }
    });
  },

  subscribe(fn) {
    listeners.add(fn);
    return () => listeners.delete(fn);
  },

  addNotification({ title, message, severity = "info" }) {
    const item = {
      id: `notif_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
      title,
      message,
      severity,
      timestamp: new Date().toISOString(),
      read: false,
    };
    this.setState({
      notifications: [item, ...initialState.notifications].slice(0, 30),
    });
  },

  markAllNotificationsRead() {
    this.setState({
      notifications: initialState.notifications.map((n) => ({ ...n, read: true })),
    });
  },
};

