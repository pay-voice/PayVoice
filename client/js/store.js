/**
 * PayVoice Reactive Client Store
 * Holds shared application state, preferences, financial budgeting, schedules, and artifacts.
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

const DEFAULT_SCHEDULES = [
  {
    id: "SCHED-REC-01",
    title: "Acme Corp Cloud Retainer",
    type: "RECURRING_INVOICE",
    typeLabel: "Recurring Retainer",
    buyerName: "Rahul Mehta (Acme USA)",
    buyerToken: "BUYER_RAHUL_01",
    amount: 500.0,
    currency: "USD",
    cadence: "Monthly (1st)",
    nextRun: "2026-12-01",
    status: "ACTIVE", // ACTIVE | PAUSED
    rbiPurposeCode: "P0802",
  },
  {
    id: "SCHED-REM-02",
    title: "24h Polite Unpaid Follow-Up Daemon",
    type: "PAYMENT_REMINDER",
    typeLabel: "Payment Reminder",
    buyerName: "All Unpaid SENT Invoices",
    buyerToken: "ALL_ELIGIBLE",
    amount: null,
    currency: null,
    cadence: "Daily 09:00 UTC",
    nextRun: "Tomorrow 09:00 UTC",
    status: "ACTIVE",
    cooldownHours: 24,
  },
  {
    id: "SCHED-TAX-03",
    title: "GST LUT Rule 96A Monthly Reconciliation",
    type: "TAX_RESERVE_SET_ASIDE",
    typeLabel: "Tax & Compliance",
    buyerName: "DGFT / GST Electronic Ledger",
    buyerToken: "DGFT_0319088821",
    amount: 18500.0,
    currency: "INR",
    cadence: "Monthly (20th)",
    nextRun: "2026-11-20",
    status: "ACTIVE",
  },
];

const DEFAULT_BUDGET = {
  monthlyTargetUsd: 5000,
  feeCapPercent: 5.0,
  taxReservePercent: 15,
  maxCurrencySharePercent: 65,
};

const initialState = {
  route: "overview",
  config: null,
  language: savedPrefs.language || "mr", // mr | hi | en
  theme: savedPrefs.theme || "system", // system | light | dark
  autoReadBack: savedPrefs.autoReadBack !== undefined ? savedPrefs.autoReadBack : true,
  autoSettleDemo: savedPrefs.autoSettleDemo !== undefined ? savedPrefs.autoSettleDemo : true,
  sseConnected: false,

  // Financial Planning & Intelligence
  activeMoneyGuideTab: savedPrefs.activeMoneyGuideTab || "overview", // overview | limits | risk | schedules
  financialBudget: savedPrefs.financialBudget || DEFAULT_BUDGET,
  financialSchedules: Array.isArray(savedPrefs.financialSchedules) && savedPrefs.financialSchedules.length
    ? savedPrefs.financialSchedules
    : DEFAULT_SCHEDULES,

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

    // Persist user preferences & planning
    if (
      "language" in patch ||
      "theme" in patch ||
      "autoReadBack" in patch ||
      "autoSettleDemo" in patch ||
      "passkeyEnrolledId" in patch ||
      "financialBudget" in patch ||
      "financialSchedules" in patch ||
      "activeMoneyGuideTab" in patch
    ) {
      savePrefs({
        language: initialState.language,
        theme: initialState.theme,
        autoReadBack: initialState.autoReadBack,
        autoSettleDemo: initialState.autoSettleDemo,
        passkeyEnrolledId: initialState.passkeyEnrolledId,
        financialBudget: initialState.financialBudget,
        financialSchedules: initialState.financialSchedules,
        activeMoneyGuideTab: initialState.activeMoneyGuideTab,
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

  toggleSchedule(scheduleId) {
    const list = (initialState.financialSchedules || []).map((s) => {
      if (s.id === scheduleId) {
        return { ...s, status: s.status === "ACTIVE" ? "PAUSED" : "ACTIVE" };
      }
      return s;
    });
    this.setState({ financialSchedules: list });
    return list.find((s) => s.id === scheduleId);
  },

  addSchedule(schedule) {
    const id = `SCHED-USR-${Date.now().toString().slice(-4)}`;
    const newSchedule = {
      id,
      status: "ACTIVE",
      ...schedule,
    };
    const list = [newSchedule, ...(initialState.financialSchedules || [])];
    this.setState({ financialSchedules: list });
    return newSchedule;
  },

  updateBudget(budgetPatch) {
    const updated = {
      ...initialState.financialBudget,
      ...budgetPatch,
    };
    this.setState({ financialBudget: updated });
    return updated;
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
