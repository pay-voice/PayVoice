/**
 * PayVoice Hash-Based SPA Router
 * Manages all 9 application sections, breadcrumbs, document title, and focus.
 */

import { store } from "./store.js";

export const ROUTES = {
  overview: {
    id: "overview",
    title: "Overview",
    subtitle: "Cross-border export command center & real-time telemetry",
    group: "Workspace",
  },
  voice: {
    id: "voice",
    title: "Voice Assistant",
    subtitle: "Multilingual speech intent capture in Marathi, Hindi & English",
    group: "Workspace",
  },
  invoices: {
    id: "invoices",
    title: "Invoices",
    subtitle: "Staged previews, lifecycle tracking & PayPal Sandbox execution",
    group: "Operations",
  },
  transactions: {
    id: "transactions",
    title: "Transactions",
    subtitle: "Cross-border settlements, fees & buyer reconciliation",
    group: "Operations",
  },
  "money-guide": {
    id: "money-guide",
    title: "Money Guide AI",
    subtitle: "Deterministic CFO analytics, OPGSP limits & anomaly alerts",
    group: "Intelligence",
  },
  statements: {
    id: "statements",
    title: "Statements",
    subtitle: "AES-256 encrypted CA/GST Rule 96A accounting PDF exports",
    group: "Intelligence",
  },
  buyers: {
    id: "buyers",
    title: "Buyers",
    subtitle: "AES-256-GCM tokenized allowlist vault & opaque client registry",
    group: "Compliance",
  },
  security: {
    id: "security",
    title: "Security & Audit",
    subtitle: "WebAuthn passkey controls, guardrail firewall & SHA-256 hash ledger",
    group: "Compliance",
  },
  settings: {
    id: "settings",
    title: "Settings",
    subtitle: "Merchant profile, language, theme & authorization preferences",
    group: "System",
  },
};

const pageRenderers = new Map();

export function registerPage(routeId, renderFn) {
  pageRenderers.set(routeId, renderFn);
}

export function navigateTo(routeId) {
  const target = ROUTES[routeId] ? routeId : "overview";
  if (window.location.hash !== `#${target}`) {
    window.location.hash = `#${target}`;
  } else {
    renderCurrentRoute();
  }
}

export function getRouteFromHash() {
  const raw = (window.location.hash || "#overview").replace(/^#\/?/, "").trim();
  return ROUTES[raw] ? raw : "overview";
}

export function renderCurrentRoute() {
  const routeId = getRouteFromHash();
  const routeMeta = ROUTES[routeId];
  store.setState({ route: routeId });

  // Update active nav item
  document.querySelectorAll(".nav-item[data-route]").forEach((btn) => {
    const active = btn.getAttribute("data-route") === routeId;
    btn.classList.toggle("active", active);
    if (active) {
      btn.setAttribute("aria-current", "page");
    } else {
      btn.removeAttribute("aria-current");
    }
  });

  // Update breadcrumbs & title
  const crumbEl = document.getElementById("breadcrumb-current");
  if (crumbEl) crumbEl.textContent = routeMeta.title;
  document.title = `${routeMeta.title} — PayVoice`;

  // Render view
  const mount = document.getElementById("page-mount");
  if (!mount) return;

  const renderer = pageRenderers.get(routeId);
  if (renderer) {
    renderer(mount, routeMeta);
  }

  // Close mobile sidebar drawer if open
  const sidebar = document.getElementById("sidebar");
  const backdrop = document.getElementById("sidebar-backdrop");
  if (sidebar) sidebar.classList.remove("open");
  if (backdrop) backdrop.classList.remove("open");

  // Scroll to top smoothly
  window.scrollTo({ top: 0, behavior: "auto" });
}

export function initRouter() {
  window.addEventListener("hashchange", renderCurrentRoute);
  renderCurrentRoute();
}

