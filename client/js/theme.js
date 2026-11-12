/**
 * PayVoice Theme Manager
 * Supports Light, Dark, and System preference with instant DOM and <meta name="color-scheme"> updates.
 */

import { store } from "./store.js";

const PREFS_STORAGE_KEY = "payvoice_preferences_v1";
const mediaQuery = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;

export function getResolvedTheme(pref = store.getState().theme) {
  if (pref === "light" || pref === "dark") return pref;
  return mediaQuery && mediaQuery.matches ? "dark" : "light";
}

export function applyTheme(pref = store.getState().theme) {
  const normalized = pref === "light" || pref === "dark" ? pref : "system";
  const resolved = getResolvedTheme(normalized);
  const meta = document.querySelector('meta[name="color-scheme"]');
  if (meta) {
    meta.setAttribute("content", normalized === "system" ? "light dark" : normalized);
  }
  if (normalized === "system") {
    document.documentElement.removeAttribute("data-theme");
  } else {
    document.documentElement.setAttribute("data-theme", resolved);
  }
  return resolved;
}

export function setThemePreference(pref) {
  store.setState({ theme: pref });
  return applyTheme(pref);
}

export function toggleTheme() {
  const current = getResolvedTheme();
  const next = current === "dark" ? "light" : "dark";
  return setThemePreference(next);
}

export function initTheme() {
  applyTheme(store.getState().theme);
  if (mediaQuery) {
    mediaQuery.addEventListener("change", () => {
      if (store.getState().theme === "system") {
        applyTheme("system");
      }
    });
  }
  window.addEventListener("storage", (event) => {
    if (event.key !== PREFS_STORAGE_KEY || !event.newValue) return;
    try {
      const parsed = JSON.parse(event.newValue);
      if (parsed && (parsed.theme === "system" || parsed.theme === "light" || parsed.theme === "dark")) {
        store.setState({ theme: parsed.theme });
        applyTheme(parsed.theme);
      }
    } catch {
      // Ignore malformed cross-tab payload
    }
  });
}
