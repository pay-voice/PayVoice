/**
 * PayVoice Theme Manager
 * Supports Light, Dark, and System preference with instant DOM updates.
 */

import { store } from "./store.js";

const mediaQuery = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;

export function getResolvedTheme(pref = store.getState().theme) {
  if (pref === "light" || pref === "dark") return pref;
  return mediaQuery && mediaQuery.matches ? "dark" : "light";
}

export function applyTheme(pref = store.getState().theme) {
  const resolved = getResolvedTheme(pref);
  document.documentElement.setAttribute("data-theme", resolved);
  document.documentElement.style.colorScheme = resolved;
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
}

