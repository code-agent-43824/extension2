// The browser this build is for: scripts/build.ts builds dist/extension for Chrome and dist/firefox for Firefox from
// the same code; the unit tests run as Chrome's (vitest.config.ts).
export type Browser = "chrome" | "firefox";

export const BROWSER: Browser = __BROWSER__;
export const BROWSER_NAME = BROWSER === "firefox" ? "Firefox" : "Chrome";
