// Which sites the page-world script runs on. The list lives in chrome.storage.local; access to a site is
// an optional host permission, requested when the user enables it. page.js is registered only for sites
// that are both listed and accessible, so a site the user never enabled sees no window.cadesplugin from
// us (docs/PLAN.md of stage 5).

export const SCRIPT_ID = "cades-shim";
// The isolated-world script handing page.js the root store (roots-bridge.ts).
export const BRIDGE_ID = "cades-roots";
export const STORAGE_KEY = "sites";
// The site being enabled while Chrome asks for access. Chrome's prompt can close the popup that asked, and with
// it the rest of enableSite; the service worker then finishes the job when the access arrives (finishPendingSite).
export const PENDING_KEY = "pendingSite";

interface PendingSite {
  site: string;
  // The tab to reload once the site is on: the popup's.
  tabId?: number;
}

type Api = typeof chrome;

// A site is an origin: scheme, host and port. Only web pages.
export function siteOf(url: string | undefined): string | undefined {
  try {
    const parsed = new URL(url ?? "");
    return parsed.protocol === "http:" || parsed.protocol === "https:" ? parsed.origin : undefined;
  } catch {
    return undefined;
  }
}

export function matchPattern(site: string): string {
  return `${site}/*`;
}

export async function enabledSites(api: Api = chrome): Promise<string[]> {
  const stored = (await api.storage.local.get(STORAGE_KEY))[STORAGE_KEY];
  return Array.isArray(stored) ? stored.filter((site): site is string => typeof site === "string") : [];
}

export async function hasAccess(site: string, api: Api = chrome): Promise<boolean> {
  return api.permissions.contains({ origins: [matchPattern(site)] });
}

// Must be called from a user gesture: permissions.request is its first step. Resolves false when the
// user refuses access.
export async function enableSite(site: string, api: Api = chrome, tabId?: number): Promise<boolean> {
  // Both calls leave before the prompt shows: the request first, while the click still counts as a user gesture.
  const request = api.permissions.request({ origins: [matchPattern(site)] });
  const pending: PendingSite = tabId === undefined ? { site } : { site, tabId };
  await api.storage.local.set({ [PENDING_KEY]: pending });
  const granted = await request;
  await api.storage.local.remove(PENDING_KEY);
  if (granted) await listSite(site, api);
  return granted;
}

async function listSite(site: string, api: Api): Promise<void> {
  const sites = await enabledSites(api);
  if (!sites.includes(site)) await api.storage.local.set({ [STORAGE_KEY]: [...sites, site].sort() });
}

// In the service worker, when Chrome grants access: lists the site enableSite was waiting for and reloads its tab,
// unless enableSite lived to do it itself.
export async function finishPendingSite(api: Api = chrome): Promise<void> {
  const pending = (await api.storage.local.get(PENDING_KEY))[PENDING_KEY] as Partial<PendingSite> | undefined;
  if (typeof pending?.site !== "string" || !(await hasAccess(pending.site, api))) return;
  await api.storage.local.remove(PENDING_KEY);
  await listSite(pending.site, api);
  if (typeof pending.tabId === "number") await api.tabs.reload(pending.tabId).catch(() => {});
}

export async function disableSite(site: string, api: Api = chrome): Promise<void> {
  const sites = await enabledSites(api);
  await api.storage.local.set({ [STORAGE_KEY]: sites.filter((s) => s !== site) });
  try {
    await api.permissions.remove({ origins: [matchPattern(site)] });
  } catch {
    // A permission the manifest requires cannot be removed; the site is off anyway, being unlisted.
  }
}

// Drops sites whose access the user revoked in Chrome's own settings.
export async function pruneSites(api: Api = chrome): Promise<void> {
  const sites = await enabledSites(api);
  const kept: string[] = [];
  for (const site of sites) if (await hasAccess(site, api)) kept.push(site);
  if (kept.length !== sites.length) await api.storage.local.set({ [STORAGE_KEY]: kept });
}

// Makes the registered content script match the enabled, accessible sites. Callers serialise calls.
export async function syncContentScript(api: Api = chrome): Promise<string[]> {
  const matches: string[] = [];
  for (const site of await enabledSites(api)) if (await hasAccess(site, api)) matches.push(matchPattern(site));
  const ids = [SCRIPT_ID, BRIDGE_ID];
  const registered = await api.scripting.getRegisteredContentScripts({ ids });
  if (registered.length) await api.scripting.unregisterContentScripts({ ids: registered.map((script) => script.id) });
  if (matches.length) {
    const common = { matches, runAt: "document_start", allFrames: true, persistAcrossSessions: true } as const;
    await api.scripting.registerContentScripts([
      { id: SCRIPT_ID, js: ["page.js"], world: "MAIN", ...common },
      { id: BRIDGE_ID, js: ["roots-bridge.js"], world: "ISOLATED", ...common },
    ]);
  }
  return matches;
}
