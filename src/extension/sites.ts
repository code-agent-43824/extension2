// Which sites the page-world script runs on. The list lives in chrome.storage.local; access to a site is
// an optional host permission, requested when the user enables it. page.js is registered only for sites
// that are both listed and accessible, so a site the user never enabled sees no window.cadesplugin from
// us (docs/PLAN.md of stage 5).

export const SCRIPT_ID = "cades-shim";
export const STORAGE_KEY = "sites";

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
export async function enableSite(site: string, api: Api = chrome): Promise<boolean> {
  if (!(await api.permissions.request({ origins: [matchPattern(site)] }))) return false;
  const sites = await enabledSites(api);
  if (!sites.includes(site)) await api.storage.local.set({ [STORAGE_KEY]: [...sites, site].sort() });
  return true;
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
  const registered = await api.scripting.getRegisteredContentScripts({ ids: [SCRIPT_ID] });
  if (registered.length) await api.scripting.unregisterContentScripts({ ids: [SCRIPT_ID] });
  if (matches.length) {
    await api.scripting.registerContentScripts([
      {
        id: SCRIPT_ID,
        matches,
        js: ["page.js"],
        world: "MAIN",
        runAt: "document_start",
        allFrames: true,
        persistAcrossSessions: true,
      },
    ]);
  }
  return matches;
}
