// Which sites the page-world script runs on, and as which plug-ins: CryptoPro's, IFCPlugin (the old Gosuslugi
// plug-in), Gosplugin and Kontur.Plugin, each turned on by the user per site (docs/PLAN.md of stages 8 and 9). Each
// plug-in's list lives in chrome.storage.local; access to a site is one optional host permission for all of them, requested when the user turns
// the first one on. page.js is registered only for sites that are both listed and accessible, so a site the user never
// enabled sees nothing from us (docs/PLAN.md of stage 5). It learns which plug-ins to be from the flag scripts
// registered before it (src/page/modes.ts).
import { BROWSER, type Browser } from "./browser.ts";
import { MODE_FILES, type Plugin, PLUGINS } from "../page/modes.ts";

export { PLUGINS, type Plugin };

// page.js as CryptoPro's plug-in alone: no flag script, page.js's default, registered under the id of the builds
// before IFCPlugin and Gosplugin, so an update changes no registration of the sites enabled then.
export const SCRIPT_ID = "cades-shim";
// The isolated-world script handing page.js the root store (roots-bridge.ts).
export const BRIDGE_ID = "cades-roots";
// What roots-bridge.js sets in the extension's isolated world of each page it runs in: a page that has it has page.js.
export const BRIDGE_MARKER = "rutokenCadesBridge";
// The plug-ins' site lists. CryptoPro's keeps the key of the single list before stage 8.
export const STORAGE_KEY = "sites";
export const LIST_KEYS: Record<Plugin, string> = { cryptopro: STORAGE_KEY, ifc: "ifcSites", gos: "gosSites", kontur: "konturSites" };
// Kontur.Plugin's client id, made once (src/page/kontur/kontur-plugin.ts).
export const KONTUR_CLIENT_ID_KEY = "konturClientId";
// What the user chose for the PIN a site passes to IFCPlugin: true — ask it in the extension's window instead.
export const IFC_PIN_WINDOW_KEY = "ifcPinWindow";
// The origins of the timestamp services the user let the extension reach (timestamps.ts).
export const TSA_KEY = "tsaServices";
// The site being enabled while Chrome asks for access. Chrome's prompt can close the popup that asked, and with
// it the rest of enableSite; the service worker then finishes the job when the access arrives (finishPendingSite).
export const PENDING_KEY = "pendingSite";

interface PendingSite {
  site: string;
  // The plug-ins to turn on; CryptoPro's when absent (builds before stage 8).
  plugins?: Plugin[];
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

// The match pattern of the access to a site or a timestamp service. Chrome's is the origin's, port included. Firefox
// injects no content script by a pattern with a port, whatever access it holds (docs/JOURNAL.md, 2026-10-16), so
// there the access to a site covers every port of its host.
export function matchPattern(site: string, browser: Browser = BROWSER): string {
  if (browser !== "firefox") return `${site}/*`;
  const url = new URL(site);
  return `${url.protocol}//${url.hostname}/*`;
}

async function origins(key: string, api: Api): Promise<string[]> {
  const stored = (await api.storage.local.get(key))[key];
  return Array.isArray(stored) ? stored.filter((origin): origin is string => typeof origin === "string") : [];
}

// The sites one plug-in is on for.
export function pluginSites(plugin: Plugin, api: Api = chrome): Promise<string[]> {
  return origins(LIST_KEYS[plugin], api);
}

// Every site some plug-in is on for, sorted.
export async function enabledSites(api: Api = chrome): Promise<string[]> {
  const all = new Set<string>();
  for (const plugin of PLUGINS) for (const site of await pluginSites(plugin, api)) all.add(site);
  return [...all].sort();
}

// The plug-ins a site is on for, in PLUGINS' order.
export async function sitePlugins(site: string, api: Api = chrome): Promise<Plugin[]> {
  const on: Plugin[] = [];
  for (const plugin of PLUGINS) if ((await pluginSites(plugin, api)).includes(site)) on.push(plugin);
  return on;
}

export async function ifcPinWindow(api: Api = chrome): Promise<boolean> {
  return (await api.storage.local.get(IFC_PIN_WINDOW_KEY))[IFC_PIN_WINDOW_KEY] === true;
}

export async function setIfcPinWindow(enabled: boolean, api: Api = chrome): Promise<void> {
  await api.storage.local.set({ [IFC_PIN_WINDOW_KEY]: enabled });
}

export function tsaServices(api: Api = chrome): Promise<string[]> {
  return origins(TSA_KEY, api);
}

// Takes the access to `origin` back once no enabled site or timestamp service needs its pattern: in Firefox, an
// enabled site and a service on the same host share one, whatever their ports.
export async function releaseAccess(origin: string, api: Api = chrome): Promise<void> {
  const pattern = matchPattern(origin);
  const listed = [...(await enabledSites(api)), ...(await tsaServices(api))];
  if (listed.some((other) => matchPattern(other) === pattern)) return;
  try {
    await api.permissions.remove({ origins: [pattern] });
  } catch {
    // A permission the manifest requires cannot be removed; the origin is off anyway, being unlisted.
  }
}

export async function hasAccess(site: string, api: Api = chrome): Promise<boolean> {
  return api.permissions.contains({ origins: [matchPattern(site)] });
}

// Turns `plugins` on for a site. Must be called from a user gesture: permissions.request is its first step (Chrome
// answers at once, without a prompt, for a site it already has access to). Resolves false when the user refuses access.
export async function enableSite(site: string, api: Api = chrome, tabId?: number, plugins: readonly Plugin[] = ["cryptopro"]): Promise<boolean> {
  // Both calls leave before the prompt shows: the request first, while the click still counts as a user gesture.
  const request = api.permissions.request({ origins: [matchPattern(site)] });
  const pending: PendingSite = { site, plugins: [...plugins], ...(tabId === undefined ? {} : { tabId }) };
  await api.storage.local.set({ [PENDING_KEY]: pending });
  const granted = await request;
  await api.storage.local.remove(PENDING_KEY);
  if (granted) await listSite(site, plugins, api);
  return granted;
}

async function listSite(site: string, plugins: readonly Plugin[], api: Api): Promise<void> {
  for (const plugin of plugins) {
    const sites = await pluginSites(plugin, api);
    if (!sites.includes(site)) await api.storage.local.set({ [LIST_KEYS[plugin]]: [...sites, site].sort() });
  }
}

async function unlistSite(site: string, plugins: readonly Plugin[], api: Api): Promise<void> {
  for (const plugin of plugins) {
    const sites = await pluginSites(plugin, api);
    if (sites.includes(site)) await api.storage.local.set({ [LIST_KEYS[plugin]]: sites.filter((s) => s !== site) });
  }
}

// Turns one plug-in off for a site; the access goes once no plug-in is on for it.
export async function disablePlugin(site: string, plugin: Plugin, api: Api = chrome): Promise<void> {
  await unlistSite(site, [plugin], api);
  await releaseAccess(site, api);
}

// In the service worker, when Chrome grants access: lists the site enableSite was waiting for and reloads its tab,
// unless enableSite lived to do it itself. The registration comes first: a tab reloaded before it would come back
// without page.js. Runs among the service worker's serialised calls, so it may sync itself.
export async function finishPendingSite(api: Api = chrome): Promise<void> {
  const pending = (await api.storage.local.get(PENDING_KEY))[PENDING_KEY] as Partial<PendingSite> | undefined;
  if (typeof pending?.site !== "string" || !(await hasAccess(pending.site, api))) return;
  await api.storage.local.remove(PENDING_KEY);
  const plugins = Array.isArray(pending.plugins) ? pending.plugins.filter((plugin): plugin is Plugin => PLUGINS.includes(plugin)) : (["cryptopro"] as Plugin[]);
  await listSite(pending.site, plugins, api);
  await syncContentScript(api);
  if (typeof pending.tabId === "number") await api.tabs.reload(pending.tabId).catch(() => {});
}

// Turns every plug-in off for a site and takes the access back.
export async function disableSite(site: string, api: Api = chrome): Promise<void> {
  await unlistSite(site, PLUGINS, api);
  await releaseAccess(site, api);
}

// Drops sites whose access the user revoked in Chrome's own settings.
export async function pruneSites(api: Api = chrome): Promise<void> {
  for (const plugin of PLUGINS) {
    const sites = await pluginSites(plugin, api);
    const kept: string[] = [];
    for (const site of sites) if (await hasAccess(site, api)) kept.push(site);
    if (kept.length !== sites.length) await api.storage.local.set({ [LIST_KEYS[plugin]]: kept });
  }
}

// The registration of page.js as a set of plug-ins: its id and scripts. CryptoPro's alone keeps SCRIPT_ID and page.js
// without a flag script; any other set has its flag scripts first.
export function shimScript(plugins: readonly Plugin[]): { id: string; js: string[] } {
  const sorted = PLUGINS.filter((plugin) => plugins.includes(plugin));
  if (sorted.length === 1 && sorted[0] === "cryptopro") return { id: SCRIPT_ID, js: ["page.js"] };
  return { id: `shim-${sorted.join("-")}`, js: [...sorted.map((plugin) => MODE_FILES[plugin]), "page.js"] };
}

// Every id page.js may be registered under: one for each non-empty set of plug-ins.
export const SHIM_IDS: readonly string[] = Array.from({ length: 2 ** PLUGINS.length - 1 }, (_, index) =>
  shimScript(PLUGINS.filter((_, bit) => (index + 1) & (1 << bit))).id,
);

// What page.js should be registered for, by registration id: the match patterns of the accessible sites, each under
// the set of plug-ins on for it. In Firefox two sites on one host share a pattern; the pattern gets both sets.
async function wantedShims(api: Api): Promise<Map<string, { js: string[]; matches: string[] }>> {
  const byPattern = new Map<string, Set<Plugin>>();
  for (const plugin of PLUGINS) {
    for (const site of await pluginSites(plugin, api)) {
      if (!(await hasAccess(site, api))) continue;
      const pattern = matchPattern(site);
      if (!byPattern.has(pattern)) byPattern.set(pattern, new Set());
      byPattern.get(pattern)!.add(plugin);
    }
  }
  const wanted = new Map<string, { js: string[]; matches: string[] }>();
  for (const [pattern, plugins] of byPattern) {
    const { id, js } = shimScript([...plugins]);
    if (!wanted.has(id)) wanted.set(id, { js, matches: [] });
    wanted.get(id)!.matches.push(pattern);
  }
  for (const entry of wanted.values()) entry.matches.sort();
  return wanted;
}

const patternSet = (matches: readonly string[]) => JSON.stringify([...new Set(matches)].sort());

// The registrations as compared by whenRegistered: id and patterns.
const registrationKey = (entries: Iterable<[string, readonly string[]]>) =>
  JSON.stringify([...entries].map(([id, matches]) => [id, patternSet(matches)]).sort());

// Waits, up to `timeoutMs`, until the registered page.js matches the site lists: the popup saves a list and the
// service worker registers page.js on the change, so a tab reloaded at once could come back without it (or, for a site
// turned off, still with it, or as the wrong plug-ins).
export async function whenRegistered(api: Api = chrome, timeoutMs = 5000): Promise<void> {
  const wanted = registrationKey([...(await wantedShims(api))].map(([id, { matches }]) => [id, matches]));
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const registered = await api.scripting.getRegisteredContentScripts({ ids: [...SHIM_IDS] });
    if (registrationKey(registered.map((script) => [script.id, script.matches ?? []])) === wanted || Date.now() >= deadline) return;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
}

// What a registration is compared by: a script registered the same way is left alone.
const shape = (script: chrome.scripting.RegisteredContentScript) =>
  JSON.stringify([patternSet(script.matches ?? []), script.js, script.world ?? "ISOLATED", script.runAt, script.allFrames ?? false]);

// Makes the registered content scripts match the enabled, accessible sites: page.js under the registration of each
// site's set of plug-ins, the bridge on all of them. Callers serialise calls. A registration is changed in place, never
// taken down and put back: a page loading in between would miss page.js (docs/JOURNAL.md, 2026-10-29). For the same
// reason a site moving to another set of plug-ins is added to its new registration before it leaves the old one; a
// page loading in between gets page.js twice, and the second one stands aside (src/page/main.ts). Returns the
// patterns of all the enabled sites.
export async function syncContentScript(api: Api = chrome): Promise<string[]> {
  const shims = await wantedShims(api);
  const matches = [...new Set([...shims.values()].flatMap((entry) => entry.matches))].sort();
  const common = { runAt: "document_start", allFrames: true, persistAcrossSessions: true } as const;
  const wanted: chrome.scripting.RegisteredContentScript[] = [...shims].map(([id, { js, matches }]) => ({ id, js, world: "MAIN", matches, ...common }));
  if (matches.length) wanted.push({ id: BRIDGE_ID, js: ["roots-bridge.js"], world: "ISOLATED", matches, ...common });
  const registered = await api.scripting.getRegisteredContentScripts({ ids: [...SHIM_IDS, BRIDGE_ID] });
  const present = new Map(registered.map((script) => [script.id, script]));
  // First every registration that gains a pattern, with its old patterns kept; then each gets exactly its own.
  const growing = wanted.filter((script) => {
    const old = present.get(script.id);
    return old && script.matches!.some((pattern) => !(old.matches ?? []).includes(pattern));
  });
  if (growing.length) {
    const grown = growing.map((script) => ({ ...script, matches: [...new Set([...(present.get(script.id)!.matches ?? []), ...script.matches!])].sort() }));
    await api.scripting.updateContentScripts(grown);
    for (const script of grown) present.set(script.id, script);
  }
  const missing = wanted.filter((script) => !present.has(script.id));
  if (missing.length) await api.scripting.registerContentScripts(missing);
  const changed = wanted.filter((script) => present.has(script.id) && shape(present.get(script.id)!) !== shape(script));
  if (changed.length) await api.scripting.updateContentScripts(changed);
  const gone = registered.filter((script) => !wanted.some((other) => other.id === script.id)).map((script) => script.id);
  if (gone.length) await api.scripting.unregisterContentScripts({ ids: gone });
  return matches;
}

// A browser restoring its tabs as it starts loads them before it has the extension's registered scripts: the pages of
// the enabled sites come up without page.js, and only loading again gives it to them (docs/JOURNAL.md, 2026-10-29).
// Reloads those tabs, and only those: a page with the bridge has page.js too, they are registered together. Returns the
// tabs reloaded.
export async function reloadTabsWithoutScript(api: Api = chrome): Promise<number[]> {
  const sites = new Set<string>();
  for (const site of await enabledSites(api)) if (await hasAccess(site, api)) sites.add(site);
  const reloaded: number[] = [];
  if (!sites.size) return reloaded;
  // Without the "tabs" permission a tab shows its address only to an extension with access to its site.
  for (const tab of await api.tabs.query({})) {
    // A discarded tab loads anew when the user opens it.
    if (tab.id === undefined || tab.discarded || !sites.has(siteOf(tab.url) ?? "")) continue;
    try {
      const [answer] = await api.scripting.executeScript({ target: { tabId: tab.id }, func: (marker: string) => marker in globalThis, args: [BRIDGE_MARKER] });
      if (answer?.result === true) continue;
    } catch {
      // The page went away while asked, or cannot be reached: nothing to repair.
      continue;
    }
    await api.tabs.reload(tab.id).catch(() => {});
    reloaded.push(tab.id);
  }
  return reloaded;
}
