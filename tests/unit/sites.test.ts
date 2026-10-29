/// <reference types="chrome" />
import { describe, expect, it } from "vitest";
import {
  disableSite,
  enabledSites,
  enableSite,
  finishPendingSite,
  matchPattern,
  PENDING_KEY,
  pruneSites,
  reloadTabsWithoutScript,
  BRIDGE_ID,
  BRIDGE_MARKER,
  SCRIPT_ID,
  siteOf,
  syncContentScript,
  TSA_KEY,
  whenRegistered,
} from "../../src/extension/sites.ts";

// The parts of chrome.* the site list uses. `granted` holds host permissions; `grant` decides what
// the user answers to Chrome's prompt; `required` ones cannot be removed.
// `tabs` are the open tabs: the address the extension sees (none without access), whether the page has the bridge.
function fakeChrome({ grant = true, required = [] as string[], closeOnPrompt = false, tabs = [] as { id: number; url?: string; bridge?: boolean; discarded?: boolean; gone?: boolean }[] } = {}) {
  const store: Record<string, unknown> = {};
  // Every moment the registration changed, how many of the two scripts were registered after it.
  const registeredCounts: number[] = [];
  const granted = new Set<string>(required);
  const reloaded: number[] = [];
  // What page.js was registered for when each tab was reloaded.
  const matchesAtReload: string[][] = [];
  let scripts: chrome.scripting.RegisteredContentScript[] = [];
  const covers = (origin: string) => granted.has(origin);
  const api = {
    storage: {
      local: {
        get: async (key: string) => (key in store ? { [key]: store[key] } : {}),
        set: async (items: Record<string, unknown>) => void Object.assign(store, items),
        remove: async (key: string) => void delete store[key],
      },
    },
    tabs: {
      query: async () => tabs.map(({ id, url, discarded = false }) => ({ id, url: url && covers(new URL(url).origin + "/*") ? url : undefined, discarded })),
      reload: async (tabId: number) => {
        reloaded.push(tabId);
        matchesAtReload.push(scripts.find((script) => script.id === SCRIPT_ID)?.matches ?? []);
      },
    },
    permissions: {
      contains: async ({ origins = [] }: chrome.permissions.Permissions) => origins.every(covers),
      request: async ({ origins = [] }: chrome.permissions.Permissions) => {
        if (origins.every(covers)) return true;
        if (grant) origins.forEach((origin) => granted.add(origin));
        // The prompt closed the popup: its enableSite never gets the answer.
        if (closeOnPrompt) return new Promise<boolean>(() => {});
        return grant;
      },
      remove: async ({ origins = [] }: chrome.permissions.Permissions) => {
        if (origins.some((origin) => required.includes(origin))) throw new Error("You cannot remove required permissions.");
        origins.forEach((origin) => granted.delete(origin));
        return true;
      },
    },
    scripting: {
      getRegisteredContentScripts: async ({ ids = [] }: chrome.scripting.ContentScriptFilter = {}) =>
        scripts.filter((script) => ids.includes(script.id)),
      unregisterContentScripts: async ({ ids = [] }: chrome.scripting.ContentScriptFilter = {}) => {
        scripts = scripts.filter((script) => !ids.includes(script.id));
        registeredCounts.push(scripts.length);
      },
      registerContentScripts: async (list: chrome.scripting.RegisteredContentScript[]) => {
        for (const script of list) {
          if (scripts.some((s) => s.id === script.id)) throw new Error(`Duplicate script ID '${script.id}'`);
          scripts.push(script);
        }
        registeredCounts.push(scripts.length);
      },
      updateContentScripts: async (list: chrome.scripting.RegisteredContentScript[]) => {
        for (const script of list) {
          const index = scripts.findIndex((s) => s.id === script.id);
          if (index < 0) throw new Error(`No script with ID '${script.id}'`);
          scripts[index] = { ...scripts[index]!, ...script };
        }
        registeredCounts.push(scripts.length);
      },
      executeScript: async ({ target, func, args = [] }: { target: { tabId: number }; func: (...a: unknown[]) => unknown; args?: unknown[] }) => {
        const tab = tabs.find((t) => t.id === target.tabId)!;
        if (tab.gone) throw new Error("No tab with id");
        // The function runs in the page's isolated world, where the bridge leaves its marker.
        const world = globalThis as Record<string, unknown>;
        const marker = String(args[0]);
        if (tab.bridge) world[marker] = true;
        try {
          return [{ result: func(...args) }];
        } finally {
          delete world[marker];
        }
      },
    },
  };
  return { api: api as unknown as typeof chrome, store, granted, reloaded, matchesAtReload, registeredCounts, scripts: () => scripts };
}

describe("site list", () => {
  it("treats a site as a web origin", () => {
    expect(siteOf("https://www.cryptopro.ru/sites/default/files/x.html?a=1#b")).toBe("https://www.cryptopro.ru");
    expect(siteOf("http://127.0.0.1:8080/")).toBe("http://127.0.0.1:8080");
    expect(siteOf("chrome://extensions")).toBeUndefined();
    expect(siteOf("file:///tmp/a.html")).toBeUndefined();
    expect(siteOf("not a url")).toBeUndefined();
    expect(siteOf(undefined)).toBeUndefined();
    expect(matchPattern("https://example.ru")).toBe("https://example.ru/*");
    expect(matchPattern("http://127.0.0.1:8080")).toBe("http://127.0.0.1:8080/*");
  });

  it("gives Firefox patterns without the port, which it injects by", () => {
    expect(matchPattern("https://example.ru", "firefox")).toBe("https://example.ru/*");
    expect(matchPattern("http://127.0.0.1:8080", "firefox")).toBe("http://127.0.0.1/*");
    expect(matchPattern("https://[::1]:8443", "firefox")).toBe("https://[::1]/*");
  });

  it("enables a site only when Chrome grants access, and registers page.js for exactly the enabled sites", async () => {
    const chrome = fakeChrome();
    expect(await enableSite("https://b.example", chrome.api)).toBe(true);
    expect(await enableSite("https://a.example", chrome.api)).toBe(true);
    expect(await enableSite("https://a.example", chrome.api)).toBe(true);
    expect(await enabledSites(chrome.api)).toEqual(["https://a.example", "https://b.example"]);
    expect(await syncContentScript(chrome.api)).toEqual(["https://a.example/*", "https://b.example/*"]);
    const common = { matches: ["https://a.example/*", "https://b.example/*"], runAt: "document_start", allFrames: true, persistAcrossSessions: true };
    // page.js in the page's world, and beside it the bridge that hands it the root store.
    expect(chrome.scripts()).toEqual([
      { id: SCRIPT_ID, js: ["page.js"], world: "MAIN", ...common },
      { id: BRIDGE_ID, js: ["roots-bridge.js"], world: "ISOLATED", ...common },
    ]);
    // A second sync leaves the same registration alone.
    const changes = chrome.registeredCounts.length;
    await syncContentScript(chrome.api);
    expect(chrome.scripts()).toHaveLength(2);
    expect(chrome.registeredCounts).toHaveLength(changes);
  });

  it("changes the registration in place, so page.js is never unregistered while sites stay enabled", async () => {
    const chrome = fakeChrome();
    await enableSite("https://a.example", chrome.api);
    await syncContentScript(chrome.api);
    await enableSite("https://b.example", chrome.api);
    await syncContentScript(chrome.api);
    expect(chrome.scripts().map((script) => script.matches)).toEqual([
      ["https://a.example/*", "https://b.example/*"],
      ["https://a.example/*", "https://b.example/*"],
    ]);
    await disableSite("https://b.example", chrome.api);
    await syncContentScript(chrome.api);
    expect(chrome.scripts().map((script) => script.matches)).toEqual([["https://a.example/*"], ["https://a.example/*"]]);
    // Both scripts were registered at every change.
    expect(chrome.registeredCounts).toEqual([2, 2, 2]);
  });

  it("after start-up reloads only the tabs of enabled sites whose page lacks page.js", async () => {
    const tabs = [
      { id: 1, url: "https://a.example/x", bridge: false },
      { id: 2, url: "https://a.example/y", bridge: true },
      { id: 3, url: "https://other.example/", bridge: false },
      { id: 4, url: "https://a.example/z", bridge: false, discarded: true },
      { id: 5, url: "https://a.example/w", bridge: false, gone: true },
      { id: 6, url: "https://b.example/", bridge: false },
    ];
    const chrome = fakeChrome({ tabs });
    expect(await reloadTabsWithoutScript(chrome.api)).toEqual([]);
    await enableSite("https://a.example", chrome.api);
    await enableSite("https://b.example", chrome.api);
    // Listed but its access revoked: not the extension's to touch.
    chrome.granted.delete("https://b.example/*");
    expect(await reloadTabsWithoutScript(chrome.api)).toEqual([1]);
    expect(chrome.reloaded).toEqual([1]);
    expect(BRIDGE_MARKER).toBe("rutokenCadesBridge");
  });

  it("is finished by the service worker when Chrome's prompt closes the popup", async () => {
    const chrome = fakeChrome({ closeOnPrompt: true });
    void enableSite("https://a.example", chrome.api, 7);
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(await enabledSites(chrome.api)).toEqual([]);
    // Chrome's permissions.onAdded in the service worker.
    await finishPendingSite(chrome.api);
    expect(await enabledSites(chrome.api)).toEqual(["https://a.example"]);
    expect(chrome.reloaded).toEqual([7]);
    // page.js was registered for the site before the tab reloaded.
    expect(chrome.matchesAtReload).toEqual([["https://a.example/*"]]);
    expect(PENDING_KEY in chrome.store).toBe(false);
    // Another access granted later changes nothing.
    await finishPendingSite(chrome.api);
    expect(chrome.reloaded).toEqual([7]);
  });

  it("lets the popup wait until the service worker has registered page.js for the new list, or gives up", async () => {
    const chrome = fakeChrome();
    expect(await enableSite("https://a.example", chrome.api, 7)).toBe(true);
    // The service worker reacts to the storage change a little later.
    setTimeout(() => void syncContentScript(chrome.api), 120);
    const started = Date.now();
    await whenRegistered(chrome.api);
    expect(Date.now() - started).toBeGreaterThanOrEqual(100);
    expect(chrome.scripts().find((script) => script.id === SCRIPT_ID)?.matches).toEqual(["https://a.example/*"]);
    // Turned off: until the registration is gone; and never more than the time allowed.
    await disableSite("https://a.example", chrome.api);
    const waited = Date.now();
    await whenRegistered(chrome.api, 200);
    expect(Date.now() - waited).toBeGreaterThanOrEqual(190);
    await syncContentScript(chrome.api);
    await whenRegistered(chrome.api, 10_000);
    expect(chrome.scripts()).toEqual([]);
  });

  it("leaves nothing pending when the popup gets the answer itself", async () => {
    const chrome = fakeChrome();
    expect(await enableSite("https://a.example", chrome.api, 7)).toBe(true);
    await finishPendingSite(chrome.api);
    expect(chrome.reloaded).toEqual([]);
    expect(PENDING_KEY in chrome.store).toBe(false);
  });

  it("does not list a site when the user refuses access", async () => {
    const chrome = fakeChrome({ grant: false });
    expect(await enableSite("https://a.example", chrome.api)).toBe(false);
    expect(await enabledSites(chrome.api)).toEqual([]);
    expect(await syncContentScript(chrome.api)).toEqual([]);
    expect(chrome.scripts()).toEqual([]);
  });

  it("disabling removes the site, its access and, with the last site, the registration", async () => {
    const chrome = fakeChrome();
    await enableSite("https://a.example", chrome.api);
    await syncContentScript(chrome.api);
    await disableSite("https://a.example", chrome.api);
    expect(await enabledSites(chrome.api)).toEqual([]);
    expect(chrome.granted.has("https://a.example/*")).toBe(false);
    await syncContentScript(chrome.api);
    expect(chrome.scripts()).toEqual([]);
  });

  it("disabling keeps the access a confirmed timestamp service at the same address still needs", async () => {
    const chrome = fakeChrome();
    await enableSite("https://a.example", chrome.api);
    chrome.store[TSA_KEY] = ["https://a.example"];
    await disableSite("https://a.example", chrome.api);
    expect(await enabledSites(chrome.api)).toEqual([]);
    expect(chrome.granted.has("https://a.example/*")).toBe(true);
  });

  it("disabling still works when the access cannot be removed", async () => {
    const chrome = fakeChrome({ required: ["https://a.example/*"] });
    await enableSite("https://a.example", chrome.api);
    await disableSite("https://a.example", chrome.api);
    expect(await enabledSites(chrome.api)).toEqual([]);
  });

  it("drops sites whose access the user revoked in Chrome, and never registers a listed site without access", async () => {
    const chrome = fakeChrome();
    await enableSite("https://a.example", chrome.api);
    await enableSite("https://b.example", chrome.api);
    chrome.granted.delete("https://b.example/*");
    expect(await syncContentScript(chrome.api)).toEqual(["https://a.example/*"]);
    await pruneSites(chrome.api);
    expect(await enabledSites(chrome.api)).toEqual(["https://a.example"]);
  });

  it("ignores a malformed stored list", async () => {
    const chrome = fakeChrome();
    chrome.store.sites = "https://a.example";
    expect(await enabledSites(chrome.api)).toEqual([]);
    chrome.store.sites = ["https://a.example", 7];
    expect(await enabledSites(chrome.api)).toEqual(["https://a.example"]);
  });
});
