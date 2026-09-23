/// <reference types="chrome" />
import { describe, expect, it } from "vitest";
import {
  disableSite,
  enabledSites,
  enableSite,
  matchPattern,
  pruneSites,
  SCRIPT_ID,
  siteOf,
  syncContentScript,
} from "../../src/extension/sites.ts";

// The parts of chrome.* the site list uses. `granted` holds host permissions; `grant` decides what
// the user answers to Chrome's prompt; `required` ones cannot be removed.
function fakeChrome({ grant = true, required = [] as string[] } = {}) {
  const store: Record<string, unknown> = {};
  const granted = new Set<string>(required);
  let scripts: chrome.scripting.RegisteredContentScript[] = [];
  const covers = (origin: string) => granted.has(origin);
  const api = {
    storage: {
      local: {
        get: async (key: string) => (key in store ? { [key]: store[key] } : {}),
        set: async (items: Record<string, unknown>) => void Object.assign(store, items),
      },
    },
    permissions: {
      contains: async ({ origins = [] }: chrome.permissions.Permissions) => origins.every(covers),
      request: async ({ origins = [] }: chrome.permissions.Permissions) => {
        if (origins.every(covers)) return true;
        if (grant) origins.forEach((origin) => granted.add(origin));
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
      },
      registerContentScripts: async (list: chrome.scripting.RegisteredContentScript[]) => {
        for (const script of list) {
          if (scripts.some((s) => s.id === script.id)) throw new Error(`Duplicate script ID '${script.id}'`);
          scripts.push(script);
        }
      },
    },
  };
  return { api: api as unknown as typeof chrome, store, granted, scripts: () => scripts };
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
  });

  it("enables a site only when Chrome grants access, and registers page.js for exactly the enabled sites", async () => {
    const chrome = fakeChrome();
    expect(await enableSite("https://b.example", chrome.api)).toBe(true);
    expect(await enableSite("https://a.example", chrome.api)).toBe(true);
    expect(await enableSite("https://a.example", chrome.api)).toBe(true);
    expect(await enabledSites(chrome.api)).toEqual(["https://a.example", "https://b.example"]);
    expect(await syncContentScript(chrome.api)).toEqual(["https://a.example/*", "https://b.example/*"]);
    expect(chrome.scripts()).toEqual([
      {
        id: SCRIPT_ID,
        matches: ["https://a.example/*", "https://b.example/*"],
        js: ["page.js"],
        world: "MAIN",
        runAt: "document_start",
        allFrames: true,
        persistAcrossSessions: true,
      },
    ]);
    // A second sync replaces the registration instead of failing on the duplicate id.
    await syncContentScript(chrome.api);
    expect(chrome.scripts()).toHaveLength(1);
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
