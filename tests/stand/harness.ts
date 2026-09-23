/// <reference types="chrome" />
// Drives Chromium on the test stand: the Rutoken adapter loaded under its store
// id, the native host and the fake Rutoken found through the stand HOME.
import { chromium, type BrowserContext, type Page } from "@playwright/test";
import { createHash, X509Certificate } from "node:crypto";
import { cpSync, existsSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { extname, join, relative } from "node:path";
import { extensionDir } from "../../scripts/build.ts";
import { stand, standDir, standEnv } from "../../scripts/setup-stand.ts";

export interface Route {
  type: string;
  body: string | Buffer;
}

export interface PageServer {
  url: string;
  close(): Promise<void>;
}

// Content scripts do not run on file:// pages by default, so pages are served over local HTTP.
export async function servePages(routes: Record<string, Route>): Promise<PageServer> {
  const server: Server = createServer((req, res) => {
    const route = routes[new URL(req.url ?? "/", "http://x").pathname];
    if (!route) {
      res.statusCode = 404;
      res.end();
      return;
    }
    res.setHeader("content-type", route.type);
    res.end(route.body);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

const contentTypes: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
};

// Routes for every file under `dir`, served at `prefix` + its path relative to `dir`.
export function directoryRoutes(dir: string, prefix: string): Record<string, Route> {
  const routes: Record<string, Route> = {};
  for (const entry of readdirSync(dir, { recursive: true, withFileTypes: true })) {
    if (!entry.isFile()) continue;
    const path = join(entry.parentPath, entry.name);
    const type = contentTypes[extname(entry.name)] ?? "application/octet-stream";
    routes[`${prefix}/${relative(dir, path)}`] = { type, body: readFileSync(path) };
  }
  return routes;
}

export interface StandOptions {
  // Unpacked extensions to load; the Rutoken adapter unless told otherwise.
  extensions?: string[];
  // Chromium profile; the stand profile holds the native host manifest.
  profile?: string;
  // Internet hosts the stand may reach (for experiments with real sites); everything else stays offline.
  online?: string[];
}

// The environment's HTTPS proxy re-signs TLS with its own CA. Chromium is told to trust exactly that CA
// (by its public key), the way every other tool here is pointed at the proxy's CA bundle.
const proxyCa = process.env.STAND_PROXY_CA ?? "/root/.ccr/agent-proxy-ca.crt";

function proxyOptions(): { proxy?: { server: string }; args: string[] } {
  const server = process.env.HTTPS_PROXY;
  if (!server || !existsSync(proxyCa)) return { args: [] };
  const spki = new X509Certificate(readFileSync(proxyCa)).publicKey.export({ type: "spki", format: "der" });
  return { proxy: { server }, args: [`--ignore-certificate-errors-spki-list=${createHash("sha256").update(spki).digest("base64")}`] };
}

export async function launchStand({ extensions = [stand.adapter], profile = stand.profile, online = [] }: StandOptions = {}) {
  const list = extensions.join(",");
  const network = online.length ? proxyOptions() : { args: [] };
  const context = await chromium.launchPersistentContext(profile, {
    headless: true,
    // The full Chromium build: the headless shell cannot load extensions.
    channel: "chromium",
    args: [`--disable-extensions-except=${list}`, `--load-extension=${list}`, ...network.args],
    ...(network.proxy ? { proxy: network.proxy } : {}),
    env: standEnv() as Record<string, string>,
  });
  // Stand tests stay offline: pages get only what the local server serves, plus the hosts asked for.
  await context.route(
    (url) => url.protocol.startsWith("http") && url.hostname !== "127.0.0.1" && !online.includes(url.hostname),
    (route) => route.abort(),
  );
  return context;
}

// On a fresh profile the adapter registers its MAIN-world script from its service worker
// after start-up, so the first navigations can miss it. Reload until the adapter object appears.
export async function openStandPage(context: BrowserContext, url: string, timeoutMs = 15000): Promise<Page> {
  const page = await context.newPage();
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    await page.goto(url);
    const ready = await page.evaluate(() => "C3B7563B-BF85-45B7-88FC-7CFF1BD3C2DB" in window);
    if (ready) return page;
    if (Date.now() > deadline) throw new Error("Rutoken adapter did not inject its page object");
    await page.waitForTimeout(250);
  }
}

export const blankPage: Route = { type: "text/html; charset=utf-8", body: "<!doctype html><title>stand</title>" };

// Page-side helper, injected by tests: loads the Rutoken Plugin through the adapter object.
export const loadPluginSource = `async () => {
  const ext = window["C3B7563B-BF85-45B7-88FC-7CFF1BD3C2DB"];
  if (!ext) throw new Error("Rutoken adapter object is missing");
  if (ext.initialize) await ext.initialize();
  if (!(await ext.isPluginInstalled())) throw new Error("Rutoken Plugin is not installed");
  return ext.loadPlugin();
}`;

// The built extension with access to the stand's pages granted in advance, as if the user had allowed
// it when enabling a site: Chrome's permission prompt is browser UI a test cannot click. Enabling and
// disabling a site still go through the extension's own options page.
export function standExtension(hosts: string[] = []): string {
  const dir = join(standDir, "extension");
  rmSync(dir, { recursive: true, force: true });
  cpSync(extensionDir, dir, { recursive: true });
  const manifestPath = join(dir, "manifest.json");
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  manifest.host_permissions = ["http://127.0.0.1/*", ...hosts];
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
  return dir;
}

// Our extension's id: unpacked extensions get one derived from their path.
export async function extensionOrigin(context: BrowserContext): Promise<string> {
  const deadline = Date.now() + 15000;
  for (;;) {
    for (const worker of context.serviceWorkers()) {
      const name = await worker
        .evaluate(() => chrome.runtime.getManifest().name)
        .catch(() => undefined);
      if (name === "КриптоПро через Рутокен") return `chrome-extension://${new URL(worker.url()).host}`;
    }
    if (Date.now() > deadline) throw new Error("the extension's service worker did not start");
    await context.waitForEvent("serviceworker", { timeout: 1000 }).catch(() => {});
  }
}

async function extensionWorker(context: BrowserContext) {
  const origin = await extensionOrigin(context);
  return context.serviceWorkers().find((worker) => worker.url().startsWith(origin))!;
}

// The stand profile persists between runs, and so does the extension's site list; tests start from none.
export async function clearSites(context: BrowserContext): Promise<void> {
  const worker = await extensionWorker(context);
  await worker.evaluate(() => chrome.storage.local.clear());
}

// The id of the tab showing `page`, as the extension sees it; `page` must be the only tab at its URL.
export async function tabId(context: BrowserContext, page: Page): Promise<number> {
  const worker = await extensionWorker(context);
  const url = page.url();
  return worker.evaluate(async (url) => {
    const tabs = await chrome.tabs.query({ url });
    if (tabs.length !== 1) throw new Error(`${tabs.length} tabs at ${url}`);
    return tabs[0]!.id!;
  }, url);
}

async function optionsPage(context: BrowserContext): Promise<Page> {
  const page = await context.newPage();
  await page.goto(`${await extensionOrigin(context)}/options.html`);
  return page;
}

// Turns the extension on for `site` the way a user does on the options page.
export async function enableSite(context: BrowserContext, site: string): Promise<void> {
  const page = await optionsPage(context);
  await page.locator("input[name=site]").fill(site);
  await page.locator("#add button[type=submit]").click();
  await page.locator("#sites li", { hasText: new URL(site).origin }).waitFor();
  await page.close();
}

export async function disableSite(context: BrowserContext, site: string): Promise<void> {
  const page = await optionsPage(context);
  const item = page.locator("#sites li", { hasText: new URL(site).origin });
  await item.locator("button").click();
  await item.waitFor({ state: "detached" });
  await page.close();
}
