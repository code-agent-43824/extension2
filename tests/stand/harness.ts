// Drives Chromium on the test stand: the Rutoken adapter loaded under its store
// id, the native host and the fake Rutoken found through the stand HOME.
import { chromium, type BrowserContext, type Page } from "@playwright/test";
import { readdirSync, readFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { extname, join, relative } from "node:path";
import { stand, standEnv } from "../../scripts/setup-stand.ts";

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
}

export async function launchStand({ extensions = [stand.adapter], profile = stand.profile }: StandOptions = {}) {
  const list = extensions.join(",");
  const context = await chromium.launchPersistentContext(profile, {
    headless: true,
    // The full Chromium build: the headless shell cannot load extensions.
    channel: "chromium",
    args: [`--disable-extensions-except=${list}`, `--load-extension=${list}`],
    env: standEnv() as Record<string, string>,
  });
  // Stand tests stay offline: pages get only what the local server serves.
  await context.route(/^https?:\/\/(?!127\.0\.0\.1[:/])/, (route) => route.abort());
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
