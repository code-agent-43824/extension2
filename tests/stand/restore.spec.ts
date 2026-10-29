// Tabs of an enabled site that the browser restores as it starts (docs/PLAN.md, action 40b): it loads them before it has
// the extension's registered scripts, so they come up without page.js; the service worker reloads them.
import { expect, test } from "@playwright/test";
import { cpSync, rmSync } from "node:fs";
import { join } from "node:path";
import { stand, standDir } from "../../scripts/setup-stand.ts";
import { blankPage, clearSites, enableSite, launchStand, servePages, standExtension, type PageServer } from "./harness.ts";

const dir = join(standDir, "restore");
const paths = ["/a", "/b", "/c"];
let server: PageServer;

test.beforeAll(async () => {
  server = await servePages(Object.fromEntries(paths.map((path) => [path, blankPage])));
  // A profile of its own: the restored session must not leak into the other stand tests.
  rmSync(dir, { recursive: true, force: true });
  cpSync(stand.profile, join(dir, "profile"), { recursive: true, verbatimSymlinks: true });
});

test.afterAll(async () => {
  await server?.close();
});

// Only our page.js defines window.cadesplugin on these blank pages.
const hasShim = () => typeof (window as unknown as { cadesplugin?: unknown }).cadesplugin === "object";

test("the tabs of an enabled site the browser restores at start-up get page.js without the user reloading them", async () => {
  test.setTimeout(180_000);
  const extensions = [stand.adapter, standExtension()];
  const profile = join(dir, "profile");
  const first = await launchStand({ extensions, profile });
  await clearSites(first);
  await enableSite(first, server.url);
  for (const path of paths) {
    const page = await first.newPage();
    await page.goto(server.url + path);
    expect(await page.evaluate(hasShim)).toBe(true);
  }
  for (const page of first.pages()) if (!page.url().startsWith(server.url)) await page.close();
  await first.close();

  for (let restart = 0; restart < 2; restart++) {
    const context = await launchStand({ extensions, profile, restoreSession: true });
    const restored = context.pages().filter((page) => page.url().startsWith(server.url));
    expect(restored.map((page) => new URL(page.url()).pathname).sort()).toEqual(paths);
    for (const page of restored) {
      await expect.poll(() => page.evaluate(hasShim).catch(() => false), { timeout: 20_000 }).toBe(true);
    }
    await context.close();
  }
});
