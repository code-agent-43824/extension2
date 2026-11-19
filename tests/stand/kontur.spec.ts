// The extension as Kontur.Plugin on the fake Rutoken: a page posts kontur-toolbox-request messages as Kontur's client
// does and reads the kontur-toolbox-response ones; the answers are compared with what the real extension and host
// gave on the stand (docs/JOURNAL.md, 2026-11-19).
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { stand } from "../../scripts/setup-stand.ts";
import { clearSites, enableSite, launchStand, openStandPage, servePages, standExtension, type PageServer } from "./harness.ts";

// A page as Kontur's client talks to the plug-in: one session, numbered commands, answers matched by commandId.
const KONTUR_PAGE = `<!doctype html><html><head><meta charset="utf-8"><title>Kontur</title></head><body><script>
let commandId = 0;
const waiting = new Map();
addEventListener("message", (event) => {
  if (!event.data || event.data.type !== "kontur-toolbox-response") return;
  const response = event.data.response;
  const resolve = waiting.get(response.commandId);
  if (resolve) { waiting.delete(response.commandId); resolve(JSON.parse(JSON.stringify(response))); }
});
window.kontur = (type, fields = {}, timeoutMs = 60000) => new Promise((resolve) => {
  const id = ++commandId;
  waiting.set(id, resolve);
  setTimeout(() => { if (waiting.delete(id)) resolve({ timeout: true }); }, timeoutMs);
  postMessage({ type: "kontur-toolbox-request", request: { sessionId: "s-test", commandId: id, type, ...fields } }, "*");
});
</script></body></html>`;

type Answer = { sessionId?: string; commandId?: number; result?: any; error?: { type: string; code?: number; message: string; context?: string }; timeout?: boolean };

const ask = (page: Page, type: string, fields: Record<string, unknown> = {}, timeoutMs?: number) =>
  page.evaluate(([t, f, ms]) => (window as unknown as { kontur: (...a: unknown[]) => Promise<Answer> }).kontur(t, f, ms), [type, fields, timeoutMs] as const) as Promise<Answer>;

let server: PageServer;
let context: BrowserContext;

test.beforeAll(async () => {
  server = await servePages({ "/kontur.html": { type: "text/html; charset=utf-8", body: KONTUR_PAGE } });
  context = await launchStand({ extensions: [stand.adapter, standExtension(["https://extern.kontur.ru/*"])] });
  await clearSites(context);
  await enableSite(context, server.url, ["kontur"]);
});

test.afterAll(async () => {
  await context?.close();
  await server?.close();
});

test("answers the extension's own commands and plugin.info as the real ones do, on a site that is not Kontur's", async () => {
  const page = await openStandPage(context, `${server.url}/kontur.html`);
  // No mark off Kontur's domains, as the real extension.
  expect(await page.locator("meta[kontur-toolbox-installed]").count()).toBe(0);
  expect(await ask(page, "extension.info")).toEqual({ sessionId: "s-test", commandId: 1, result: { id: "hnhppcgejeffnbnioloohhmndpmclaga", type: "chrome", version: "3.1.11" } });
  expect((await ask(page, "extension.info", { extensionId: "other" }, 1000)).timeout).toBe(true);
  const info = await ask(page, "plugin.info");
  // Enabled is allowed: not denied, unlike the real host off Kontur's domains (the owner, 2026-11-19).
  expect(info.result).toMatchObject({ architecture: "x86_64", buildType: "stable", denied: false, platform: "linux", pluginVersion: "4.15.1.6119" });
  expect(info.result.clientId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  expect((await ask(page, "no.such")).error).toEqual({ type: "plugin", code: 2, message: "PLUGIN[0x00000002] unknown command" });
  expect((await ask(page, "extension.uninstall", { extensionId: "hnhppcgejeffnbnioloohhmndpmclaga" })).error).toEqual({ type: "extension", message: "bad request" });
  // The client id is the extension's, the same on the next page.
  const next = await openStandPage(context, `${server.url}/kontur.html`);
  expect((await ask(next, "plugin.info")).result.clientId).toBe(info.result.clientId);
  await next.close();
  await page.close();
});

test("marks Kontur's own pages for the client", async () => {
  const site = "https://extern.kontur.ru";
  await enableSite(context, site, ["kontur"]);
  const page = await context.newPage();
  await page.route(`${site}/**`, (route) => route.fulfill({ contentType: "text/html; charset=utf-8", body: KONTUR_PAGE }));
  await page.goto(`${site}/kontur.html`);
  await expect(page.locator('meta[kontur-toolbox-installed="true"]')).toHaveCount(1, { timeout: 15_000 });
  expect((await ask(page, "extension.uninstall", { extensionId: "other" }, 1000)).timeout).toBe(true);
  await page.close();
});
