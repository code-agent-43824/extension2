/// <reference types="chrome" />
// The extension runs only on sites the user enabled: from the options page or the button's popup.
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { join } from "node:path";
import { vendorDir } from "../../scripts/fetch-vendor.ts";
import { stand } from "../../scripts/setup-stand.ts";
import { ADAPTER_WAIT_MS } from "../../src/page/cadesplugin.ts";
import {
  clearSites,
  directoryRoutes,
  disableSite,
  enableSite,
  extensionOrigin,
  launchStand,
  openStandPage,
  servePages,
  standExtension,
  tabId,
  type PageServer,
} from "./harness.ts";

const demoPath = "/sites/default/files/products/cades/demopage/cades_bes_sample.html";

let server: PageServer;
let context: BrowserContext;

test.beforeAll(async () => {
  server = await servePages(directoryRoutes(join(vendorDir, "cryptopro"), "/sites/default/files"));
  context = await launchStand({ extensions: [stand.adapter, standExtension()] });
});

test.afterAll(async () => {
  await context?.close();
  await server?.close();
});

test.beforeEach(async () => {
  await clearSites(context);
});

// With the shim the page reports our extension and the plug-in as loaded. Without it, CryptoPro's own
// cadesplugin_api.js runs and waits for a CryptoPro extension that never answers; the shim would have
// answered, one way or the other, within ADAPTER_WAIT_MS of the page loading.
async function expectShim(page: Page, present: boolean) {
  if (present) {
    await expect(page.locator("#ExtensionEnabledTxt")).toHaveText("Расширение загружено", { timeout: 30_000 });
    await expect(page.locator("#PluginEnabledTxt")).toHaveText("Плагин загружен", { timeout: 30_000 });
    return;
  }
  await page.waitForLoadState("load");
  await page.waitForTimeout(ADAPTER_WAIT_MS + 2000);
  await expect(page.locator("#ExtensionEnabledTxt")).toHaveText("Расширение не загружено");
  await expect(page.locator("#PluginEnabledTxt")).toHaveText("Плагин: ожидание загрузки расширения");
}

test("a site the user did not enable gets nothing from the extension", async () => {
  const page = await openStandPage(context, server.url + demoPath);
  await expectShim(page, false);
});

test("enabled on the options page, the site gets the plug-in; disabled, it no longer does", async () => {
  await enableSite(context, server.url);
  const page = await openStandPage(context, server.url + demoPath);
  await expectShim(page, true);
  await disableSite(context, server.url);
  await page.reload();
  await expectShim(page, false);
});

test("the options page refuses an address that is not a web site", async () => {
  const page = await context.newPage();
  await page.goto(`${await extensionOrigin(context)}/options.html`);
  await page.locator("input[name=site]").fill("ftp://example.ru");
  await page.locator("#add button[type=submit]").click();
  await expect(page.locator("#error")).toContainText("http:// или https://");
  await expect(page.locator("#sites li")).toHaveCount(0);
});

test("the button's popup switches the current site on and reloads it", async () => {
  // Its own query string, so the extension finds this tab and not one left open by an earlier test.
  const site = await openStandPage(context, `${server.url}${demoPath}?popup`);
  await expectShim(site, false);
  // A popup cannot be opened from a test, so popup.html is opened in a tab and asked about the
  // site's tab instead of itself; the rest is the popup's own code.
  const id = await tabId(context, site);
  const popup = await context.newPage();
  await popup.addInitScript(
    ({ id, url }) => {
      const api = chrome;
      api.tabs.query = (async () => [{ id, url }]) as unknown as typeof api.tabs.query;
    },
    { id, url: site.url() },
  );
  await popup.goto(`${await extensionOrigin(context)}/popup.html`);
  await expect(popup.locator("#site")).toHaveText(server.url);
  await expect(popup.getByRole("link", { name: "Настройки" })).toHaveAttribute("href", "options.html");
  const checkbox = popup.locator("input[name=enabled]");
  await expect(checkbox).not.toBeChecked();
  // click, not check(): the popup closes itself before check() could see the box ticked.
  const reloaded = site.waitForEvent("load", { timeout: 15_000 });
  const closed = popup.waitForEvent("close", { timeout: 15_000 });
  await checkbox.click();
  await Promise.all([reloaded, closed]);
  await expectShim(site, true);
});
