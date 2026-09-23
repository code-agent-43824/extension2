// Our extension next to CryptoPro's own browser extension (the CryptoPro plug-in and CSP behind it are
// not on the stand). CryptoPro's extension puts nothing into pages by itself: the site's
// cadesplugin_api.js loads its nmcades_plugin_api.js, and returns before that when window.cadesplugin
// is already ours. So on a site enabled in our extension CryptoPro's stays out; elsewhere it works as usual.
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { join } from "node:path";
import { packageVersion } from "../../scripts/build.ts";
import { vendorDir } from "../../scripts/fetch-vendor.ts";
import { cryptoproExtensionId, stand, userPin } from "../../scripts/setup-stand.ts";
import { ADAPTER_WAIT_MS } from "../../src/page/cadesplugin.ts";
import { clearSites, directoryRoutes, disableSite, enableSite, launchStand, openStandPage, servePages, standExtension, type PageServer } from "./harness.ts";
import { verifyCms } from "./verify.ts";

const demoPath = "/sites/default/files/products/cades/demopage/cades_bes_sample.html";
const cryptoproScript = `chrome-extension://${cryptoproExtensionId}/nmcades_plugin_api.js`;

let server: PageServer;
let context: BrowserContext;

test.beforeAll(async () => {
  server = await servePages(directoryRoutes(join(vendorDir, "cryptopro"), "/sites/default/files"));
  context = await launchStand({ extensions: [stand.adapter, standExtension(), stand.cryptoproExtension] });
  await clearSites(context);
});

test.afterAll(async () => {
  await context?.close();
  await server?.close();
});

const scripts = (page: Page) => page.evaluate(() => [...document.scripts].map((script) => script.src));

// Not ours: CryptoPro's extension answers the page, which then waits for a CryptoPro plug-in the stand lacks.
async function expectCryptopro(page: Page) {
  await page.waitForLoadState("load");
  await page.waitForTimeout(ADAPTER_WAIT_MS + 2000);
  expect(await scripts(page)).toContain(cryptoproScript);
  await expect(page.locator("#ExtensionEnabledTxt")).toHaveText("Расширение загружено");
  await expect(page.locator("#PluginEnabledTxt")).toHaveText("Плагин: ожидание загрузки плагина");
}

async function expectOurs(page: Page) {
  await expect(page.locator("#PluginEnabledTxt")).toHaveText("Плагин загружен", { timeout: 30_000 });
  await expect(page.locator("#ExtVersionTxt")).toHaveText(`Версия расширения: ${packageVersion()}`);
  await expect(page.locator("#CSPNameTxt")).toHaveText("Криптопровайдер: Rutoken Plugin 4.12.3.0");
  expect(await scripts(page)).not.toContain(cryptoproScript);
}

test("a site not enabled in our extension gets CryptoPro's extension, as without us", async () => {
  await expectCryptopro(await openStandPage(context, server.url + demoPath));
});

test("on an enabled site CryptoPro's extension stays out: the page talks to us and signs through the Rutoken", async () => {
  await enableSite(context, server.url);
  const page = await openStandPage(context, server.url + demoPath);
  await expectOurs(page);
  await expect(page.locator("#CertificatesCountTxt")).toHaveText("Сертификаты My:1, Cont:0", { timeout: 30_000 });
  await page.locator("#CertListBox").selectOption({ index: 0 });
  await page.locator("#SignBtn").click();
  const dialog = page.locator("#rutoken-cades-bridge-pin [role=dialog]");
  await dialog.locator("input[name=pin]").fill(userPin);
  await dialog.locator("button[name=confirm]").click();
  await expect(page.locator("[name=SignatureTitle]")).toHaveText("Подпись сформирована успешно:", { timeout: 30_000 });
  expect(verifyCms((await page.locator("#SignatureTxtBox").inputValue()).trim()).valid).toBe(true);
  // Switched off again, the site is CryptoPro's once more.
  await disableSite(context, server.url);
  await page.reload();
  await expectCryptopro(page);
});
