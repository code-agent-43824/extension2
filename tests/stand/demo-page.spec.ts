// CryptoPro's own demo page (cades_bes_sample.html), served locally from vendor/, with our extension
// in place of CryptoPro's extension, plug-in and CSP.
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { extensionDir, packageVersion } from "../../scripts/build.ts";
import { vendorDir } from "../../scripts/fetch-vendor.ts";
import { stand } from "../../scripts/setup-stand.ts";
import { directoryRoutes, launchStand, openStandPage, servePages, type PageServer } from "./harness.ts";

// Same path as on www.cryptopro.ru, so the page's relative links (../cadesplugin_api.js) resolve.
const demoPath = "/sites/default/files/products/cades/demopage/cades_bes_sample.html";

let server: PageServer;

test.beforeAll(async () => {
  server = await servePages(directoryRoutes(join(vendorDir, "cryptopro"), "/sites/default/files"));
});

test.afterAll(async () => {
  await server?.close();
});

async function expectText(page: Page, id: string, text: string | RegExp) {
  await expect(page.locator(`#${id}`)).toHaveText(text, { timeout: 30_000 });
}

test.describe("with the Rutoken adapter", () => {
  let context: BrowserContext;

  test.beforeAll(async () => {
    context = await launchStand({ extensions: [stand.adapter, extensionDir] });
  });

  test.afterAll(async () => {
    await context?.close();
  });

  test("shows the plug-in and the provider as loaded", async () => {
    const page = await openStandPage(context, server.url + demoPath);
    await expectText(page, "ExtensionEnabledTxt", "Расширение загружено");
    await expectText(page, "PluginEnabledTxt", "Плагин загружен");
    await expectText(page, "CspEnabledTxt", "Криптопровайдер загружен");
    await expectText(page, "PlugInVersionTxt", "Версия плагина: 2.0.15000");
    await expectText(page, "CSPVersionTxt", "Версия криптопровайдера: 5.0.13000");
    await expectText(page, "CSPNameTxt", "Криптопровайдер: Rutoken Plugin 4.12.3.0");
    await expectText(page, "ExtVersionTxt", `Версия расширения: ${packageVersion()}`);
  });
});

test.describe("without the Rutoken adapter", () => {
  let context: BrowserContext;
  let profile: string;

  test.beforeAll(async () => {
    profile = mkdtempSync(join(tmpdir(), "stand-no-adapter-"));
    context = await launchStand({ extensions: [extensionDir], profile });
  });

  test.afterAll(async () => {
    await context?.close();
    rmSync(profile, { recursive: true, force: true });
  });

  test("reports the plug-in as unavailable, as CryptoPro does", async () => {
    const page = await context.newPage();
    await page.goto(server.url + demoPath);
    await expectText(page, "ExtensionEnabledTxt", "Расширение загружено");
    await expectText(page, "PluginEnabledTxt", "Плагин недоступен");
  });
});
