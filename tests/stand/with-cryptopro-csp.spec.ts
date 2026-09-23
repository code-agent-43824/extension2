// Our extension on a machine that also has the real CryptoPro CSP and CAdES Browser plug-in (docs/PLAN.md,
// action 10). Opt-in, since those are CryptoPro's licensed packages installed by hand:
// node scripts/setup-cryptopro-csp.ts DIR_WITH_DEB_FILES, then
// STAND_CRYPTOPRO_CSP=1 npx playwright test tests/stand/with-cryptopro-csp.spec.ts
// (add STAND_ONLINE=1 for the test CA's page). On a site not enabled in our extension the page works with
// CryptoPro and signs with a key in a CryptoPro file container; on an enabled one it sees only us.
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { join } from "node:path";
import { packageVersion } from "../../scripts/build.ts";
import { vendorDir } from "../../scripts/fetch-vendor.ts";
import { cryptoproCsp } from "../../scripts/setup-cryptopro-csp.ts";
import { cryptoproExtensionId, stand, userPin } from "../../scripts/setup-stand.ts";
import { clearSites, directoryRoutes, disableSite, enableSite, launchStand, openStandPage, servePages, standExtension, type PageServer } from "./harness.ts";
import { verifyCms } from "./verify.ts";

const demoPath = "/sites/default/files/products/cades/demopage/cades_bes_sample.html";
const cryptoproScript = `chrome-extension://${cryptoproExtensionId}/nmcades_plugin_api.js`;
const ca = "https://testgost2012.cryptopro.ru";
const online = Boolean(process.env.STAND_ONLINE);

test.skip(!process.env.STAND_CRYPTOPRO_CSP, "needs CryptoPro CSP and plug-in: run scripts/setup-cryptopro-csp.ts, set STAND_CRYPTOPRO_CSP=1");
test.describe.configure({ mode: "serial" });

let server: PageServer;
let context: BrowserContext;

test.beforeAll(async () => {
  server = await servePages(directoryRoutes(join(vendorDir, "cryptopro"), "/sites/default/files"), cryptoproCsp.pagePort);
  context = await launchStand({
    profile: cryptoproCsp.profile,
    online: online ? [new URL(ca).hostname] : [],
    extensions: [stand.adapter, standExtension(online ? [`${ca}/*`] : []), stand.cryptoproExtension],
  });
  await clearSites(context);
});

test.afterAll(async () => {
  await context?.close();
  await server?.close();
});

const scripts = (page: Page) => page.evaluate(() => [...document.scripts].map((script) => script.src));

async function signOnDemoPage(page: Page, commonName: string, pin?: string): Promise<string> {
  const option = page.locator("#CertListBox option", { hasText: commonName });
  await expect(option).toHaveCount(1, { timeout: 30_000 });
  await page.locator("#CertListBox").selectOption({ label: (await option.textContent())! });
  await page.locator("#SignBtn").click();
  if (pin) {
    const dialog = page.locator("#rutoken-cades-bridge-pin [role=dialog]");
    await dialog.locator("input[name=pin]").fill(pin);
    await dialog.locator("button[name=confirm]").click();
  }
  await expect(page.locator("[name=SignatureTitle]")).toHaveText("Подпись сформирована успешно:", { timeout: 30_000 });
  return (await page.locator("#SignatureTxtBox").inputValue()).trim();
}

async function expectCryptopro(page: Page) {
  await expect(page.locator("#PluginEnabledTxt")).toHaveText("Плагин загружен", { timeout: 30_000 });
  expect(await scripts(page)).toContain(cryptoproScript);
  await expect(page.locator("#CSPNameTxt")).toHaveText(/^Криптопровайдер: Crypto-Pro /);
  // Only the certificate in the CryptoPro container: the CSP looks for tokens over PC/SC and does not see the
  // fake Rutoken, which is a PKCS #11 library.
  await expect(page.locator("#CertificatesCountTxt")).toHaveText("Сертификаты My:1, Cont:0", { timeout: 30_000 });
}

test("a site not enabled in our extension works with CryptoPro and signs with a CryptoPro key", async () => {
  const page = await openStandPage(context, server.url + demoPath);
  await expectCryptopro(page);
  const report = verifyCms(await signOnDemoPage(page, cryptoproCsp.commonName));
  expect(report.checks).toEqual({ message_digest: true, signature: true, certificate_by_ca: true, cades_bes_attributes: true });
});

test("on an enabled site the page sees only us and signs through the Rutoken; switched off, CryptoPro is back", async () => {
  await enableSite(context, server.url);
  const page = await openStandPage(context, server.url + demoPath);
  await expect(page.locator("#PluginEnabledTxt")).toHaveText("Плагин загружен", { timeout: 30_000 });
  await expect(page.locator("#ExtVersionTxt")).toHaveText(`Версия расширения: ${packageVersion()}`);
  await expect(page.locator("#CSPNameTxt")).toHaveText("Криптопровайдер: Rutoken Plugin 4.12.3.0");
  expect(await scripts(page)).not.toContain(cryptoproScript);
  await expect(page.locator("#CertificatesCountTxt")).toHaveText("Сертификаты My:1, Cont:0", { timeout: 30_000 });
  await expect(page.locator("#CertListBox option", { hasText: cryptoproCsp.commonName })).toHaveCount(0);
  expect(verifyCms(await signOnDemoPage(page, "Stand User", userPin)).valid).toBe(true);
  await disableSite(context, server.url);
  await page.reload();
  await expectCryptopro(page);
});

test("the test CA's request page lists CryptoPro's providers when not enabled, ours when enabled", async () => {
  test.skip(!online, "needs the internet: set STAND_ONLINE=1");
  const providers = async () => {
    const page = await openStandPage(context, `${ca}/certsrv/certrqma.asp`);
    const options = page.locator("select[name=lbCSP] option");
    // The page shows "Загрузка..." until the plug-in has listed the providers.
    await expect(options.first()).not.toHaveText("Загрузка...", { timeout: 60_000 });
    const names = await options.allTextContents();
    await page.close();
    return names;
  };
  const theirs = await providers();
  expect(theirs.length).toBeGreaterThan(0);
  expect(theirs.every((name) => name.startsWith("Crypto-Pro "))).toBe(true);
  await enableSite(context, ca);
  expect(await providers()).toEqual(["Rutoken Plugin 4.12.3.0", "Rutoken Plugin 4.12.3.0 (ГОСТ Р 34.10-2012 512 бит)"]);
  await disableSite(context, ca);
});
