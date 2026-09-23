// The owner's experiment (docs/PLAN.md, stage 5): get a certificate from CryptoPro's public test CA,
// testgost2012.cryptopro.ru, with the key made on the (fake) Rutoken through our extension, then sign
// with it on CryptoPro's demo page. Opt-in, since it needs the internet and an outside service:
// STAND_ONLINE=1 npx playwright test tests/stand/testgost.spec.ts
// It runs on a copy of the stand HOME, so the stand's own token stays as the other tests expect it.
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { cpSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { vendorDir } from "../../scripts/fetch-vendor.ts";
import { stand, standDir, userPin } from "../../scripts/setup-stand.ts";
import { clearSites, directoryRoutes, enableSite, launchStand, openStandPage, servePages, standExtension, type PageServer } from "./harness.ts";
import { verifyCms } from "./verify.ts";

const ca = "https://testgost2012.cryptopro.ru";
const demoPath = "/sites/default/files/products/cades/demopage/cades_bes_sample.html";
// What the run leaves for a look afterwards: the token copy, the CA's certificate and response, screenshots.
const outDir = join(standDir, "testgost");
const home = join(outDir, "home");
const runName = `Рутокен вместо КриптоПро ${new Date().toISOString().slice(0, 19)}`;
// One certificate per provider the page lists: GOST R 34.10-2012 with a 256-bit and a 512-bit key.
const variants = [
  { bits: 256, type: "80", keySize: "512", hash: "ГОСТ Р 34.11-2012 256 бит", commonName: `${runName} 256` },
  { bits: 512, type: "81", keySize: "1024", hash: "ГОСТ Р 34.11-2012 512 бит", commonName: `${runName} 512` },
];

test.skip(!process.env.STAND_ONLINE, "needs the internet: set STAND_ONLINE=1");
test.describe.configure({ mode: "serial" });

let server: PageServer;
let context: BrowserContext;
// The CA's certificate, downloaded from the CA's own link, not taken from anything the extension parsed.
const caPem = join(outDir, "ca.pem");

test.beforeAll(async () => {
  rmSync(outDir, { recursive: true, force: true });
  mkdirSync(outDir, { recursive: true });
  cpSync(stand.home, home, { recursive: true, verbatimSymlinks: true });
  server = await servePages(directoryRoutes(join(vendorDir, "cryptopro"), "/sites/default/files"));
  context = await launchStand({
    home,
    online: [new URL(ca).hostname],
    // CryptoPro's own extension too: both pages must still work through ours (with-cryptopro.spec.ts).
    extensions: [stand.adapter, standExtension([`${ca}/*`]), stand.cryptoproExtension],
  });
  await clearSites(context);
  await enableSite(context, ca);
  await enableSite(context, server.url);
});

test.afterAll(async () => {
  await context?.close();
  await server?.close();
});

const pinDialog = (page: Page) => page.locator("#rutoken-cades-bridge-pin [role=dialog]");

async function enterPin(page: Page) {
  const dialog = pinDialog(page);
  await dialog.locator("input[name=pin]").fill(userPin);
  await dialog.locator("button[name=confirm]").click();
}

// The CA's pages report problems with alert(); a test would otherwise dismiss them unseen.
function collectDialogs(page: Page): string[] {
  const messages: string[] = [];
  page.on("dialog", async (dialog) => {
    messages.push(`${dialog.type()}: ${dialog.message()}`);
    await dialog.accept();
  });
  return messages;
}

for (const { bits, type, keySize, hash, commonName } of variants) {
  test(`the test CA issues a certificate for a ${bits}-bit key made on the Rutoken, and it is installed there`, async () => {
    test.setTimeout(180_000);
    const page = await openStandPage(context, `${ca}/certsrv/certrqma.asp`);
    const dialogs = collectDialogs(page);
    // The page fills its provider list from CCspInformations and pre-selects type 80.
    const csp = page.locator("select[name=lbCSP]");
    await expect(csp.locator("option")).toHaveText(["Rutoken Plugin 4.12.3.0", "Rutoken Plugin 4.12.3.0 (ГОСТ Р 34.10-2012 512 бит)"], { timeout: 60_000 });
    await expect(csp).toHaveValue("80");
    await csp.selectOption(type);
    await expect(page.locator("input[name=tbKeySize]")).toHaveValue(keySize);
    await expect(page.locator("select[name=lbHashAlgorithm] option")).toHaveText([hash]);
    await page.locator("input[name=tbCommonName]").fill(commonName);
    await page.locator("input[name=tbEmail]").fill("rutoken@example.ru");
    await page.locator("input[name=tbOrg]").fill("Проверка");
    await page.locator("input[name=tbCountry]").fill("RU");
    await page.screenshot({ path: join(outDir, `${bits}-1-request-form.png`), fullPage: true });
    await page.locator("input[name=btnSubmit]").click();

    await expect(pinDialog(page)).toContainText("просит создать на Рутокене ключ и запрос на сертификат.", { timeout: 30_000 });
    await expect(pinDialog(page)).toContainText(`Владелец: ${commonName}`);
    await expect(pinDialog(page)).toContainText(`Ключ: ГОСТ Р 34.10-2012 ${bits} бит`);
    await page.screenshot({ path: join(outDir, `${bits}-2-pin-for-key.png`) });
    await enterPin(page);

    // certfnsh.asp: the CA has issued the certificate at once and offers to install it.
    await page.waitForURL(/certfnsh\.asp/i, { timeout: 60_000 });
    const install = page.locator("#locInstallCert1");
    await expect(install).toBeVisible({ timeout: 60_000 });
    writeFileSync(join(outDir, `${bits}-response.b64`), await page.evaluate(() => (window as unknown as { sPKCS7: string }).sPKCS7));
    const caLink = (await page.locator("a[href*='ReqID=CACert']").first().getAttribute("href"))!;
    const caText = await page.evaluate((href) => fetch(href).then((r) => r.text()), caLink);
    expect(caText).toContain("-----BEGIN CERTIFICATE-----");
    writeFileSync(caPem, caText);
    await page.screenshot({ path: join(outDir, `${bits}-3-issued.png`), fullPage: true });
    await install.click();

    await expect(pinDialog(page)).toContainText("просит записать сертификат на Рутокен.", { timeout: 30_000 });
    await expect(pinDialog(page)).toContainText(`Сертификат: ${commonName}`);
    await page.screenshot({ path: join(outDir, `${bits}-4-pin-for-certificate.png`) });
    await enterPin(page);
    await page.waitForURL(/certrmpn\.asp/i, { timeout: 60_000 });
    await expect(page.locator("body")).toContainText("Новый сертификат успешно установлен.");
    await page.screenshot({ path: join(outDir, `${bits}-5-installed.png`), fullPage: true });
    expect(dialogs).toEqual([]);
  });
}

for (const { bits, commonName } of variants) {
  test(`the demo page signs with the ${bits}-bit certificate, and the signature verifies against the test CA`, async () => {
    test.setTimeout(120_000);
    const page = await openStandPage(context, server.url + demoPath);
    // The stand's own certificate and the two from the test CA.
    await expect(page.locator("#CertificatesCountTxt")).toHaveText("Сертификаты My:3, Cont:0", { timeout: 30_000 });
    const option = page.locator("#CertListBox option", { hasText: commonName });
    await expect(option).toHaveCount(1);
    await page.locator("#CertListBox").selectOption({ label: (await option.textContent())! });
    await expect(page.locator("#issuer")).toContainText("Тестовый УЦ", { timeout: 30_000 });
    await expect(page.locator("#algorithm")).toHaveText(`Алгоритм ключа: ГОСТ Р 34.10-2012 ${bits} бит`);
    await page.locator("#SignBtn").click();
    await expect(pinDialog(page)).toContainText(`Сертификат: ${commonName}`, { timeout: 30_000 });
    await enterPin(page);
    await expect(page.locator("[name=SignatureTitle]")).toHaveText("Подпись сформирована успешно:", { timeout: 30_000 });
    const signature = (await page.locator("#SignatureTxtBox").inputValue()).trim();
    writeFileSync(join(outDir, `${bits}-signature.b64`), signature);
    await page.screenshot({ path: join(outDir, `${bits}-6-signed.png`), fullPage: true });
    const report = verifyCms(signature, undefined, caPem);
    expect(report.checks).toEqual({ message_digest: true, signature: true, certificate_by_ca: true, cades_bes_attributes: true });
  });
}
