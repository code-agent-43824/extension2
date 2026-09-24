// CryptoPro's other demo pages the manual check goes through (docs/MANUAL-CHECK.md): signing a file
// (cades_bes_file.html), XMLDSig (cades_xmldsig_sample.html) and verifying a signature (verify.html), served
// locally from vendor/ at their original paths, with our extension in place of CryptoPro's.
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { vendorDir } from "../../scripts/fetch-vendor.ts";
import { caDir } from "../../scripts/provision-token.ts";
import { stand } from "../../scripts/setup-stand.ts";
import { addRoots, clearSites, directoryRoutes, enableSite, launchStand, openStandPage, servePages, standExtension, type PageServer } from "./harness.ts";
import { enterPin, pinDialog } from "./testgost-certs.ts";
import { verifyCms, verifyXml } from "./verify.ts";

const demoDir = "/sites/default/files/products/cades/demopage";

let server: PageServer;
let context: BrowserContext;

test.beforeAll(async () => {
  server = await servePages(directoryRoutes(join(vendorDir, "cryptopro"), "/sites/default/files"));
  context = await launchStand({ extensions: [stand.adapter, standExtension()] });
  await clearSites(context);
  await enableSite(context, server.url);
  // verify.html builds the chain to the root store: the stand's CA issued the token certificate.
  await addRoots(context, [{ name: "stand-ca.pem", buffer: readFileSync(join(caDir, "ca.pem")) }]);
});

test.afterAll(async () => {
  await context?.close();
  await server?.close();
});

// Opens a demo page and picks the token certificate; the pages report errors with alert(), which fails the test.
async function demoPage(name: string, withCertificate = true): Promise<Page> {
  const page = await openStandPage(context, `${server.url}${demoDir}/${name}`);
  page.on("dialog", (dialog) => {
    void dialog.dismiss();
    throw new Error(`${name}: alert "${dialog.message()}"`);
  });
  if (withCertificate) {
    await expect(page.locator("#CertListBox option")).toHaveCount(1, { timeout: 30_000 });
    await page.locator("#CertListBox").selectOption({ index: 0 });
  }
  return page;
}

async function sign(page: Page): Promise<string> {
  // A second signature on the same page must not be read from the first one's result.
  await page.locator("[name=SignatureTitle]").evaluate((element) => (element.innerHTML = ""));
  await page.locator("#SignBtn").click();
  await expect(pinDialog(page)).toBeVisible({ timeout: 30_000 });
  // Browsers offer saved passwords for "off", not for a one-time code.
  await expect(pinDialog(page).locator("input[name=pin]")).toHaveAttribute("autocomplete", "one-time-code");
  await enterPin(page);
  await expect(page.locator("[name=SignatureTitle]")).toHaveText("Подпись сформирована успешно:", { timeout: 30_000 });
  return (await page.locator("#SignatureTxtBox").inputValue()).trim();
}

const file = Buffer.from("Файл для подписи\n");

test("cades_bes_file.html signs a file, attached and detached, and the signatures verify", async () => {
  const page = await demoPage("cades_bes_file.html");
  await page.locator("#openFileButton").setInputFiles({ name: "document.txt", mimeType: "text/plain", buffer: file });
  const attached = verifyCms(await sign(page));
  expect(attached.valid).toBe(true);
  expect(attached.detached).toBe(false);
  await page.locator("#chkDetached").check();
  const detached = verifyCms(await sign(page), file);
  expect(detached.valid).toBe(true);
  expect(detached.detached).toBe(true);
});

test("cades_xmldsig_sample.html makes an XMLDSig signature of its sample document that verifies", async () => {
  const page = await demoPage("cades_xmldsig_sample.html");
  const report = verifyXml(await sign(page));
  expect(report.valid).toBe(true);
});

// What verify.html shows after "Проверить" for the signature in its box.
async function verifyOnPage(page: Page, signature: string): Promise<string> {
  await page.locator("#verifyResult").evaluate((element) => (element.innerHTML = ""));
  await page.locator("#VerifySignTxtBox").fill(signature);
  await page.locator("#VerifyBtn").click();
  await expect(page.locator("#verifyResult")).toContainText("Результат проверки:", { timeout: 30_000 });
  return page.locator("#verifyResult").innerText();
}

test("verify.html verifies the signatures of cades_bes_file.html, and refuses a changed one", async () => {
  const signing = await demoPage("cades_bes_file.html");
  await signing.locator("#openFileButton").setInputFiles({ name: "document.txt", mimeType: "text/plain", buffer: file });
  const attached = await sign(signing);
  await signing.locator("#chkDetached").check();
  const detached = await sign(signing);
  await signing.close();

  const page = await demoPage("verify.html", false);
  await expect(page.locator("#PluginEnabledTxt")).toHaveText("Плагин загружен", { timeout: 30_000 });
  const result = await verifyOnPage(page, attached);
  expect(result).toContain("Тип подписи: CAdES-BES");
  expect(result).toContain("Результат проверки: Подпись проверена успешно");
  expect(result).toContain("Подписанты: 1");
  expect(result).toContain("Владелец: CN=Stand User");
  expect(result).toContain("Статус сертификата: Сертификат действителен");
  expect(result).toContain("Статус подписи: Подпись проверена успешно");

  // The detached signature against the same file, then against its text typed in, then against another file.
  await page.locator("#chkDetached").check();
  await page.locator("#openFileButton").setInputFiles({ name: "document.txt", mimeType: "text/plain", buffer: file });
  await expect(page.locator("#DataToSignTxtBox")).toHaveValue(file.toString("base64"));
  expect(await verifyOnPage(page, detached)).toContain("Результат проверки: Подпись проверена успешно");
  await page.evaluate(() => (window as unknown as { clearFile: () => void }).clearFile());
  await page.locator("#DataToSignTxtBox").fill(file.toString("utf8"));
  expect(await verifyOnPage(page, detached)).toContain("Результат проверки: Подпись проверена успешно");
  await page.locator("#openFileButton").setInputFiles({ name: "other.txt", mimeType: "text/plain", buffer: Buffer.from("Другой файл\n") });
  await expect(page.locator("#DataToSignTxtBox")).not.toHaveValue(file.toString("base64"));
  expect(await verifyOnPage(page, detached)).toMatch(/Результат проверки: .*\(0x80090006\)/);
});
