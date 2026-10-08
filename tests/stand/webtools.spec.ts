// CryptoPro's webtools.html, served locally from vendor/ at its original path, with our extension in place of
// CryptoPro's (docs/PLAN.md, action 24): what the owner found failing — the readers tab, signing with the TSA
// field, encryption — and the tabs next to them. The page reports errors as notifications it keeps in localStorage.
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { vendorDir } from "../../scripts/fetch-vendor.ts";
import { stand, standDir, tokenLabel } from "../../scripts/setup-stand.ts";
import { clearSites, directoryRoutes, enableSite, launchStand, openStandPage, servePages, standExtension, type PageServer } from "./harness.ts";
import { enterPin, pinDialog } from "./testgost-certs.ts";
import { envelopedInfo, verifyCms, verifyXml } from "./verify.ts";

const webtools = "/sites/default/files/products/cades/demopage/webtools.html";
// The page's NTF_LEVEL_ERROR.
const ERROR_NOTIFICATION = 0x30;
const tokenCertificateSerial = new X509Certificate(readFileSync(join(standDir, "user.pem"))).serialNumber.toUpperCase();

let server: PageServer;
let context: BrowserContext;
let page: Page;

test.beforeAll(async () => {
  server = await servePages(directoryRoutes(join(vendorDir, "cryptopro"), "/sites/default/files"));
  context = await launchStand({ extensions: [stand.adapter, standExtension()] });
  await clearSites(context);
  await enableSite(context, server.url);
  page = await openStandPage(context, `${server.url}${webtools}`);
  await expect(page.locator("#CspEnabledTxt")).toHaveText("Криптопровайдер загружен", { timeout: 30_000 });
});

test.afterAll(async () => {
  await context?.close();
  await server?.close();
});

// The error notifications since the page loaded (it clears the saved ones on load).
async function errors(): Promise<string[]> {
  return page.evaluate((level) => {
    const saved = JSON.parse(localStorage.getItem("notifications") ?? "[]") as { level: number; message: string }[];
    return saved.filter((notification) => notification.level === level).map((notification) => notification.message);
  }, ERROR_NOTIFICATION);
}

// A tab's settings are folded under a button that covers them until it is clicked; its checkbox says which.
async function unfold(fold: string): Promise<void> {
  if (!(await page.locator(`#${fold}`).isChecked())) await page.locator(`label[for=${fold}]`).click();
}

async function withPin(button: string, result: string): Promise<string> {
  await page.locator(result).fill("");
  await page.locator(button).click();
  await expect(pinDialog(page)).toBeVisible({ timeout: 30_000 });
  await enterPin(page);
  await expect(page.locator(result)).not.toHaveValue("", { timeout: 30_000 });
  return page.locator(result).inputValue();
}

test("the readers tab shows the token, the containers tab says there are none, and nothing raises an error", async () => {
  await page.locator("#navbtnreaders").click();
  const reader = page.locator("#UlReaders li");
  await expect(reader).toHaveCount(1);
  await expect(reader).toHaveText(new RegExp(`^ ?Aktiv Rutoken ECP \\d+/${tokenLabel}/Rutoken ECP [\\d.]+ \\d+$`));
  await reader.click();
  await expect(page.locator("#readerflags")).toContainText("CARRIER_FLAG_REMOVABLE");
  await expect(page.locator("#readerconts")).toHaveText("Контейнеры: -");
  await page.locator("#navbtnconts").click();
  await expect(page.locator("#boxNoCont")).toHaveText("Контейнеры отсутствуют.");
  expect(await errors()).toEqual([]);
});

test("signs CMS with the TSA field left empty and XMLDSig, both verifying; XAdES is refused with a reason", async () => {
  await page.locator("#navbtnsign").click();
  await expect(page.locator("#SelectSignCert option")).toHaveCount(1, { timeout: 30_000 });
  await expect(page.locator("#textarea_tsa")).toHaveValue("");
  await page.locator("#textarea_sign_data").fill("Данные для подписи");
  const cms = verifyCms(await withPin("#btnSign", "#textarea_sign_signed_msg"));
  expect(cms.valid).toBe(true);
  expect(cms.detached).toBe(false);

  await unfold("collapse-main-sign");
  await page.locator("label[for=tab-sign-xml]").click();
  await page.locator("#textarea_sign_data").fill("<document>Документ</document>");
  // XAdES-BES is the page's default for XML.
  await page.locator("#textarea_sign_signed_msg").fill("");
  await page.locator("#btnSign").click();
  await expect(page.locator("#textarea_sign_signed_msg")).toHaveValue(/Попытка подписать XML: Подпись XAdES пока не поддерживается расширением \(0x80004001\)/);
  await page.locator("label:has(input[name=type-xades][value='0'])").click();
  expect(verifyXml(await withPin("#btnSign", "#textarea_sign_signed_msg")).valid).toBe(true);
  expect(await errors()).toEqual([]);
});

async function encrypt(algorithm: string, text: string): Promise<string> {
  await page.locator("#navbtnencrypt").click();
  await expect(page.locator("#SelectEncryptCert option")).toHaveCount(1, { timeout: 30_000 });
  await unfold("collapse-main-encrypt");
  await page.locator(`label[for=${algorithm}]`).click();
  await page.locator("#textarea_encrypt_plain_msg").fill(text);
  return withPin("#btnEncrypt", "#textarea_encrypt_encrypted_msg");
}

async function decrypt(message: string): Promise<string> {
  await page.locator("#navbtndecrypt").click();
  await page.locator("#textarea_encrypted_msg").fill(message);
  return withPin("#btnDecrypt", "#textarea_decrypted_msg");
}

// The page's options, and the content encryption each one gives in the CMS (GOST R 34.12-2015 in CTR-ACPKM mode).
const ciphers = [
  ["enc-2", "MAGMA", "1.2.643.7.1.1.5.1.1"],
  ["enc-3", "MAGMA_OMAC", "1.2.643.7.1.1.5.1.2"],
  ["enc-4", "KUZNYECHIK", "1.2.643.7.1.1.5.2.1"],
  ["enc-5", "KUZNYECHIK_OMAC", "1.2.643.7.1.1.5.2.2"],
] as const;

for (const [option, name, oid] of ciphers) {
  test(`encrypts with ${name} for the token's certificate and decrypts back`, async () => {
    const text = `Сообщение для шифрования (${name})`;
    const message = await encrypt(option, text);
    const info = envelopedInfo(message);
    expect(info.content_encryption).toBe(oid);
    expect(info.recipients).toEqual([expect.objectContaining({ kind: "ktri", serial: tokenCertificateSerial })]);
    expect(await decrypt(message)).toBe(text);
    expect(await errors()).toEqual([]);
  });
}

// The fake token answers the Rutoken Plugin's cmsDecrypt of GOST 28147-89 with error 147 (docs/JOURNAL.md,
// 2026-10-08): only the message itself is checked here.
test("encrypts with GOST 28147-89, the page's default, for the token's certificate", async () => {
  const info = envelopedInfo(await encrypt("enc-1", "Сообщение для шифрования (28147-89)"));
  expect(info.content_encryption).toBe("1.2.643.2.2.21");
  expect(info.recipients).toEqual([expect.objectContaining({ kind: "ktri", serial: tokenCertificateSerial })]);
});
