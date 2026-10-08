// CryptoPro's webtools.html, served locally from vendor/ at its original path, with our extension in place of
// CryptoPro's (docs/PLAN.md, action 24): what the owner found failing — the readers tab, signing with the TSA
// field, encryption — and the tabs next to them. The page reports errors as notifications it keeps in localStorage.
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { vendorDir } from "../../scripts/fetch-vendor.ts";
import { stand, standDir, tokenLabel } from "../../scripts/setup-stand.ts";
import { clearSites, directoryRoutes, enableSite, extensionOrigin, launchStand, openStandPage, servePages, standExtension, type PageServer } from "./harness.ts";
import { enterPin, pinDialog } from "./testgost-certs.ts";
import { envelopedInfo, startTsa, verifyCms, verifyXml, type VerifyReport } from "./verify.ts";

const webtools = "/sites/default/files/products/cades/demopage/webtools.html";
// The page's NTF_LEVEL_ERROR.
const ERROR_NOTIFICATION = 0x30;
// As enveloped_info.py prints it: the number in upper-case hex, without the leading zeros Node keeps.
const tokenCertificateSerial = BigInt(`0x${new X509Certificate(readFileSync(join(standDir, "user.pem"))).serialNumber}`).toString(16).toUpperCase();

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
  // The page lists the containers as soon as it loads, and the token's keys come only after its PIN
  // (docs/PLAN.md, action 25 (e)).
  await expect(pinDialog(page)).toContainText("просит показать ключи на Рутокене.", { timeout: 30_000 });
  await enterPin(page);
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

// The token's key is CryptoPro's container \\.\<reader>\ID_<CKA_ID>; the PIN the page's own listing asked for at
// load covers the rest of the page.
test("the readers tab shows the token and its key as a container; the containers tab describes it, with no new PIN", async () => {
  await page.locator("#navbtnreaders").click();
  const reader = page.locator("#UlReaders li");
  await expect(reader).toHaveCount(1);
  await expect(reader).toHaveText(new RegExp(`^ ?Aktiv Rutoken ECP \\d+/${tokenLabel}/Rutoken ECP [\\d.]+ \\d+$`));
  await reader.click();
  await expect(page.locator("#readerflags")).toContainText("CARRIER_FLAG_REMOVABLE");
  const fqcn = /\\\\\.\\Aktiv Rutoken ECP \d+\\ID_[0-9a-f]+$/;
  await expect(page.locator("#readerconts")).toHaveText(new RegExp(`^Контейнеры: ?• ${fqcn.source}`), { timeout: 30_000 });

  await page.locator("#navbtnconts").click();
  const container = page.locator("#UlContainer li");
  await expect(container).toHaveCount(1, { timeout: 30_000 });
  await expect(container).toHaveText(new RegExp(`^ ?${fqcn.source}`));
  await container.click();
  await expect(page.locator("#name")).toHaveText(/^Name: ID_[0-9a-f]+$/);
  await expect(page.locator("#countKeys")).toHaveText("Ключей: 1");
  const info = page.locator("#additionalContInfo");
  await expect(info).toContainText("AT_KEYEXCHANGE");
  await expect(info).toContainText("0xAA46 (DH 34.10-2012 256, Exchange, 512bit)");
  await expect(info).toContainText("Сертификат в контейнере: true");
  // The page shows the serial number as the certificate writes it, perhaps with a leading zero.
  await expect(info).toContainText(tokenCertificateSerial);
  await expect(pinDialog(page)).toHaveCount(0);
  expect(await errors()).toEqual([]);
});

test("signs CMS with the TSA field left empty, and XML as XAdES-BES, the page's default, and XMLDSig, all verifying", async () => {
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
  const xades = await withPin("#btnSign", "#textarea_sign_signed_msg");
  expect(xades).toContain("<xades:SignedProperties Id=");
  const report = verifyXml(xades);
  expect(report.signatures[0]!.checks).toMatchObject({ xades_signed_properties_covered: true, xades_certificate_digest: true, xades_issuer_serial: true });
  expect(report.valid).toBe(true);
  await page.locator("label:has(input[name=type-xades][value='0'])").click();
  try {
    const xmldsig = await withPin("#btnSign", "#textarea_sign_signed_msg");
    expect(xmldsig).not.toContain("xades");
    expect(verifyXml(xmldsig).valid).toBe(true);
  } finally {
    await page.locator("label:has(input[name=type-xades][value='32'])").click();
  }
  expect(await errors()).toEqual([]);
});

// XAdES-T with the TSA field filled in (docs/PLAN.md, action 26): the user says yes to the stand's service in the
// extension's window (Chrome itself does not ask: the stand build has access to 127.0.0.1), the service worker asks
// the service; the page's own verification tab takes the result.
test("signs XAdES-T with the stand's timestamp service in the TSA field and verifies it on the page's verification tab", async () => {
  const tsa = await startTsa();
  await page.locator("#navbtnsign").click();
  await expect(page.locator("#SelectSignCert option")).toHaveCount(1, { timeout: 30_000 });
  await unfold("collapse-main-sign");
  await page.locator("label[for=tab-sign-xml]").click();
  await page.locator("label:has(input[name=type-xades][value='80'])").click();
  let signed: string;
  try {
    await page.locator("#textarea_tsa").fill(tsa.url);
    await page.locator("#textarea_sign_data").fill("<document>Документ со штампом</document>");
    await page.locator("#textarea_sign_signed_msg").fill("");
    const origin = await extensionOrigin(context);
    const window = context.waitForEvent("page", (candidate) => candidate.url().startsWith(`${origin}/tsa-access.html`));
    await page.locator("#btnSign").click();
    await (await window).locator("button[name=allow]").click();
    await expect(pinDialog(page)).toContainText(`Служба штампов времени: ${new URL(tsa.url).host}`, { timeout: 30_000 });
    await enterPin(page);
    await expect(page.locator("#textarea_sign_signed_msg")).not.toHaveValue("", { timeout: 60_000 });
    signed = await page.locator("#textarea_sign_signed_msg").inputValue();
  } finally {
    tsa.close();
    await page.locator("#textarea_tsa").fill("");
    await page.locator("label:has(input[name=type-xades][value='32'])").click();
  }
  expect(signed).toContain("<xades:EncapsulatedTimeStamp>");
  const report = verifyXml(signed);
  expect(report.signatures[0]!.checks).toMatchObject({ timestamp_imprint: true, timestamp_signature: true, timestamp_tsa_by_ca: true });
  expect(report.valid).toBe(true);

  await page.locator("#navbtnverify").click();
  await page.locator("#textarea_verify_signed_msg").fill(signed);
  await page.locator("#btnVerify").click();
  // The page writes the signers over its first line, the type and result.
  await expect(page.locator("#fieldVerifyResult")).toContainText("Владелец: CN=Stand User", { timeout: 30_000 });
  await expect(page.locator("#fieldVerifyResult")).toContainText("Статус подписи: Подпись проверена успешно");
  expect(await errors()).toEqual([]);
});

test("refuses XAdES-X Long Type 1 with a reason", async () => {
  await page.locator("#navbtnsign").click();
  await unfold("collapse-main-sign");
  await page.locator("label[for=tab-sign-xml]").click();
  await page.locator("label:has(input[name=type-xades][value='1488'])").click();
  try {
    await page.locator("#textarea_sign_data").fill("<document/>");
    await page.locator("#textarea_sign_signed_msg").fill("");
    await page.locator("#btnSign").click();
    await expect(page.locator("#textarea_sign_signed_msg")).toHaveValue(
      /Попытка подписать XML: Подпись XAdES-X Long Type 1 не поддерживается расширением: доступны XAdES-BES и XAdES-T \(0x80004001\)/,
    );
  } finally {
    await page.locator("label:has(input[name=type-xades][value='32'])").click();
  }
  await expect(pinDialog(page)).toHaveCount(0);
});

const SIGNATURE_TIMESTAMP = "1.2.840.113549.1.9.16.2.14";

// CAdES-T with the TSA field filled in (docs/PLAN.md, action 25): the PIN window names the service; the page's
// settings go back to CAdES-BES and an empty field afterwards.
async function signCadesT(tsaUrl: string): Promise<VerifyReport> {
  await page.locator("#navbtnsign").click();
  await expect(page.locator("#SelectSignCert option")).toHaveCount(1, { timeout: 30_000 });
  await unfold("collapse-main-sign");
  await page.locator("label[for=tab-sign-cms]").click();
  await page.locator("label:has(input[name=type-cades][value='5'])").click();
  try {
    await page.locator("#textarea_tsa").fill(tsaUrl);
    await page.locator("#textarea_sign_data").fill("Данные для подписи со штампом времени");
    await page.locator("#textarea_sign_signed_msg").fill("");
    await page.locator("#btnSign").click();
    await expect(pinDialog(page)).toContainText(`Служба штампов времени: ${new URL(tsaUrl).host}`, { timeout: 30_000 });
    await enterPin(page);
    await expect(page.locator("#textarea_sign_signed_msg")).not.toHaveValue("", { timeout: 60_000 });
    const signature = await page.locator("#textarea_sign_signed_msg").inputValue();
    expect(signature).not.toMatch(/^Ошибка/);
    return verifyCms(signature);
  } finally {
    await page.locator("#textarea_tsa").fill("");
    await page.locator("label:has(input[name=type-cades][value='1'])").click();
  }
}

test("signs CAdES-T with the stand's timestamp service in the TSA field, the timestamp checking out", async () => {
  const tsa = await startTsa();
  try {
    const report = await signCadesT(tsa.url);
    expect(report.unsigned_attributes).toEqual([SIGNATURE_TIMESTAMP]);
    expect(report.checks).toMatchObject({ timestamp_imprint: true, timestamp_signature: true, timestamp_tsa_by_ca: true });
    expect(report.valid).toBe(true);
    expect(await errors()).toEqual([]);
  } finally {
    tsa.close();
  }
});

// CryptoPro's test timestamp service, over the internet: its certificate is not the stand CA's, so the check stops
// at the timestamp's own signature.
test("signs CAdES-T with CryptoPro's test timestamp service (online)", async () => {
  test.skip(!process.env.STAND_ONLINE, "needs the internet: set STAND_ONLINE=1");
  const report = await signCadesT("http://testca2012.cryptopro.ru/tsp/tsp.srf");
  expect(report.unsigned_attributes).toEqual([SIGNATURE_TIMESTAMP]);
  expect(report.checks).toMatchObject({ message_digest: true, signature: true, certificate_by_ca: true, timestamp_imprint: true, timestamp_signature: true });
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

// XML encryption (docs/PLAN.md, action 25): done in the page, so no PIN window; decrypting needs the token's VKO key,
// which the fake token cannot make (error 147, docs/JOURNAL.md 2026-10-08) — the whole round trip runs in
// tests/stand/enveloped-xml.spec.ts. The settings go back to CMS afterwards.
test("encrypts XML for the token's certificate without the PIN; decrypting reaches the token's key", async () => {
  await page.locator("#navbtnencrypt").click();
  await expect(page.locator("#SelectEncryptCert option")).toHaveCount(1, { timeout: 30_000 });
  await unfold("collapse-main-encrypt");
  await page.locator("label[for=enc-1]").click();
  await page.locator("label[for=enc-type-2]").click();
  try {
    await page.locator("#textarea_encrypt_plain_msg").fill('<?xml version="1.0" encoding="UTF-8"?><Документ><Текст>Секрет</Текст></Документ>');
    await page.locator("#textarea_encrypt_encrypted_msg").fill("");
    await page.locator("#btnEncrypt").click();
    await expect(page.locator("#textarea_encrypt_encrypted_msg")).not.toHaveValue("", { timeout: 30_000 });
    const encrypted = await page.locator("#textarea_encrypt_encrypted_msg").inputValue();
    expect(encrypted).toMatch(/^<\?xml version="1.0" encoding="UTF-8"\?>\n<EncryptedData xmlns="http:\/\/www.w3.org\/2001\/04\/xmlenc#" Type="http:\/\/www.w3.org\/2001\/04\/xmlenc#Element">/);
    expect(encrypted).toContain("urn:ietf:params:xml:ns:cpxmlsec:algorithms:transport-gost2012-256");
    expect(encrypted.replace(/\s+/g, "")).toContain(readFileSync(join(standDir, "user.pem"), "utf8").replace(/-----[^-]+-----|\s+/g, ""));
    await expect(pinDialog(page)).toHaveCount(0);

    await page.locator("#navbtndecrypt").click();
    await page.locator("#textarea_encrypted_msg").fill(encrypted);
    await page.locator("#textarea_decrypted_msg").fill("");
    await page.locator("#btnDecrypt").click();
    await expect(pinDialog(page)).toContainText("Зашифрованный XML-документ", { timeout: 30_000 });
    await enterPin(page);
    await expect(page.locator("#textarea_decrypted_msg")).toHaveValue(/Попытка расшифровать XML: Рутокен Плагин не расшифровал сообщение: ошибка 147 \(0x80090005\)/, { timeout: 30_000 });
    expect(await errors()).toEqual([]);
  } finally {
    await page.locator("#navbtnencrypt").click();
    await page.locator("label[for=enc-type-1]").click();
  }
});
