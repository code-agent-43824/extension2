// CryptoPro's own demo page (cades_bes_sample.html), served locally from vendor/, with our extension
// in place of CryptoPro's extension, plug-in and CSP.
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { X509Certificate } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { extensionDir, packageVersion } from "../../scripts/build.ts";
import { vendorDir } from "../../scripts/fetch-vendor.ts";
import { stand, standDir, userPin } from "../../scripts/setup-stand.ts";
import { directoryRoutes, launchStand, openStandPage, servePages, type PageServer } from "./harness.ts";
import { verifyCms } from "./verify.ts";

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

// Our PIN window; Playwright's CSS locators reach into its open shadow root.
const pinDialog = (page: Page) => page.locator("#rutoken-cades-bridge-pin [role=dialog]");

async function enterPin(page: Page, pin: string) {
  const dialog = pinDialog(page);
  await dialog.locator("input[name=pin]").fill(pin);
  await dialog.locator("button[name=sign]").click();
}

async function demoPageWithCertificate(context: BrowserContext): Promise<Page> {
  const page = await openStandPage(context, server.url + demoPath);
  await expectText(page, "CertificatesCountTxt", "Сертификаты My:1, Cont:0");
  await page.locator("#CertListBox").selectOption({ index: 0 });
  return page;
}

// What the page shows after "Подписать": the title and the signature (or the error text).
async function signatureResult(page: Page, title: string): Promise<string> {
  await expect(page.locator("[name=SignatureTitle]")).toHaveText(title, { timeout: 30_000 });
  await expect(pinDialog(page)).toHaveCount(0);
  return (await page.locator("#SignatureTxtBox").inputValue()).trim();
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

  test("lists the token certificate and shows its card", async () => {
    // The page prints names as they come, "CN=" included. Checked against Node's own parsing of the certificate the stand put on the token.
    const x509 = new X509Certificate(readFileSync(join(standDir, "user.pem")));
    const page = await openStandPage(context, server.url + demoPath);
    await expectText(page, "ObjectsLoadedTxt", "Перечисление объектов плагина завершено");
    await expectText(page, "CertificatesCountTxt", "Сертификаты My:1, Cont:0");
    const list = page.locator("#CertListBox");
    await expect(list.locator("option")).toHaveCount(1);
    await expect(list.locator("option")).toContainText("CN=Stand User; Выдан: ");
    await list.selectOption({ index: 0 });
    await expectText(page, "subject", "Владелец: CN=Stand User");
    await expectText(page, "issuer", "Издатель: CN=Stand Test CA");
    await expectText(page, "thumbprint", `Отпечаток: ${x509.fingerprint.replaceAll(":", "")}`);
    await expectText(page, "algorithm", "Алгоритм ключа: ГОСТ Р 34.10-2012 256 бит");
    await expectText(page, "provname", "Криптопровайдер: Rutoken Plugin 4.12.3.0");
    await expectText(page, "privateKeyLink", /^Ссылка на закрытый ключ: \\\\\.\\Rutoken \d+\\[0-9a-f:]+$/);
    await expectText(page, "status", "Статус: Действителен");
    await expectText(page, "location", "Установлен в хранилище: Да");
    await expect(page.locator("#pkupInfo")).toContainText("Срок действия ключа (2.5.29.16) до:");
    const from = new Date(x509.validFrom).toISOString().replace(/^(\d+)-(\d+)-(\d+)T([\d:]+).*$/, "$3.$2.$1 $4");
    await expectText(page, "from", `Выдан: ${from} UTC`);
  });

  test("signs Hello World with an attached CAdES-BES signature that verifies", async () => {
    const page = await demoPageWithCertificate(context);
    await page.locator("#SignBtn").click();
    const dialog = pinDialog(page);
    await expect(dialog).toContainText(new URL(server.url).origin);
    await expect(dialog).toContainText("Stand User");
    await expect(dialog).toContainText("11 байт, присоединённая подпись.");
    await enterPin(page, userPin);
    const report = verifyCms(await signatureResult(page, "Подпись сформирована успешно:"));
    expect(report.checks).toEqual({ message_digest: true, signature: true, certificate_by_ca: true, cades_bes_attributes: true });
    expect(report.detached).toBe(false);
    expect(report.signing_time).toBeTruthy();
  });

  test("signs detached, checking the certificate, and the signature verifies against Hello World", async () => {
    const page = await demoPageWithCertificate(context);
    await page.locator("#chkDetached").check();
    await page.locator("#chkCheckCertificate").check();
    await page.locator("#SignBtn").click();
    await enterPin(page, userPin);
    const signature = await signatureResult(page, "Подпись сформирована успешно:");
    const report = verifyCms(signature, Buffer.from("Hello World"));
    expect(report.detached).toBe(true);
    expect(report.valid).toBe(true);
    expect(verifyCms(signature, Buffer.from("Hello World!")).checks.message_digest).toBe(false);
  });

  test("asks again after a wrong PIN, and asks for the PIN on every signature", async () => {
    const page = await demoPageWithCertificate(context);
    await page.locator("#SignBtn").click();
    await enterPin(page, "00000000");
    await expect(pinDialog(page).locator("[role=alert]")).toHaveText(/Неверный PIN-код/, { timeout: 30_000 });
    await enterPin(page, userPin);
    expect(verifyCms(await signatureResult(page, "Подпись сформирована успешно:")).valid).toBe(true);
    // The shim logged out after signing, so a second signature needs the PIN again.
    await page.locator("#SignBtn").click();
    await expect(pinDialog(page)).toBeVisible();
    await enterPin(page, userPin);
    expect(verifyCms(await signatureResult(page, "Подпись сформирована успешно:")).valid).toBe(true);
  });

  test("reports cancellation the way CryptoPro does", async () => {
    const page = await demoPageWithCertificate(context);
    await page.locator("#SignBtn").click();
    await pinDialog(page).locator("button[name=cancel]").click();
    expect(await signatureResult(page, "Возникла ошибка:")).toBe(
      "Не удалось создать подпись из-за ошибки: Действие было отменено пользователем. (0x8010006E)",
    );
  });

  test("signs a string as UTF-16LE when the site sets no encoding, as CryptoPro does", async () => {
    const page = await demoPageWithCertificate(context);
    const signing = page.evaluate(async () => {
      const plugin = (window as unknown as { cadesplugin: Record<string, (...args: unknown[]) => Promise<any>> }).cadesplugin;
      const store = await plugin.CreateObjectAsync!("CAdESCOM.Store");
      await store.Open();
      const certificate = await (await store.Certificates).Item(1);
      const signer = await plugin.CreateObjectAsync!("CAdESCOM.CPSigner");
      await signer.propset_Certificate(certificate);
      const data = await plugin.CreateObjectAsync!("CAdESCOM.CadesSignedData");
      await data.propset_Content("Привет, мир");
      return (await data.SignCades(signer, 1, true)) as string;
    });
    await enterPin(page, userPin);
    const report = verifyCms(await signing, Buffer.from("Привет, мир", "utf16le"));
    expect(report.valid).toBe(true);
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
