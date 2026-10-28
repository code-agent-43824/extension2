// CryptoPro's own demo page (cades_bes_sample.html), served locally from vendor/, with our extension
// in place of CryptoPro's extension, plug-in and CSP.
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { X509Certificate } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { packageVersion } from "../../scripts/build.ts";
import { repoRoot, vendorDir } from "../../scripts/fetch-vendor.ts";
import { caDir } from "../../scripts/provision-token.ts";
import { stand, standDir, userPin } from "../../scripts/setup-stand.ts";
import {
  addRoots,
  clearSites,
  directoryRoutes,
  enableSite,
  launchStand,
  openStandPage,
  servePages,
  standExtension,
  type PageServer,
} from "./harness.ts";
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
  await dialog.locator("button[name=confirm]").click();
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
    context = await launchStand({ extensions: [stand.adapter, standExtension()] });
    await clearSites(context);
    await enableSite(context, server.url);
    // The stand's CA as a root of the extension's store, as item 11 of docs/MANUAL-CHECK.md has the user add theirs:
    // tools/check-api.js verifies what it signs.
    await addRoots(context, [{ name: "stand-ca.pem", buffer: readFileSync(join(caDir, "ca.pem")) }]);
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

  test("raises no errors in the page while it loads and lists the certificate", async () => {
    // Errors are listened to from the second load on: the first waits for the Rutoken adapter (openStandPage).
    const page = await openStandPage(context, server.url + demoPath);
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    await page.reload();
    await expectText(page, "CertificatesCountTxt", "Сертификаты My:1, Cont:0");
    await expectText(page, "ObjectsLoadedTxt", "Перечисление объектов плагина завершено");
    expect(errors).toEqual([]);
    await page.close();
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

  test("tools/dump-fields.js reads the plug-in and the token certificate through the extension", async () => {
    const x509 = new X509Certificate(readFileSync(join(standDir, "user.pem")));
    const page = await openStandPage(context, server.url + demoPath);
    const dump = JSON.parse(await page.evaluate(readFileSync(join(repoRoot, "tools", "dump-fields.js"), "utf8")));
    expect(dump.about).toMatchObject({ PluginVersion: "2.0.15000", CSPVersion: "5.0.13000", CSPName: "Rutoken Plugin 4.12.3.0" });
    expect(dump.certificates).toHaveLength(1);
    const thumbprint = x509.fingerprint.replaceAll(":", "");
    expect(dump.certificates[0]).toMatchObject({
      Thumbprint: thumbprint,
      SubjectName: expect.stringContaining("CN=Stand User"),
      IsValid: true,
      GetInfo: { SUBJECT_SIMPLE_NAME: "Stand User", ISSUER_SIMPLE_NAME: "Stand Test CA", SUBJECT_UPN: "" },
      KeyUsage: { IsPresent: true, IsCritical: true, IsDigitalSignatureEnabled: true, IsKeyCertSignEnabled: false },
      ExtendedKeyUsage: {
        IsPresent: true,
        EKUs: [
          { Name: 2, OID: "1.3.6.1.5.5.7.3.2" },
          { Name: 4, OID: "1.3.6.1.5.5.7.3.4" },
        ],
      },
      BasicConstraints: { IsPresent: false },
      PublicKey: { Algorithm: "1.2.643.7.1.1.1.1", Length: 512, EncodedKey: expect.stringMatching(/^BE/) },
    });
    // Every value was read: no property of the 1.14.0 objects answered with an error.
    expect(JSON.stringify(dump.certificates[0].Extensions)).not.toContain('"error"');
    expect(dump.certificates[0].Extensions.map((e: { OID: string }) => e.OID)).toEqual(["2.5.29.15", "2.5.29.37", "2.5.29.16"]);
    expect(dump.find).toEqual({
      "ROOT_NAME Stand Test CA": [thumbprint],
      "EXTENSION 2.5.29.15": [thumbprint],
      "EXTENSION CAPICOM_OID_KEY_USAGE_EXTENSION": [thumbprint],
      "APPLICATION_POLICY 1.3.6.1.5.5.7.3.2": [thumbprint],
      "APPLICATION_POLICY 1.3.6.1.5.5.7.3.4": [thumbprint],
      "CERTIFICATE_POLICY 1.2.643.100.113.1": [],
      "KEY_USAGE CAPICOM_DIGITAL_SIGNATURE_KEY_USAGE": [thumbprint],
    });
  });

  test("tools/check-api.js signs with attributes, RawSignature, the site's and the remembered PIN", async () => {
    const page = await openStandPage(context, server.url + demoPath);
    const script = readFileSync(join(repoRoot, "tools", "check-api.js"), "utf8").replace('const PIN = "";', `const PIN = ${JSON.stringify(userPin)};`);
    let done = false;
    const run = page.evaluate(script).finally(() => (done = true));
    // What each PIN window said, in order; a window without the field only needs the click.
    const windows: string[] = [];
    while (!done) {
      const dialog = pinDialog(page);
      if (await dialog.isVisible().catch(() => false)) {
        windows.push((await dialog.innerText()).replace(/\s+/g, " "));
        const field = dialog.locator("input[name=pin]");
        if (await field.isVisible()) await field.fill(userPin);
        await dialog.locator("button[name=confirm]").click();
        await dialog.waitFor({ state: "detached" });
      }
      await page.waitForTimeout(100);
    }
    const result = JSON.parse((await run) as string);
    const thumbprint = new X509Certificate(readFileSync(join(standDir, "user.pem"))).fingerprint.replaceAll(":", "");
    expect(result.error).toBeUndefined();
    expect(result.hasPrivateKeyBefore).toEqual({ [thumbprint]: true });
    expect(result.hasPrivateKeyAfter).toEqual({ [thumbprint]: true });
    expect(result.attributes).toMatchObject({
      verified: true,
      certificatesInSignature: 1,
      attributes: expect.arrayContaining([
        { Name: 1, OID: "1.3.6.1.4.1.311.88.2.1", Value: "Документ.txt" },
        { Name: 2, OID: "1.3.6.1.4.1.311.88.2.2", Value: "Проверка атрибутов" },
      ]),
    });
    expect(verifyCms(result.attributes.signature).checks).toEqual({
      message_digest: true,
      signature: true,
      certificate_by_ca: true,
      cades_bes_attributes: true,
    });
    expect(result.rawSignature).toMatchObject({ verified: true, tampered: { error: expect.stringContaining("0x80090006") } });
    expect(result.rawSignature.signature).toMatch(/^[0-9a-f]{2}( [0-9a-f]{2}){63}$/i);
    expect(result.keyPin).toEqual({ signed: true });
    expect(result.cachePin).toEqual({ CachePin: true, first: true, second: true, afterCacheKeyFalse: false });
    // Attributes, RawSignature, KeyPin, then the two CachePin signatures.
    expect(windows).toHaveLength(5);
    expect(windows[1]).toContain("просит подписать хеш данных.");
    expect(windows[2]).toContain("PIN-код Рутокена передал сайт.");
    expect(windows[4]).toContain("PIN-код запомнен до закрытия страницы.");
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
    // The page's own attributes are in the signature (docs/PLAN.md, action 35c): its signing time and the document name.
    expect(report.attributes).toContain("1.3.6.1.4.1.311.88.2.1");
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
    context = await launchStand({ extensions: [standExtension()], profile });
    await enableSite(context, server.url);
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
