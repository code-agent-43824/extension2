// CryptoPro's own demo page (cades_bes_sample.html), served locally from vendor/, with our extension
// in place of CryptoPro's extension, plug-in and CSP.
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { X509Certificate } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { extensionDir, packageVersion } from "../../scripts/build.ts";
import { vendorDir } from "../../scripts/fetch-vendor.ts";
import { stand, standDir } from "../../scripts/setup-stand.ts";
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
