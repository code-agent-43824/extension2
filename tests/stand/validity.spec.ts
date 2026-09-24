// The extended certificate validity check and Store.Add (docs/PLAN.md, action 20), the way the owner met them:
// CryptoPro's demo page shows a certificate whose CA root the machine lacks as not valid, "Нет доверия к
// корневому сертификату", and its link "Установить корневой сертификат тестового УЦ" adds the root. Here the
// stand's CA plays the test CA: the link's download from testgost2012 is answered with it, offline.
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { vendorDir } from "../../scripts/fetch-vendor.ts";
import { caDir } from "../../scripts/provision-token.ts";
import { stand } from "../../scripts/setup-stand.ts";
import { clearSites, directoryRoutes, enableSite, extensionOrigin, launchStand, openStandPage, servePages, setExtendedValidity, standExtension, type PageServer } from "./harness.ts";

const demoPath = "/sites/default/files/products/cades/demopage/cades_bes_sample.html";
const caPem = readFileSync(join(caDir, "ca.pem"), "utf8");
const caThumbprint = createHash("sha1").update(Buffer.from(caPem.replace(/-----[^-]+-----|\s/g, ""), "base64")).digest("hex").toUpperCase();

let server: PageServer;
let context: BrowserContext;

test.describe.configure({ mode: "serial" });

test.beforeAll(async () => {
  server = await servePages(directoryRoutes(join(vendorDir, "cryptopro"), "/sites/default/files"));
  context = await launchStand({ extensions: [stand.adapter, standExtension()] });
  await context.route("https://testgost2012.cryptopro.ru/certsrv/certnew.cer?*", (route) =>
    route.fulfill({ status: 200, contentType: "application/pkix-cert", headers: { "access-control-allow-origin": "*" }, body: caPem }),
  );
  await clearSites(context);
  await enableSite(context, server.url);
});

test.afterAll(async () => {
  await context?.close();
  await server?.close();
});

// The demo page with the token certificate picked; its alerts are collected and accepted.
async function demoPage(): Promise<{ page: Page; alerts: string[] }> {
  const page = await openStandPage(context, server.url + demoPath);
  const alerts: string[] = [];
  page.on("dialog", (dialog) => {
    alerts.push(dialog.message());
    void dialog.accept();
  });
  await expect(page.locator("#CertListBox option")).toHaveCount(1, { timeout: 30_000 });
  await page.locator("#CertListBox").selectOption({ index: 0 });
  return { page, alerts };
}

// Clicks the demo page's link and returns the extension's confirmation window it opens.
async function installRoot(page: Page): Promise<Page> {
  const origin = await extensionOrigin(context);
  const opened = context.waitForEvent("page", (candidate) => candidate.url().startsWith(`${origin}/confirm.html`));
  // The link is among the ones the page's "show more" switch reveals.
  if (!(await page.locator("#showMoreCheckbox").isChecked())) await page.locator("label[for=showMoreCheckbox]").click();
  await page.getByText("Установить корневой сертификат тестового УЦ").click();
  const window = await opened;
  await expect(window.locator("#request")).toContainText(`Сайт ${server.url} просит добавить сертификат в хранилище «Доверенные корневые центры сертификации» (Root).`);
  await expect(window.locator("#fields")).toContainText(caThumbprint);
  return window;
}

async function extraTab(): Promise<string[]> {
  const page = await context.newPage();
  await page.goto(`${await extensionOrigin(context)}/options.html`);
  await page.locator("#tab-extra").click();
  await expect(page.locator("#extra-count")).not.toBeEmpty();
  const thumbprints = await page.locator("#extra li").evaluateAll((items) => items.map((item) => (item as HTMLElement).dataset.thumbprint ?? ""));
  await page.close();
  return thumbprints;
}

test("off, the default: the certificate is valid by its dates alone, as before", async () => {
  const { page } = await demoPage();
  await expect(page.locator("#status")).toHaveText("Статус: Действителен", { timeout: 30_000 });
});

test("on: no trusted root makes it not valid, and a refused root is not added", async () => {
  await setExtendedValidity(context, true);
  const { page, alerts } = await demoPage();
  await expect(page.locator("#status")).toContainText("Не действителен", { timeout: 30_000 });
  // The CA is in none of the extension's stores, so the chain is the certificate alone, as the plug-in shows one
  // whose issuer it cannot find (docs/JOURNAL.md, 2026-09-24).
  await expect(page.locator("#status")).toHaveText("Статус: Не действителенЦепочка для сертификата:• CN=Stand User");
  const window = await installRoot(page);
  await window.locator("button[name=cancel]").click();
  await expect.poll(() => alerts).toEqual([expect.stringMatching(/^Не удалось установить корневой сертификат тестового УЦ.*0x800704C7/s)]);
  expect(await extraTab()).not.toContain(caThumbprint);
});

test("on: the root the user lets the page add makes the certificate valid", async () => {
  const { page, alerts } = await demoPage();
  const window = await installRoot(page);
  await window.locator("button[name=install]").click();
  await expect.poll(() => alerts).toEqual(["Сертификат установлен."]);
  expect(await extraTab()).toContain(caThumbprint);
  // The page lists the certificates again; picked anew, it is valid.
  await page.locator("#CertListBox").selectOption({ index: 0 });
  await expect(page.locator("#status")).toHaveText("Статус: Действителен", { timeout: 30_000 });
  await setExtendedValidity(context, false);
});
