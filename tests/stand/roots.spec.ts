/// <reference types="chrome" />
// The root certificate store (docs/PLAN.md of stage 5, actions 12 and 13): on the options page, the built-in
// roots as cards, switched one by one, all at once and as a whole store, removed and added from DER and PEM
// files; on an enabled site, the enabled ones as CryptoPro's Root store.
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { repoRoot } from "../../scripts/fetch-vendor.ts";
import { standDir } from "../../scripts/setup-stand.ts";
import { BUILTIN_ROOTS } from "../../src/extension/builtin-roots.ts";
import { base64ToDer } from "../../src/extension/roots.ts";
import { parseCertificate } from "../../src/page/x509.ts";
import { stand } from "../../scripts/setup-stand.ts";
import { clearSites, enableSite, extensionOrigin, launchStand, openStandPage, servePages, standExtension, type PageServer } from "./harness.ts";

const outDir = join(standDir, "roots");
const headCa = "8CAE88BBFD404A7A53630864F9033606E1DC45E2";
const headCaDer = base64ToDer(BUILTIN_ROOTS.find((der) => parseCertificate(base64ToDer(der)).thumbprint === headCa)!);
const caPem = readFileSync(join(repoRoot, "tests", "fixtures", "stand-ca.pem"));

let context: BrowserContext;
let server: PageServer;

test.beforeAll(async () => {
  mkdirSync(outDir, { recursive: true });
  server = await servePages({ "/": { type: "text/html; charset=utf-8", body: Buffer.from("<!doctype html><title>roots</title>") } });
  context = await launchStand({ extensions: [stand.adapter, standExtension()] });
});

test.afterAll(async () => {
  await context?.close();
  await server?.close();
});

test.beforeEach(async () => {
  await clearSites(context);
});

async function optionsPage(): Promise<Page> {
  const page = await context.newPage();
  await page.goto(`${await extensionOrigin(context)}/options.html`);
  await expect(page.locator("#roots li")).not.toHaveCount(0);
  return page;
}

const cards = (page: Page) => page.locator("#roots li");
const cardOf = (page: Page, thumbprint: string) => page.locator(`#roots li[data-thumbprint="${thumbprint}"]`);
const count = (page: Page) => page.locator("#roots-count");

test("the store starts with CryptoPro's root certificates, each on its own card", async () => {
  const page = await optionsPage();
  await expect(cards(page)).toHaveCount(BUILTIN_ROOTS.length);
  await expect(count(page)).toHaveText(`Включено ${BUILTIN_ROOTS.length} из ${BUILTIN_ROOTS.length}`);
  await expect(page.locator("input[name=roots-enabled]")).toBeChecked();
  const card = cardOf(page, headCa);
  await expect(card.locator("h2")).toContainText("Головной удостоверяющий центр");
  await expect(card.locator("h2")).toContainText("встроенный");
  await expect(card).toContainText("самоподписанный");
  await expect(card).toContainText("с 20.07.2012 по 17.07.2027");
  await expect(card).toContainText("ГОСТ Р 34.10-2001");
  await expect(card.locator("input[name=enabled]")).toBeChecked();
  await page.screenshot({ path: join(outDir, "roots.png"), fullPage: true });
});

test("certificates switch one by one and all at once, the store as a whole, and it stays so", async () => {
  const page = await optionsPage();
  const all = BUILTIN_ROOTS.length;
  await cardOf(page, headCa).locator("input[name=enabled]").uncheck();
  await expect(count(page)).toHaveText(`Включено ${all - 1} из ${all}`);
  await page.reload();
  await expect(cardOf(page, headCa).locator("input[name=enabled]")).not.toBeChecked();
  await expect(cardOf(page, headCa)).toHaveClass(/off/);
  await page.locator("#roots-all-off").click();
  await expect(count(page)).toHaveText(`Включено 0 из ${all}`);
  await page.locator("#roots-all-on").click();
  await expect(count(page)).toHaveText(`Включено ${all} из ${all}`);
  await page.locator("input[name=roots-enabled]").uncheck();
  await expect(count(page)).toHaveText(`Включено ${all} из ${all}, хранилище выключено`);
  await page.reload();
  await expect(page.locator("input[name=roots-enabled]")).not.toBeChecked();
  await expect(page.locator("#roots")).toHaveClass(/off/);
});

test("a certificate is removed, and added back from DER, another from PEM; other files are refused", async () => {
  const page = await optionsPage();
  const all = BUILTIN_ROOTS.length;
  page.once("dialog", (dialog) => void dialog.accept());
  await cardOf(page, headCa).locator("button[name=remove]").click();
  await expect(cards(page)).toHaveCount(all - 1);
  await expect(cardOf(page, headCa)).toHaveCount(0);

  const files = page.locator("#roots-add input[name=files]");
  const submit = page.locator("#roots-add button[type=submit]");
  await files.setInputFiles([
    { name: "guc.cer", mimeType: "application/pkix-cert", buffer: Buffer.from(headCaDer) },
    { name: "stand-ca.pem", mimeType: "application/x-pem-file", buffer: caPem },
  ]);
  await submit.click();
  await expect(cards(page)).toHaveCount(all + 1);
  await expect(page.locator("#roots-message")).toContainText("guc.cer: добавлен Головной удостоверяющий центр");
  await expect(cardOf(page, headCa).locator("h2")).toContainText("встроенный");
  await expect(cards(page).last().locator("h2")).not.toContainText("встроенный");
  await expect(cards(page).last().locator("input[name=enabled]")).toBeChecked();

  await files.setInputFiles([
    { name: "again.pem", mimeType: "application/x-pem-file", buffer: caPem },
    { name: "notes.txt", mimeType: "text/plain", buffer: Buffer.from("не сертификат") },
  ]);
  await submit.click();
  await expect(page.locator("#roots-message")).toContainText("again.pem: уже есть");
  await expect(page.locator("#roots-message")).toContainText("notes.txt: файл не похож на сертификат X.509");
  await expect(cards(page)).toHaveCount(all + 1);
  await page.screenshot({ path: join(outDir, "added.png"), fullPage: true });

  // Declining the confirmation keeps the certificate.
  page.once("dialog", (dialog) => void dialog.dismiss());
  await cardOf(page, headCa).locator("button[name=remove]").click();
  await expect(cards(page)).toHaveCount(all + 1);
});

// What lkip2.nalog.ru's conditions check does (docs/JOURNAL.md): open Root, find the head CA by SHA-1.
async function rootStoreOnSite(page: Page) {
  return page.evaluate(async (thumbprint) => {
    const cadesplugin = (window as unknown as { cadesplugin: Promise<void> & { CreateObjectAsync(name: string): Promise<any> } }).cadesplugin;
    await cadesplugin;
    const store = await cadesplugin.CreateObjectAsync("CAPICOM.Store");
    await store.Open(2, "Root", 2);
    const certificates = await store.Certificates;
    const found = await certificates.Find(0, thumbprint);
    const result = { count: await certificates.Count, found: await found.Count };
    await store.Close();
    return result;
  }, headCa);
}

test("an enabled site sees the enabled certificates as CryptoPro's Root store", async () => {
  await enableSite(context, server.url);
  const site = await openStandPage(context, `${server.url}/`);
  expect(await rootStoreOnSite(site)).toEqual({ count: BUILTIN_ROOTS.length, found: 1 });

  const options = await optionsPage();
  await cardOf(options, headCa).locator("input[name=enabled]").uncheck();
  await expect(count(options)).toHaveText(`Включено ${BUILTIN_ROOTS.length - 1} из ${BUILTIN_ROOTS.length}`);
  await site.reload();
  expect(await rootStoreOnSite(site)).toEqual({ count: BUILTIN_ROOTS.length - 1, found: 0 });

  await options.locator("input[name=roots-enabled]").uncheck();
  await expect(count(options)).toContainText("хранилище выключено");
  await site.reload();
  expect(await rootStoreOnSite(site)).toEqual({ count: 0, found: 0 });
});
