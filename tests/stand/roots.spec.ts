/// <reference types="chrome" />
// The certificate stores (docs/PLAN.md of stage 5, actions 12, 13 and 18): on the options page, the built-in
// roots as cards on their tab, switched one by one, all at once and as a whole store, and removed; on the second
// tab, roots of other CAs and intermediates added from DER and PEM files; on an enabled site, the enabled roots
// of both as CryptoPro's Root store and the intermediates as CA.
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { repoRoot } from "../../scripts/fetch-vendor.ts";
import { standDir } from "../../scripts/setup-stand.ts";
import { BUILTIN_ROOTS } from "../../src/extension/builtin-roots.ts";
import { base64ToDer } from "../../src/extension/roots.ts";
import { parseSignedData } from "../../src/page/cms.ts";
import { parseCertificate } from "../../src/page/x509.ts";
import { stand } from "../../scripts/setup-stand.ts";
import { addRoots, clearSites, enableSite, extensionOrigin, launchStand, openStandPage, servePages, setRootStore, standExtension, type PageServer } from "./harness.ts";

const outDir = join(standDir, "roots");
const headCa = "8CAE88BBFD404A7A53630864F9033606E1DC45E2";
const headCaDer = base64ToDer(BUILTIN_ROOTS.find((der) => parseCertificate(base64ToDer(der)).thumbprint === headCa)!);
const caPem = readFileSync(join(repoRoot, "tests", "fixtures", "stand-ca.pem"));
// An intermediate CA: the one a crafted signature of tests/fixtures/verify.json chains through.
const fixtures = JSON.parse(readFileSync(join(repoRoot, "tests", "fixtures", "verify.json"), "utf8")) as { crafted: Record<string, string> };
const intermediate = parseSignedData(Uint8Array.from(Buffer.from(fixtures.crafted.intermediate!, "base64"))).certificates[1]!;

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

const extraCards = (page: Page) => page.locator("#extra li");

test("a built-in root is removed and comes back from its file; other CAs' roots and intermediates go to their own tab", async () => {
  const page = await optionsPage();
  const all = BUILTIN_ROOTS.length;
  await expect(page.locator("#panel-extra")).toBeHidden();
  page.once("dialog", (dialog) => void dialog.accept());
  await cardOf(page, headCa).locator("button[name=remove]").click();
  await expect(cards(page)).toHaveCount(all - 1);
  await expect(cardOf(page, headCa)).toHaveCount(0);

  await page.locator("#tab-extra").click();
  await expect(page.locator("#panel-roots")).toBeHidden();
  await expect(page.locator("#extra-empty")).toBeVisible();
  const files = page.locator("#extra-add input[name=files]");
  const submit = page.locator("#extra-add button[type=submit]");
  await files.setInputFiles([
    { name: "guc.cer", mimeType: "application/pkix-cert", buffer: Buffer.from(headCaDer) },
    { name: "stand-ca.pem", mimeType: "application/x-pem-file", buffer: caPem },
    { name: "intermediate.cer", mimeType: "application/pkix-cert", buffer: Buffer.from(intermediate.der) },
  ]);
  await submit.click();
  const message = page.locator("#extra-message");
  await expect(message).toContainText("guc.cer: встроенный Головной удостоверяющий центр возвращён на вкладку «Корневые»");
  await expect(message).toContainText("stand-ca.pem: добавлен Stand Test CA (корневой)");
  await expect(message).toContainText("intermediate.cer: добавлен");
  await expect(message).toContainText("(промежуточный)");
  await expect(extraCards(page)).toHaveCount(2);
  await expect(extraCards(page).first().locator("h2")).toContainText("корневой");
  await expect(extraCards(page).last().locator("h2")).toContainText("промежуточный");
  await expect(extraCards(page).last().locator("input[name=enabled]")).toBeChecked();
  await expect(page.locator("#extra-count")).toHaveText("Включено 2 из 2");

  await files.setInputFiles([
    { name: "again.pem", mimeType: "application/x-pem-file", buffer: caPem },
    { name: "notes.txt", mimeType: "text/plain", buffer: Buffer.from("не сертификат") },
  ]);
  await submit.click();
  await expect(message).toContainText("again.pem: уже есть");
  await expect(message).toContainText("notes.txt: файл не похож на сертификат X.509");
  await expect(extraCards(page)).toHaveCount(2);
  await page.screenshot({ path: join(outDir, "extra.png"), fullPage: true });

  await page.locator("#tab-roots").click();
  await expect(cards(page)).toHaveCount(all);
  await expect(cardOf(page, headCa).locator("h2")).toContainText("встроенный");
  // Declining the confirmation keeps the certificate.
  page.once("dialog", (dialog) => void dialog.dismiss());
  await cardOf(page, headCa).locator("button[name=remove]").click();
  await expect(cards(page)).toHaveCount(all);
});

// What lkip2.nalog.ru's conditions check does (docs/JOURNAL.md): open Root, find the head CA by SHA-1.
async function rootStoreOnSite(page: Page, name = "Root") {
  return page.evaluate(async ({ thumbprint, name }) => {
    const cadesplugin = (window as unknown as { cadesplugin: Promise<void> & { CreateObjectAsync(name: string): Promise<any> } }).cadesplugin;
    await cadesplugin;
    const store = await cadesplugin.CreateObjectAsync("CAPICOM.Store");
    await store.Open(2, name, 2);
    const certificates = await store.Certificates;
    const found = await certificates.Find(0, thumbprint);
    const result = { count: await certificates.Count, found: await found.Count };
    await store.Close();
    return result;
  }, { thumbprint: headCa, name });
}

test("an enabled site sees the enabled roots as CryptoPro's Root store, and the intermediates as CA", async () => {
  await enableSite(context, server.url);
  const site = await openStandPage(context, `${server.url}/`);
  expect(await rootStoreOnSite(site)).toEqual({ count: BUILTIN_ROOTS.length, found: 1 });
  expect(await rootStoreOnSite(site, "CA")).toEqual({ count: 0, found: 0 });
  await addRoots(context, [
    { name: "stand-ca.pem", buffer: caPem },
    { name: "intermediate.cer", buffer: Buffer.from(intermediate.der) },
  ]);
  await site.reload();
  expect(await rootStoreOnSite(site)).toEqual({ count: BUILTIN_ROOTS.length + 1, found: 1 });
  expect(await rootStoreOnSite(site, "CA")).toEqual({ count: 1, found: 0 });
  await setRootStore(context, false, "extra");
  await site.reload();
  expect(await rootStoreOnSite(site)).toEqual({ count: BUILTIN_ROOTS.length, found: 1 });
  expect(await rootStoreOnSite(site, "CA")).toEqual({ count: 0, found: 0 });

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
