// The PIN window on the stand (docs/PLAN.md, action 35b): "remember the PIN until the page closes" leaves only a
// confirming button for the next signatures, a reload forgets the PIN, and the site's CPSigner.KeyPin needs only the
// user's yes. Every signature must pass the independent verifier.
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { stand, userPin } from "../../scripts/setup-stand.ts";
import { blankPage, clearSites, enableSite, launchStand, openStandPage, servePages, standExtension, type PageServer } from "./harness.ts";
import { pinDialog } from "./testgost-certs.ts";
import { verifyCms } from "./verify.ts";

let server: PageServer;
let context: BrowserContext;

test.beforeAll(async () => {
  server = await servePages({ "/": blankPage });
  context = await launchStand({ extensions: [stand.adapter, standExtension()] });
  await clearSites(context);
  await enableSite(context, server.url);
});

test.afterAll(async () => {
  await context?.close();
  await server?.close();
});

const content = "Подпись с запомненным PIN-кодом";

// Starts a CAdES-BES signature of `content` in the page, with the site's KeyPin when given.
async function startSigning(page: Page, keyPin?: string): Promise<void> {
  await page.evaluate(
    ([text, pin]) => {
      const win = window as unknown as { flowResult?: { signature?: string; error?: string }; cadesplugin: any };
      delete win.flowResult;
      void (async () => {
        const cadesplugin = win.cadesplugin;
        try {
          await cadesplugin;
          const store = await cadesplugin.CreateObjectAsync("CAdESCOM.Store");
          await store.Open();
          const signer = await cadesplugin.CreateObjectAsync("CAdESCOM.CPSigner");
          await signer.propset_Certificate(await (await store.Certificates).Item(1));
          if (pin) await signer.propset_KeyPin(pin);
          const data = await cadesplugin.CreateObjectAsync("CAdESCOM.CadesSignedData");
          await data.propset_Content(text);
          win.flowResult = { signature: await data.SignCades(signer, cadesplugin.CADESCOM_CADES_BES) };
        } catch (e) {
          win.flowResult = { error: cadesplugin.getLastError(e) };
        }
      })();
    },
    [content, keyPin ?? ""] as const,
  );
}

async function signature(page: Page): Promise<string> {
  await page.waitForFunction(() => "flowResult" in window, undefined, { timeout: 30_000 });
  const result = await page.evaluate(() => (window as unknown as { flowResult: { signature?: string; error?: string } }).flowResult);
  expect(result.error).toBeUndefined();
  const report = verifyCms(result.signature!);
  expect(report.valid).toBe(true);
  return result.signature!;
}

test("a ticked box leaves only the confirming button for the next signature, until the page reloads", async () => {
  const page = await openStandPage(context, `${server.url}/`);
  await startSigning(page);
  const dialog = pinDialog(page);
  await expect(dialog.locator("input[name=remember]")).not.toBeChecked({ timeout: 30_000 });
  await dialog.locator("input[name=pin]").fill(userPin);
  await dialog.locator("input[name=remember]").check();
  await dialog.locator("button[name=confirm]").click();
  await signature(page);

  await startSigning(page);
  await expect(dialog).toContainText("PIN-код запомнен до закрытия страницы.", { timeout: 30_000 });
  await expect(dialog.locator("input[name=pin]")).toBeHidden();
  await expect(dialog.locator("input[name=remember]")).toBeChecked();
  await dialog.locator("button[name=confirm]").click();
  await signature(page);

  await page.reload();
  await page.waitForFunction(() => "C3B7563B-BF85-45B7-88FC-7CFF1BD3C2DB" in window, undefined, { timeout: 15_000 });
  await startSigning(page);
  await expect(dialog.locator("input[name=pin]")).toBeVisible({ timeout: 30_000 });
  await expect(dialog.locator("input[name=remember]")).not.toBeChecked();
  await dialog.locator("button[name=cancel]").click();
  await page.waitForFunction(() => "flowResult" in window);
  expect(await page.evaluate(() => (window as unknown as { flowResult: { error?: string } }).flowResult.error)).toContain("0x8010006E");
});

test("the site's KeyPin needs only the user's yes; a wrong one brings the PIN field back", async () => {
  const page = await openStandPage(context, `${server.url}/`);
  const dialog = pinDialog(page);
  await startSigning(page, userPin);
  await expect(dialog).toContainText("PIN-код Рутокена передал сайт.", { timeout: 30_000 });
  await expect(dialog.locator("input[name=pin]")).toBeHidden();
  await expect(dialog.locator("input[name=remember]")).toBeHidden();
  await dialog.locator("button[name=confirm]").click();
  await signature(page);

  await startSigning(page, "00000000");
  await expect(dialog).toContainText("PIN-код Рутокена передал сайт.", { timeout: 30_000 });
  await dialog.locator("button[name=confirm]").click();
  await expect(dialog).toContainText("PIN-код, который передал сайт, не подошёл. Введите PIN-код.");
  await dialog.locator("input[name=pin]").fill(userPin);
  await dialog.locator("button[name=confirm]").click();
  await signature(page);
});
