// Certificate's CAPICOM methods and the Find criteria on the stand's token certificate (docs/PLAN.md, action 35d), and
// Display()'s window on the page.
import { expect, test, type BrowserContext } from "@playwright/test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { caDir } from "../../scripts/provision-token.ts";
import { stand, standDir } from "../../scripts/setup-stand.ts";
import { addRoots, blankPage, clearSites, enableSite, launchStand, openStandPage, servePages, standExtension, type PageServer } from "./harness.ts";

let server: PageServer;
let context: BrowserContext;

test.beforeAll(async () => {
  server = await servePages({ "/": blankPage });
  context = await launchStand({ extensions: [stand.adapter, standExtension()] });
  await clearSites(context);
  await enableSite(context, server.url);
  await addRoots(context, [{ name: "stand-ca.pem", buffer: readFileSync(join(caDir, "ca.pem")) }]);
});

test.afterAll(async () => {
  await context?.close();
  await server?.close();
});

test("the token certificate's names, usages and extensions, Find by root and extension, and Display's window", async () => {
  const page = await openStandPage(context, `${server.url}/`);
  const facts = await page.evaluate(async () => {
    const cadesplugin = (window as unknown as { cadesplugin: any }).cadesplugin;
    await cadesplugin;
    const store = await cadesplugin.CreateObjectAsync("CAdESCOM.Store");
    await store.Open();
    const certificates = await store.Certificates;
    const certificate = await certificates.Item(1);
    const usage = await certificate.KeyUsage();
    const ekus = await (await certificate.ExtendedKeyUsage()).EKUs;
    const count = async (type: number, criteria: unknown) => (await certificates.Find(type, criteria)).Count;
    return {
      simple: await certificate.GetInfo(cadesplugin.CAPICOM_CERT_INFO_SUBJECT_SIMPLE_NAME),
      issuer: await certificate.GetInfo(cadesplugin.CAPICOM_CERT_INFO_ISSUER_SIMPLE_NAME),
      signature: await usage.IsDigitalSignatureEnabled,
      ekus: await ekus.Count,
      clientAuth: await (await ekus.Item(1)).Name,
      extensions: await (await certificate.Extensions()).Count,
      byRoot: await count(cadesplugin.CAPICOM_CERTIFICATE_FIND_ROOT_NAME, "Stand Test CA"),
      byOtherRoot: await count(cadesplugin.CAPICOM_CERTIFICATE_FIND_ROOT_NAME, "Минцифры"),
      byExtension: await count(cadesplugin.CAPICOM_CERTIFICATE_FIND_EXTENSION, cadesplugin.CAPICOM_OID_KEY_USAGE_EXTENSION),
      byPolicy: await count(cadesplugin.CAPICOM_CERTIFICATE_FIND_APPLICATION_POLICY, "1.3.6.1.5.5.7.3.2"),
      keyBytes: (await (await (await certificate.PublicKey()).EncodedKey).Value()).length > 0,
    };
  });
  expect(facts).toEqual({
    simple: "Stand User",
    issuer: "Stand Test CA",
    signature: 1,
    ekus: 2,
    clientAuth: 2,
    extensions: 3,
    byRoot: 1,
    byOtherRoot: 0,
    byExtension: 1,
    byPolicy: 1,
    keyBytes: true,
  });

  await page.evaluate(() => {
    const w = window as unknown as { displayed?: boolean; cadesplugin: any };
    void (async () => {
      const store = await w.cadesplugin.CreateObjectAsync("CAdESCOM.Store");
      await store.Open();
      await (await (await store.Certificates).Item(1)).Display();
      w.displayed = true;
    })();
  });
  const dialog = page.locator("#rutoken-cades-bridge-certificate [role=dialog]");
  await expect(dialog).toContainText("Кому выдан");
  await expect(dialog).toContainText("Stand User");
  await expect(dialog).toContainText("Цифровая подпись");
  await page.screenshot({ path: join(standDir, "certificate-display.png") });
  expect(await page.evaluate(() => "displayed" in window)).toBe(false);
  await dialog.locator("button[name=confirm]").click();
  await page.waitForFunction(() => "displayed" in window);
  await expect(dialog).toHaveCount(0);
});
