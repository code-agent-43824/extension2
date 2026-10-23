// The site's signed attributes and the certificate chain in a CMS signature on the stand (docs/PLAN.md, action 35c):
// with attributes the CMS is made in the page around the token's rawSign, CAdES-T then taking its timestamp through
// the extension, as XAdES-T does. The independent verifier and the extension's own verification must accept it.
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { caDir } from "../../scripts/provision-token.ts";
import { stand } from "../../scripts/setup-stand.ts";
import { addRoots, blankPage, clearSites, enableSite, extensionOrigin, launchStand, openStandPage, servePages, standExtension, type PageServer } from "./harness.ts";
import { enterPin, pinDialog } from "./testgost-certs.ts";
import { startTsa, verifyCms, type TimestampService } from "./verify.ts";

let server: PageServer;
let context: BrowserContext;
let tsa: TimestampService;

test.beforeAll(async () => {
  server = await servePages({ "/": blankPage });
  tsa = await startTsa();
  context = await launchStand({ extensions: [stand.adapter, standExtension()] });
  await clearSites(context);
  await enableSite(context, server.url);
  // The stand's CA as a root of the extension's store: the chain then reaches it.
  await addRoots(context, [{ name: "stand-ca.pem", buffer: readFileSync(join(caDir, "ca.pem")) }]);
});

test.afterAll(async () => {
  await context?.close();
  await server?.close();
  tsa?.close();
});

const DOCUMENT_NAME = "1.3.6.1.4.1.311.88.2.1";
const DOCUMENT_DESCRIPTION = "1.3.6.1.4.1.311.88.2.2";
const content = "Договор № 1";

interface Flow {
  type: "BES" | "T";
  options: "CHAIN_EXCEPT_ROOT" | "WHOLE_CHAIN";
  tsaAddress?: string;
}

// Signs `content` with a document name and description, then verifies the signature in the page: the signature, how
// many certificates it carries, and the signer's signing time.
async function startSigning(page: Page, flow: Flow): Promise<void> {
  await page.evaluate(
    ({ text, flow }) => {
      const w = window as unknown as { flowResult?: unknown; cadesplugin: any };
      delete w.flowResult;
      void (async () => {
        const cadesplugin = w.cadesplugin;
        try {
          await cadesplugin;
          const store = await cadesplugin.CreateObjectAsync("CAdESCOM.Store");
          await store.Open();
          const signer = await cadesplugin.CreateObjectAsync("CAdESCOM.CPSigner");
          await signer.propset_Certificate(await (await store.Certificates).Item(1));
          await signer.propset_Options(cadesplugin[`CAPICOM_CERTIFICATE_INCLUDE_${flow.options}`]);
          if (flow.tsaAddress) await signer.propset_TSAAddress(flow.tsaAddress);
          const attributes = await signer.AuthenticatedAttributes2;
          for (const [name, value] of [
            [cadesplugin.CADESCOM_AUTHENTICATED_ATTRIBUTE_DOCUMENT_NAME, "Договор.pdf"],
            [cadesplugin.CADESCOM_AUTHENTICATED_ATTRIBUTE_DOCUMENT_DESCRIPTION, "Договор поставки"],
          ]) {
            const attribute = await cadesplugin.CreateObjectAsync("CADESCOM.CPAttribute");
            await attribute.propset_Name(name);
            await attribute.propset_Value(value);
            await attributes.Add(attribute);
          }
          const data = await cadesplugin.CreateObjectAsync("CAdESCOM.CadesSignedData");
          await data.propset_Content(text);
          const signature = await data.SignCades(signer, cadesplugin[`CADESCOM_CADES_${flow.type}`]);
          const check = await cadesplugin.CreateObjectAsync("CAdESCOM.CadesSignedData");
          let verified: string | number;
          const read: Record<string, unknown> = {};
          try {
            await check.VerifyCades(signature, cadesplugin.CADESCOM_CADES_BES);
            verified = await (await check.Certificates).Count;
            // The signer's attributes, read back by OID.
            const attributes = await (await (await check.Signers).Item(1)).AuthenticatedAttributes2;
            for (let i = 1; i <= (await attributes.Count); i++) {
              const attribute = await attributes.Item(i);
              read[await (await attribute.OID).Value] = await attribute.Value;
            }
          } catch (e) {
            verified = cadesplugin.getLastError(e);
          }
          w.flowResult = { signature, verified, read };
        } catch (e) {
          w.flowResult = { error: cadesplugin.getLastError(e) };
        }
      })();
    },
    { text: content, flow },
  );
}

interface FlowResult {
  signature?: string;
  verified?: string | number;
  read?: Record<string, unknown>;
  error?: string;
}

async function result(page: Page): Promise<FlowResult> {
  await page.waitForFunction(() => "flowResult" in window, undefined, { timeout: 30_000 });
  return page.evaluate(() => (window as unknown as { flowResult: FlowResult }).flowResult);
}

test("CAdES-BES with the document's name and description, the chain without the root by default, whole on request", async () => {
  const page = await openStandPage(context, `${server.url}/`);
  for (const [options, count] of [
    ["CHAIN_EXCEPT_ROOT", 1],
    ["WHOLE_CHAIN", 2],
  ] as const) {
    await startSigning(page, { type: "BES", options });
    await expect(pinDialog(page)).toContainText("просит подписать данные.", { timeout: 30_000 });
    await enterPin(page);
    const { signature, verified, read, error } = await result(page);
    expect(error).toBeUndefined();
    const report = verifyCms(signature!);
    expect(report.checks).toEqual({ message_digest: true, signature: true, certificate_by_ca: true, cades_bes_attributes: true });
    expect(report.attributes).toEqual(expect.arrayContaining([DOCUMENT_NAME, DOCUMENT_DESCRIPTION]));
    expect(verified).toBe(count);
    // The verified signer gives them back (docs/PLAN.md, action 36a).
    expect(read).toMatchObject({ [DOCUMENT_NAME]: "Договор.pdf", [DOCUMENT_DESCRIPTION]: "Договор поставки" });
    expect(String(read!["1.2.840.113549.1.9.5"])).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.000Z$/);
  }
});

test("CAdES-T with the site's attributes: the timestamp comes through the extension after the user's yes", async () => {
  const page = await openStandPage(context, `${server.url}/`);
  const origin = await extensionOrigin(context);
  const opened = context.waitForEvent("page", (candidate) => candidate.url().startsWith(`${origin}/tsa-access.html`));
  await startSigning(page, { type: "T", options: "CHAIN_EXCEPT_ROOT", tsaAddress: tsa.url });
  await (await opened).locator("button[name=allow]").click();
  await expect(pinDialog(page)).toContainText(`Служба штампов времени: ${new URL(tsa.url).host}`, { timeout: 30_000 });
  await enterPin(page);
  const { signature, verified, error } = await result(page);
  expect(error).toBeUndefined();
  const report = verifyCms(signature!);
  expect(report.checks).toEqual({
    message_digest: true,
    signature: true,
    certificate_by_ca: true,
    cades_bes_attributes: true,
    timestamp_imprint: true,
    timestamp_signature: true,
    timestamp_tsa_by_ca: true,
  });
  expect(report.attributes).toEqual(expect.arrayContaining([DOCUMENT_NAME, DOCUMENT_DESCRIPTION]));
  // The extension's verification of CAdES-BES takes it: the timestamp is an unsigned attribute.
  expect(verified).toBe(1);
});
