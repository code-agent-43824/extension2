// XAdES-BES and XAdES-T through our extension on the stand (docs/PLAN.md, action 26): CAdESCOM.SignedXML with the
// XAdES flags on the three XML types. Every result must pass the independent verifier (tests/tools/verify_xmldsig.py
// checks the qualifying properties and the timestamp too) and the extension's own Verify. XAdES-T's timestamp comes
// from the stand's service (tsa.py) through the service worker, after the user's yes to the service in the extension's
// window; Chrome's own question that follows cannot be clicked, so the stand build has access to the services from the
// start (127.0.0.1, and CryptoPro's, reached only with STAND_ONLINE=1), and a refusal is seen with the stand's service
// named by another host, localhost.
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { join } from "node:path";
import { stand, standDir } from "../../scripts/setup-stand.ts";
import { blankPage, clearSites, enableSite, extensionOrigin, launchStand, openStandPage, servePages, standExtension, type PageServer } from "./harness.ts";
import { enterPin, pinDialog } from "./testgost-certs.ts";
import { startTsa, verifyXml, type TimestampService } from "./verify.ts";

const DS = "http://www.w3.org/2000/09/xmldsig#";
const CRYPTOPRO_TSA = "http://testca2012.cryptopro.ru/tsp/tsp.srf";
const XADES = "http://uri.etsi.org/01903/v1.3.2#";

let server: PageServer;
let context: BrowserContext;
let tsa: TimestampService;

test.beforeAll(async () => {
  server = await servePages({ "/": blankPage });
  tsa = await startTsa();
  context = await launchStand({ extensions: [stand.adapter, standExtension([`${new URL(CRYPTOPRO_TSA).origin}/*`])] });
  await clearSites(context);
  await enableSite(context, server.url);
});

test.afterAll(async () => {
  await context?.close();
  await server?.close();
  tsa?.close();
});

interface Options {
  type: "ENVELOPED" | "ENVELOPING" | "TEMPLATE";
  xades: "BES" | "T" | "X_LONG_TYPE_1";
  tsaAddress?: string;
}

// Starts signing `content` in the page with the token certificate; the result lands in window.flowResult.
async function startSigning(page: Page, content: string, { type, xades, tsaAddress }: Options): Promise<void> {
  await page.evaluate(
    ({ content, type, xades, tsaAddress }) => {
      const w = window as unknown as { cadesplugin: any; flowResult?: unknown };
      delete w.flowResult;
      void (async () => {
        const cadesplugin = w.cadesplugin;
        try {
          await cadesplugin;
          const store = await cadesplugin.CreateObjectAsync("CAdESCOM.Store");
          await store.Open(cadesplugin.CAPICOM_CURRENT_USER_STORE, cadesplugin.CAPICOM_MY_STORE, cadesplugin.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED);
          const certificate = await (await store.Certificates).Item(1);
          const signer = await cadesplugin.CreateObjectAsync("CAdESCOM.CPSigner");
          await signer.propset_Certificate(certificate);
          if (tsaAddress) await signer.propset_TSAAddress(tsaAddress);
          const xml = await cadesplugin.CreateObjectAsync("CAdESCOM.SignedXML");
          await xml.propset_Content(content);
          await xml.propset_SignatureType(cadesplugin[`CADESCOM_XML_SIGNATURE_TYPE_${type}`] | cadesplugin[`CADESCOM_XADES_${xades}`]);
          w.flowResult = { signed: await xml.Sign(signer) };
        } catch (e) {
          w.flowResult = { error: cadesplugin.getLastError(e) };
        }
      })();
    },
    { content, type, xades, tsaAddress },
  );
}

async function result(page: Page): Promise<{ signed?: string; error?: string }> {
  await page.waitForFunction(() => "flowResult" in window, undefined, { timeout: 30_000 });
  return page.evaluate(() => (window as unknown as { flowResult: { signed?: string; error?: string } }).flowResult);
}

// The extension's window asking about a timestamp service, once `start` has made the page ask for one.
async function accessWindow(start: () => Promise<void>): Promise<Page> {
  const origin = await extensionOrigin(context);
  const opened = context.waitForEvent("page", (candidate) => candidate.url().startsWith(`${origin}/tsa-access.html`));
  await start();
  return opened;
}

// Signs with the PIN; `details` are lines the PIN window must show; `allow` says yes to the timestamp service first.
async function signXades(page: Page, content: string, options: Options, details: string[] = [], allow = false): Promise<{ signed?: string; error?: string }> {
  if (allow) await (await accessWindow(() => startSigning(page, content, options))).locator("button[name=allow]").click();
  else await startSigning(page, content, options);
  await expect(pinDialog(page)).toContainText("просит подписать XML-документ.", { timeout: 30_000 });
  for (const line of details) await expect(pinDialog(page)).toContainText(line);
  await enterPin(page);
  return result(page);
}

// The extension's own Verify of the document, in the page.
async function verifyInPage(page: Page, signed: string): Promise<{ count?: number; error?: string }> {
  return page.evaluate(async (signed) => {
    const cadesplugin = (window as unknown as { cadesplugin: any }).cadesplugin;
    try {
      const xml = await cadesplugin.CreateObjectAsync("CAdESCOM.SignedXML");
      await xml.Verify(signed);
      return { count: await (await xml.Signers).Count };
    } catch (e) {
      return { error: cadesplugin.getLastError(e) };
    }
  }, signed);
}

const besChecks = {
  references: true,
  signature: true,
  certificate_by_ca: true,
  xades_target: true,
  xades_signed_properties_covered: true,
  xades_signing_time: true,
  xades_certificate_digest: true,
  xades_issuer_serial: true,
};
const timestampChecks = { timestamp_imprint: true, timestamp_signature: true, timestamp_tsa_by_ca: true };

function expectXades(signed: string | undefined, timestamp = false) {
  expect(signed).toBeDefined();
  const report = verifyXml(signed!);
  expect(report.signatures).toHaveLength(1);
  expect(report.signatures[0]!.checks).toEqual(timestamp ? { ...besChecks, ...timestampChecks } : besChecks);
  expect(report.valid).toBe(true);
  return report.signatures[0]!;
}

test("signs XAdES-BES enveloped, as webtools.html asks by default, and the extension's Verify accepts it", async () => {
  const page = await openStandPage(context, `${server.url}/`);
  const content = '<?xml version="1.0" encoding="UTF-8"?>\n<Envelope xmlns="urn:test"><Body>Привет</Body></Envelope>';
  const { signed, error } = await signXades(page, content, { type: "ENVELOPED", xades: "BES" }, ["XML-подпись XAdES-BES вложенная"]);
  expect(error).toBeUndefined();
  expect(signed).toContain(`<Object><xades:QualifyingProperties xmlns:xades="${XADES}" Target="#Signature1-`);
  expect(signed).toMatch(/<Reference Type="http:\/\/uri\.etsi\.org\/01903#SignedProperties" URI="#SignedProperties1-[0-9a-f-]+">/);
  expect(signed).toContain("<X509IssuerName>CN=Stand Test CA,O=Стенд,C=RU</X509IssuerName>");
  const report = expectXades(signed) as { xades?: { signing_time: string } };
  expect(Math.abs(Date.parse(report.xades!.signing_time) - Date.now())).toBeLessThan(5 * 60_000);
  expect(await verifyInPage(page, signed!)).toEqual({ count: 1 });
  // A changed signing time no longer verifies, in the page or outside it.
  const changed = signed!.replace(/<xades:SigningTime>\d{4}/, "<xades:SigningTime>1999");
  expect(verifyXml(changed).valid).toBe(false);
  expect((await verifyInPage(page, changed)).error).toMatch(/\(0x80090006\)$/);
});

test("signs XAdES-BES enveloping, and in a prefixed template without an Id, which gets one", async () => {
  const page = await openStandPage(context, `${server.url}/`);
  const enveloping = await signXades(page, "<r><a>1</a></r>", { type: "ENVELOPING", xades: "BES" }, ["XML-подпись XAdES-BES оборачивающая"]);
  expect(enveloping.error).toBeUndefined();
  expectXades(enveloping.signed);

  const template =
    `<root xmlns="urn:r"><x>1</x><ds:Signature xmlns:ds="${DS}"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>` +
    '<ds:SignatureMethod Algorithm="urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256"/><ds:Reference URI="">' +
    `<ds:Transforms><ds:Transform Algorithm="${DS}enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms>` +
    '<ds:DigestMethod Algorithm="urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo>' +
    "<ds:SignatureValue/></ds:Signature></root>";
  const filled = await signXades(page, template, { type: "TEMPLATE", xades: "BES" }, ["XML-подпись XAdES-BES по шаблону"]);
  expect(filled.error).toBeUndefined();
  expect(filled.signed).toMatch(/<ds:Signature xmlns:ds="[^"]+" Id="Signature1-[0-9a-f-]+">/);
  expect(filled.signed).toContain("<xades:CertDigest><ds:DigestMethod ");
  expectXades(filled.signed);
});

test("signs XAdES-T with a timestamp from the stand's service, which the independent verifier checks", async () => {
  const page = await openStandPage(context, `${server.url}/`);
  const details = ["XML-подпись XAdES-T вложенная", `Служба штампов времени: ${new URL(tsa.url).host}`];
  const { signed, error } = await signXades(page, "<doc>Документ</doc>", { type: "ENVELOPED", xades: "T", tsaAddress: tsa.url }, details, true);
  expect(error).toBeUndefined();
  expect(signed).toMatch(/<xades:UnsignedProperties><xades:UnsignedSignatureProperties><xades:SignatureTimeStamp Id="SignatureTimeStamp1-[0-9a-f-]+">/);
  expect(signed).toContain('<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><xades:EncapsulatedTimeStamp>');
  const report = expectXades(signed, true) as { timestamp?: { policy: string } };
  // The stand's service answers a request without a policy with its own.
  expect(report.timestamp?.policy).toBe("2.999.1");
  expect(await verifyInPage(page, signed!)).toEqual({ count: 1 });
  // The service is known now: no question the second time.
  const origin = await extensionOrigin(context);
  const windows = () => context.pages().filter((candidate) => candidate.url().startsWith(`${origin}/tsa-access.html`)).length;
  const before = windows();
  expect((await signXades(page, "<doc>Ещё</doc>", { type: "ENVELOPED", xades: "T", tsaAddress: tsa.url }, details)).error).toBeUndefined();
  expect(windows()).toBe(before);
});

// Over the internet: the service's certificate is not the stand CA's, so the check stops at the timestamp's own
// signature; this also shows the service worker reaching an http: address.
test("signs XAdES-T with CryptoPro's test timestamp service (online)", async () => {
  test.skip(!process.env.STAND_ONLINE, "needs the internet: set STAND_ONLINE=1");
  const page = await openStandPage(context, `${server.url}/`);
  const { signed, error } = await signXades(page, "<doc>Документ</doc>", { type: "ENVELOPING", xades: "T", tsaAddress: CRYPTOPRO_TSA }, ["Служба штампов времени: testca2012.cryptopro.ru"], true);
  expect(error).toBeUndefined();
  const report = verifyXml(signed!);
  expect(report.signatures[0]!.checks).toMatchObject({ ...besChecks, timestamp_imprint: true, timestamp_signature: true });
  expect(await verifyInPage(page, signed!)).toEqual({ count: 1 });
});

test("asks in its own window for access to a service it cannot reach yet; a no ends the signing before the PIN", async () => {
  const page = await openStandPage(context, `${server.url}/`);
  const origin = await extensionOrigin(context);
  const elsewhere = tsa.url.replace("127.0.0.1", "localhost");
  const window = await accessWindow(() => startSigning(page, "<doc/>", { type: "ENVELOPED", xades: "T", tsaAddress: elsewhere }));
  await expect(window.locator("#request")).toHaveText(`Сайт ${server.url} просит подписать XML-документ подписью XAdES-T со штампом времени службы ${elsewhere}.`);
  await expect(window.locator("#what")).toContainText(`доступ к ${new URL(elsewhere).origin}: туда уходит только хеш подписи`);
  await expect(window.locator("button[name=allow]")).toBeEnabled();
  await window.screenshot({ path: join(standDir, "tsa-access.png") });
  await window.locator("button[name=cancel]").click();
  const { signed, error } = await result(page);
  expect(signed).toBeUndefined();
  expect(error).toBe("Пользователь не разрешил обращаться к службе штампов времени. (0x800704C7)");
  await expect(pinDialog(page)).toHaveCount(0);
});

test("refuses XAdES-X Long Type 1 with a reason, and XAdES-T without an address with CryptoPro's code, before the PIN", async () => {
  const page = await openStandPage(context, `${server.url}/`);
  await startSigning(page, "<doc/>", { type: "ENVELOPED", xades: "X_LONG_TYPE_1" });
  expect((await result(page)).error).toBe("Подпись XAdES-X Long Type 1 не поддерживается расширением: доступны XAdES-BES и XAdES-T (0x80004001)");
  await startSigning(page, "<doc/>", { type: "ENVELOPED", xades: "T" });
  expect((await result(page)).error).toMatch(/\(0xC2100121\)$/);
  await expect(pinDialog(page)).toHaveCount(0);
});
