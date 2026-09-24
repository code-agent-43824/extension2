// XMLDSig through our extension on the stand: CAdESCOM.SignedXML in the three types, the way sites and
// CryptoPro's own sample call it (docs/JOURNAL.md, 2026-09-24). Every result must pass the independent
// verifier (tests/tools/verify_xmldsig.py: libxml2 canonicalization, gostcrypto signatures).
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { stand } from "../../scripts/setup-stand.ts";
import { blankPage, clearSites, enableSite, launchStand, openStandPage, servePages, standExtension, type PageServer } from "./harness.ts";
import { enterPin, pinDialog } from "./testgost-certs.ts";
import { verifyXml } from "./verify.ts";

const DS = "http://www.w3.org/2000/09/xmldsig#";

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

interface Options {
  type: "ENVELOPED" | "ENVELOPING" | "TEMPLATE";
  methods?: boolean;
  xpath?: string;
}

// Signs `content` in the page with the token certificate; `pin` false for calls that fail before the PIN.
async function signXml(page: Page, content: string, { type, methods, xpath }: Options, pin = true): Promise<{ signed?: string; error?: string }> {
  await page.evaluate(
    ({ content, type, methods, xpath }) => {
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
          const xml = await cadesplugin.CreateObjectAsync("CAdESCOM.SignedXML");
          await xml.propset_Content(content);
          await xml.propset_SignatureType(cadesplugin[`CADESCOM_XML_SIGNATURE_TYPE_${type}`]);
          if (methods) {
            // What Честный знак and the crypto-pro library do: the methods of the key, named.
            await xml.propset_SignatureMethod(cadesplugin.XmlDsigGost3410Url2012256);
            await xml.propset_DigestMethod(cadesplugin.XmlDsigGost3411Url2012256);
          }
          w.flowResult = { signed: await (xpath ? xml.Sign(signer, xpath) : xml.Sign(signer)) };
        } catch (e) {
          w.flowResult = { error: cadesplugin.getLastError(e) };
        }
      })();
    },
    { content, type, methods, xpath },
  );
  if (pin) {
    await expect(pinDialog(page)).toContainText("просит подписать XML-документ.", { timeout: 30_000 });
    await enterPin(page);
  }
  await page.waitForFunction(() => "flowResult" in window, undefined, { timeout: 30_000 });
  return page.evaluate(() => (window as unknown as { flowResult: { signed?: string; error?: string } }).flowResult);
}

function expectValid(signed: string | undefined, signatures = 1) {
  expect(signed).toBeDefined();
  const report = verifyXml(signed!);
  expect(report.signatures).toHaveLength(signatures);
  for (const signature of report.signatures) {
    expect(signature.checks).toEqual({ references: true, signature: true, certificate_by_ca: true });
  }
  expect(report.valid).toBe(true);
}

test("signs a document enveloped with the key's methods named (Честный знак, crypto-pro)", async () => {
  const page = await openStandPage(context, `${server.url}/`);
  const content = '<?xml version="1.0" encoding="UTF-8"?>\n<!-- заявка -->\n<Envelope xmlns="urn:test" xmlns:p="urn:p"><p:Body a="1" b=\'2\'>Привет &amp; <![CDATA[x<y]]></p:Body><e></e></Envelope>';
  const { signed, error } = await signXml(page, content, { type: "ENVELOPED", methods: true });
  expect(error).toBeUndefined();
  expect(signed).toMatch(/^<\?xml version="1.0" encoding="UTF-8"\?>\n<!-- заявка -->\n<Envelope /);
  expect(signed).toContain(`<Signature xmlns="${DS}" Id="Signature1-`);
  expectValid(signed);
});

test("signs enveloping with the methods of the key by default, a root without a namespace included", async () => {
  const page = await openStandPage(context, `${server.url}/`);
  const { signed, error } = await signXml(page, "<r><a>1</a></r>", { type: "ENVELOPING" });
  expect(error).toBeUndefined();
  expect(signed).toContain('<r xmlns=""><a>1</a></r></Object>');
  expect(signed).toContain('<SignatureMethod Algorithm="urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256"/>');
  expectValid(signed);
});

test("fills CryptoPro's template sample: an xml:id reference canonicalized inclusively", async () => {
  const page = await openStandPage(context, `${server.url}/`);
  // docs.cryptopro.ru, plugin-samples-sign-xml-template.
  const content =
    '<?xml version="1.0" encoding="UTF-8"?>\n<!-- \n Original XML doc file for sign example. \n-->\n<Envelope xmlns="urn:envelope">\n  <Data>\n   Hello, World!\n  </Data>\n' +
    '  <Node xml:id="nodeID">\n   Hello, Node!\n  </Node>\n  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">\n  <SignedInfo>\n' +
    '      <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>\n' +
    '      <SignatureMethod Algorithm="urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256"/>\n' +
    '      <Reference URI="#nodeID">\n      <Transforms>\n          <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>\n      </Transforms>\n' +
    '      <DigestMethod Algorithm="urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256"/>\n      <DigestValue/>\n      </Reference>\n  </SignedInfo>\n' +
    "  <SignatureValue/>\n  <KeyInfo/>\n  </Signature>\n</Envelope>";
  const { signed, error } = await signXml(page, content, { type: "TEMPLATE" });
  expect(error).toBeUndefined();
  expect(signed).toContain("<KeyInfo>\n<X509Data>\n<X509Certificate>");
  expectValid(signed);
});

test("fills a prefixed template with inclusive SignedInfo, inherited xml:lang and a new KeyInfo", async () => {
  const page = await openStandPage(context, `${server.url}/`);
  const signature = (id: string) =>
    `<ds:Signature xmlns:ds="${DS}" Id="${id}"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>` +
    '<ds:SignatureMethod Algorithm="urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256"/><ds:Reference URI="">' +
    `<ds:Transforms><ds:Transform Algorithm="${DS}enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms>` +
    '<ds:DigestMethod Algorithm="urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256"/><ds:DigestValue></ds:DigestValue></ds:Reference>' +
    "</ds:SignedInfo><ds:SignatureValue/></ds:Signature>";
  const content = `<root xmlns="urn:r" xmlns:x="urn:x" xml:lang="ru"><x:a>A</x:a>${signature("s1")}${signature("s2")}</root>`;
  const { signed, error } = await signXml(page, content, { type: "TEMPLATE", xpath: "//*[@Id='s2']" });
  expect(error).toBeUndefined();
  expect(signed).toContain("</ds:SignatureValue>\n<ds:KeyInfo>\n<ds:X509Data>");
  // Only s2 was named, so s1 stays an unfilled template the verifier skips.
  expect(signed).toContain('Id="s1"><ds:SignedInfo>');
  expectValid(signed, 1);
});

test("takes Base64 content and answers in Base64", async () => {
  const page = await openStandPage(context, `${server.url}/`);
  const content = Buffer.from('<?xml version="1.0" encoding="utf-8"?><doc>Документ</doc>').toString("base64");
  const { signed, error } = await signXml(page, content, { type: "ENVELOPED" });
  expect(error).toBeUndefined();
  const xml = Buffer.from(signed!.replace(/\n/g, ""), "base64").toString("utf8");
  expect(xml).toContain("<doc>Документ<Signature");
  expectValid(xml);
});

test("answers with the real plug-in's codes before any PIN", async () => {
  const page = await openStandPage(context, `${server.url}/`);
  expect((await signXml(page, "not xml", { type: "ENVELOPED" }, false)).error).toMatch(/\(0x800705B9\)$/);
  expect((await signXml(page, "<r/>", { type: "TEMPLATE" }, false)).error).toMatch(/\(0x80092004\)$/);
  const missing = `<r><Signature xmlns="${DS}"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256"/><Reference URI="#nope"><DigestMethod Algorithm="urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256"/><DigestValue/></Reference></SignedInfo><SignatureValue/></Signature></r>`;
  expect((await signXml(page, missing, { type: "TEMPLATE" }, false)).error).toMatch(/\(0x80070490\)$/);
  await expect(pinDialog(page)).toHaveCount(0);
});
