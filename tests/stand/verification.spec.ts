// Signature verification through our extension on the stand (docs/PLAN.md, action 16): VerifyCades,
// VerifyHash and SignedXML.Verify run in the page, with no PIN and no token call, the chain ending in the
// extension's root store. Signatures come from our own signing on the token and from CryptoPro's plug-in
// (tests/fixtures/verify.json); the answers expected are the real plug-in's (docs/JOURNAL.md, 2026-09-24).
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { repoRoot } from "../../scripts/fetch-vendor.ts";
import { caDir } from "../../scripts/provision-token.ts";
import { stand } from "../../scripts/setup-stand.ts";
import { addRoots, blankPage, clearSites, enableSite, launchStand, openStandPage, servePages, setRootStore, standExtension, type PageServer } from "./harness.ts";
import { enterPin, pinDialog } from "./testgost-certs.ts";

interface Fixtures {
  ca: string;
  content: string;
  cryptopro: Record<"bes" | "detached" | "pkcs7" | "hash_abc" | "xml", string>;
}

const fixtures = JSON.parse(readFileSync(join(repoRoot, "tests", "fixtures", "verify.json"), "utf8")) as Fixtures;
const pem = (base64: string) => Buffer.from(`-----BEGIN CERTIFICATE-----\n${base64.replace(/(.{64})/g, "$1\n")}\n-----END CERTIFICATE-----\n`);

let server: PageServer;
let context: BrowserContext;

test.beforeAll(async () => {
  server = await servePages({ "/": blankPage });
  context = await launchStand({ extensions: [stand.adapter, standExtension()] });
  await clearSites(context);
  await enableSite(context, server.url);
  // This stand's CA signed our token certificate; the fixtures' CA, the certificate of CryptoPro's signatures.
  // Both land on the options page's second tab, as roots of other CAs.
  await addRoots(context, [
    { name: "fixtures-ca.pem", buffer: pem(fixtures.ca) },
    { name: "stand-ca.pem", buffer: readFileSync(join(caDir, "ca.pem")) },
  ]);
});

test.afterAll(async () => {
  await context?.close();
  await server?.close();
});

type Result = Record<string, unknown> & { error?: string };

// Runs `flow` (the source of an async function of cadesplugin) in the page; with `pin`, enters the PIN it asks for.
async function inPage(page: Page, flow: string, args: unknown = null, pin = false): Promise<Result> {
  await page.evaluate(
    ([flow, args]) => {
      const w = window as unknown as { cadesplugin: any; flowResult?: unknown };
      delete w.flowResult;
      void (async () => {
        try {
          await w.cadesplugin;
          w.flowResult = await (0, eval)(flow as string)(w.cadesplugin, args);
        } catch (e) {
          w.flowResult = { error: w.cadesplugin.getLastError(e) };
        }
      })();
    },
    [flow, args] as const,
  );
  if (pin) {
    await expect(pinDialog(page)).toBeVisible({ timeout: 30_000 });
    await enterPin(page);
  }
  await page.waitForFunction(() => "flowResult" in window, undefined, { timeout: 30_000 });
  return page.evaluate(() => (window as unknown as { flowResult: Result }).flowResult);
}

// Verifies a CMS signature and reports what the real plug-in lets a site read afterwards.
const verifyCades = `async (cadesplugin, { signature, type, detached, content }) => {
  const data = await cadesplugin.CreateObjectAsync("CAdESCOM.CadesSignedData");
  if (content !== undefined) await data.propset_Content(content);
  await data.VerifyCades(signature, type, detached);
  const signer = await (await data.Signers).Item(1);
  return {
    content: await data.Content,
    subject: await (await signer.Certificate).SubjectName,
    valid: await (await signer.SignatureStatus).IsValid,
    signingTime: await signer.SigningTime,
  };
}`;

test("verifies what our extension signed on the token, and CryptoPro's signatures, without a PIN", async () => {
  const page = await openStandPage(context, `${server.url}/`);
  const signed = await inPage(
    page,
    `async (cadesplugin) => {
      const store = await cadesplugin.CreateObjectAsync("CAdESCOM.Store");
      await store.Open(cadesplugin.CAPICOM_CURRENT_USER_STORE, cadesplugin.CAPICOM_MY_STORE, cadesplugin.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED);
      const signer = await cadesplugin.CreateObjectAsync("CAdESCOM.CPSigner");
      await signer.propset_Certificate(await (await store.Certificates).Item(1));
      const data = await cadesplugin.CreateObjectAsync("CAdESCOM.CadesSignedData");
      await data.propset_Content("Документ для проверки");
      return { signature: await data.SignCades(signer, cadesplugin.CADESCOM_CADES_BES) };
    }`,
    null,
    true,
  );
  expect(signed.error).toBeUndefined();
  const ours = await inPage(page, verifyCades, { signature: signed.signature, type: 1, detached: false });
  expect(ours).toMatchObject({ content: "Документ для проверки", valid: true });
  expect(ours.subject).toContain("CN=Stand User");

  const cryptopro = await inPage(page, verifyCades, { signature: fixtures.cryptopro.bes, type: 1, detached: false });
  expect(cryptopro).toMatchObject({ content: fixtures.content, subject: "C=RU, O=Проверка, CN=КриптоПро на стенде", valid: true });
  const detached = await inPage(page, verifyCades, { signature: fixtures.cryptopro.detached, type: 65535, detached: true, content: fixtures.content });
  expect(detached.valid).toBe(true);
  const hash = await inPage(
    page,
    `async (cadesplugin, signature) => {
      const hash = await cadesplugin.CreateObjectAsync("CAdESCOM.HashedData");
      await hash.propset_Algorithm(cadesplugin.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256);
      await hash.Hash("abc");
      const data = await cadesplugin.CreateObjectAsync("CAdESCOM.CadesSignedData");
      await data.VerifyHash(hash, signature, cadesplugin.CADESCOM_CADES_BES);
      return { valid: await (await (await (await data.Signers).Item(1)).SignatureStatus).IsValid };
    }`,
    fixtures.cryptopro.hash_abc,
  );
  expect(hash).toEqual({ valid: true });
  await expect(pinDialog(page)).toHaveCount(0);
});

test("answers a changed document and a chain the root store does not end, as the real plug-in", async () => {
  const page = await openStandPage(context, `${server.url}/`);
  const changed = await inPage(page, verifyCades, { signature: fixtures.cryptopro.detached, type: 1, detached: true, content: "Привеп" });
  expect(changed.error).toMatch(/\(0x80090006\)$/);
  await setRootStore(context, false, "extra");
  try {
    const untrusted = await inPage(
      page,
      `async (cadesplugin, signature) => {
        const data = await cadesplugin.CreateObjectAsync("CAdESCOM.CadesSignedData");
        let error;
        try {
          await data.VerifyCades(signature, cadesplugin.CADESCOM_CADES_BES);
        } catch (e) {
          error = cadesplugin.getLastError(e);
        }
        return { error, valid: await (await (await (await data.Signers).Item(1)).SignatureStatus).IsValid };
      }`,
      fixtures.cryptopro.bes,
    );
    expect(untrusted.error).toMatch(/\(0x800B010A\)$/);
    expect(untrusted.valid).toBe(false);
  } finally {
    await setRootStore(context, true, "extra");
  }
});

// Verifies XML and reports the signers and the Content the real plug-in leaves.
const verifyXml = `async (cadesplugin, xml) => {
  const signed = await cadesplugin.CreateObjectAsync("CAdESCOM.SignedXML");
  let error;
  try {
    await signed.Verify(xml);
  } catch (e) {
    error = cadesplugin.getLastError(e);
  }
  const signers = await signed.Signers;
  const count = await signers.Count;
  const first = count ? await signers.Item(1) : undefined;
  return {
    error,
    count,
    valid: first && (await (await first.SignatureStatus).IsValid),
    subject: first && (await (await first.Certificate).SubjectName),
    content: await signed.Content,
  };
}`;

test("verifies XML signatures: ours, CryptoPro's, and refuses changed ones", async () => {
  const page = await openStandPage(context, `${server.url}/`);
  const signed = await inPage(
    page,
    `async (cadesplugin) => {
      const store = await cadesplugin.CreateObjectAsync("CAdESCOM.Store");
      await store.Open(cadesplugin.CAPICOM_CURRENT_USER_STORE, cadesplugin.CAPICOM_MY_STORE, cadesplugin.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED);
      const signer = await cadesplugin.CreateObjectAsync("CAdESCOM.CPSigner");
      await signer.propset_Certificate(await (await store.Certificates).Item(1));
      const xml = await cadesplugin.CreateObjectAsync("CAdESCOM.SignedXML");
      await xml.propset_Content('<Envelope xmlns="urn:test"><Body a="1">Привет</Body></Envelope>');
      await xml.propset_SignatureType(cadesplugin.CADESCOM_XML_SIGNATURE_TYPE_ENVELOPED);
      return { xml: await xml.Sign(signer) };
    }`,
    null,
    true,
  );
  expect(signed.error).toBeUndefined();
  const xml = signed.xml as string;
  const ours = await inPage(page, verifyXml, xml);
  expect(ours).toMatchObject({ error: undefined, count: 1, valid: true, content: xml });
  expect(ours.subject).toContain("CN=Stand User");

  const cryptopro = await inPage(page, verifyXml, fixtures.cryptopro.xml);
  expect(cryptopro).toMatchObject({ error: undefined, count: 1, valid: true, subject: "C=RU, O=Проверка, CN=КриптоПро на стенде" });

  const changed = await inPage(page, verifyXml, xml.replace("Привет", "Привеп"));
  expect(changed).toMatchObject({ count: 1, valid: false });
  expect(changed.error).toMatch(/\(0x80090006\)$/);
  const unsigned = await inPage(page, verifyXml, "<r/>");
  expect(unsigned.error).toMatch(/\(0x8007000D\)$/);
  const noKey = await inPage(page, verifyXml, xml.replace(/<KeyInfo>[\s\S]*<\/KeyInfo>/, ""));
  expect(noKey.error).toMatch(/\(0x800705BA\)$/);
  const notXml = await inPage(page, verifyXml, "not xml");
  expect(notXml.error).toMatch(/\(0x800705B9\)$/);
});
