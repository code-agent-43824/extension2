// Signing a hash through our extension on the stand: CAdESCOM.HashedData hashed by the Rutoken Plugin,
// CadesSignedData.SignHash signed by it, in the three ways sites call them (docs/JOURNAL.md, 2026-09-24).
// Every signature must pass the independent verifier against the data that was hashed.
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { stand } from "../../scripts/setup-stand.ts";
import { blankPage, clearSites, enableSite, launchStand, openStandPage, servePages, standExtension, type PageServer } from "./harness.ts";
import { enterPin, pinDialog } from "./testgost-certs.ts";
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

// Starts `flow` in the page with the token certificate as `certificate`, enters the PIN, returns what it returned.
async function run(page: Page, flow: string): Promise<{ signature: string; hash?: string }> {
  await page.evaluate(`void (async () => {
    try {
      await cadesplugin;
      const store = await cadesplugin.CreateObjectAsync("CAdESCOM.Store");
      await store.Open(cadesplugin.CAPICOM_CURRENT_USER_STORE, cadesplugin.CAPICOM_MY_STORE, cadesplugin.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED);
      const certificate = await (await store.Certificates).Item(1);
      window.flowResult = await (${flow})(certificate);
    } catch (e) {
      window.flowResult = { error: cadesplugin.getLastError(e) };
    }
  })()`);
  await expect(pinDialog(page)).toContainText("просит подписать хеш данных.", { timeout: 30_000 });
  await enterPin(page);
  await page.waitForFunction(() => "flowResult" in window, undefined, { timeout: 30_000 });
  const result = await page.evaluate(() => (window as unknown as { flowResult: { signature: string; hash?: string; error?: string } }).flowResult);
  expect(result.error).toBeUndefined();
  return result;
}

function expectValid(signature: string, content: Buffer) {
  const report = verifyCms(signature, content);
  expect(report.checks).toEqual({ message_digest: true, signature: true, certificate_by_ca: true, cades_bes_attributes: true });
  expect(report.detached).toBe(true);
  expect(report.valid).toBe(true);
}

test("hashes Base64 pieces and signs the hash as PKCS#7 (Честный знак)", async () => {
  const page = await openStandPage(context, `${server.url}/`);
  const content = Buffer.from(Array.from({ length: 3000 }, (_, i) => i % 251));
  const pieces = [content.subarray(0, 999), content.subarray(999, 2001), content.subarray(2001)].map((piece) => piece.toString("base64"));
  const { signature } = await run(
    page,
    `async (certificate) => {
      const hash = await cadesplugin.CreateObjectAsync("CAdESCOM.HashedData");
      await hash.propset_Algorithm(cadesplugin.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256);
      await hash.propset_DataEncoding(cadesplugin.CADESCOM_BASE64_TO_BINARY);
      for (const piece of ${JSON.stringify(pieces)}) await hash.Hash(piece);
      const signer = await cadesplugin.CreateObjectAsync("CAdESCOM.CPSigner");
      await signer.propset_Certificate(certificate);
      await signer.propset_CheckCertificate(true);
      const data = await cadesplugin.CreateObjectAsync("CAdESCOM.CadesSignedData");
      await data.propset_ContentEncoding(cadesplugin.CADESCOM_BASE64_TO_BINARY);
      return { signature: await data.SignHash(hash, signer, cadesplugin.CADESCOM_PKCS7_TYPE) };
    }`,
  );
  expectValid(signature, content);
});

test("hashes a string as UTF-16LE and signs it as CAdES-BES (Сбербанк-АСТ)", async () => {
  const page = await openStandPage(context, `${server.url}/`);
  const text = "Вход на площадку: 2026-09-24T12:00:00";
  const { signature } = await run(
    page,
    `async (certificate) => {
      const hash = await cadesplugin.CreateObjectAsync("CAdESCOM.HashedData");
      await hash.propset_DataEncoding(cadesplugin.CADESCOM_STRING_TO_UCS2LE);
      await hash.propset_Algorithm(cadesplugin.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256);
      await hash.Hash(${JSON.stringify(text)});
      const signer = await cadesplugin.CreateObjectAsync("CAdESCOM.CPSigner");
      await signer.propset_Certificate(certificate);
      await signer.propset_Options(cadesplugin.CAPICOM_CERTIFICATE_INCLUDE_WHOLE_CHAIN);
      const data = await cadesplugin.CreateObjectAsync("CAdESCOM.CadesSignedData");
      return { signature: await data.SignHash(hash, signer, cadesplugin.CADESCOM_CADES_BES) };
    }`,
  );
  expectValid(signature, Buffer.from(text, "utf16le"));
});

test("takes the hash's Value into a new HashedData and signs that (crypto-pro, Росэлторг)", async () => {
  const page = await openStandPage(context, `${server.url}/`);
  const content = Buffer.from("<document>данные</document>");
  const { signature, hash } = await run(
    page,
    `async (certificate) => {
      const hashing = await cadesplugin.CreateObjectAsync("CAdESCOM.HashedData");
      await hashing.propset_Algorithm(cadesplugin.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256);
      await hashing.propset_DataEncoding(cadesplugin.CADESCOM_BASE64_TO_BINARY);
      await hashing.Hash(${JSON.stringify(content.toString("base64"))});
      const value = await hashing.Value;
      const hash = await cadesplugin.CreateObjectAsync("CAdESCOM.HashedData");
      await hash.propset_Algorithm(cadesplugin.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256);
      await hash.SetHashValue(value);
      const signer = await cadesplugin.CreateObjectAsync("CAdESCOM.CPSigner");
      await signer.propset_Certificate(certificate);
      const data = await cadesplugin.CreateObjectAsync("CAdESCOM.CadesSignedData");
      return { signature: await data.SignHash(hash, signer, cadesplugin.CADESCOM_PKCS7_TYPE), hash: value };
    }`,
  );
  expect(hash).toMatch(/^[0-9A-F]{64}$/);
  expectValid(signature, content);
});
