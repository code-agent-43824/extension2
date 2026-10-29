// A GOST R 34.10-2012 512-bit key on the stand (docs/PLAN.md, action 37): the Rutoken Plugin makes it on a copy of the
// stand HOME (the stand's own token keeps its single certificate), the stand's CA certifies it, and the extension
// signs with it every way it signs, and decrypts on it the CMS of all five ciphers and XML encrypted for it. The
// independent tools and the extension's own verification check the results. Only the fake Rutoken.
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { X509Certificate } from "node:crypto";
import { cpSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { caDir, provisionKey, subjectAttributes } from "../../scripts/provision-token.ts";
import { stand, standDir, userPin } from "../../scripts/setup-stand.ts";
import { addRoots, blankPage, clearSites, enableSite, launchStand, openStandPage, servePages, standExtension, type PageServer } from "./harness.ts";
import { pinDialog } from "./testgost-certs.ts";
import { envelopedInfo, verifyCms, verifyRaw, verifyXml } from "./verify.ts";

const outDir = join(standDir, "gost512");
const home = join(outDir, "home");
const commonName = "Stand User 512";

let server: PageServer;
let context: BrowserContext;
let certificatePem: string;
let thumbprint: string;

test.describe.configure({ mode: "serial" });

test.beforeAll(async () => {
  rmSync(outDir, { recursive: true, force: true });
  mkdirSync(outDir, { recursive: true });
  cpSync(stand.home, home, { recursive: true, verbatimSymlinks: true });
  const subject = subjectAttributes.map((attribute) => (attribute.rdn === "commonName" ? { rdn: "commonName", value: commonName } : attribute));
  certificatePem = await provisionKey({ home, bits: 512, subject, name: "gost512/user512" });
  thumbprint = new X509Certificate(certificatePem).fingerprint.replaceAll(":", "");
  server = await servePages({ "/": blankPage });
  context = await launchStand({ home, extensions: [stand.adapter, standExtension()] });
  await clearSites(context);
  await enableSite(context, server.url);
  await addRoots(context, [{ name: "stand-ca.pem", buffer: readFileSync(join(caDir, "ca.pem")) }]);
});

test.afterAll(async () => {
  await context?.close();
  await server?.close();
});

// Runs `code` in the page with the 512-bit certificate as `certificate`, entering the PIN in every window that asks
// for it; resolves with what `code` returned or the getLastError of what it threw.
async function run<T>(page: Page, code: string): Promise<{ value?: T; error?: string }> {
  await page.evaluate(`window.flowResult = undefined; void (async () => {
    try {
      await cadesplugin;
      const store = await cadesplugin.CreateObjectAsync("CAdESCOM.Store");
      await store.Open();
      const found = await (await store.Certificates).Find(cadesplugin.CAPICOM_CERTIFICATE_FIND_SHA1_HASH, ${JSON.stringify(thumbprint)});
      const certificate = await found.Item(1);
      window.flowResult = { value: await (async () => { ${code} })() };
    } catch (e) {
      window.flowResult = { error: cadesplugin.getLastError(e) };
    }
  })()`);
  const done = () => page.evaluate(() => (window as unknown as { flowResult?: unknown }).flowResult !== undefined);
  const deadline = Date.now() + 60_000;
  while (!(await done())) {
    if (Date.now() > deadline) throw new Error("the flow did not finish");
    const dialog = pinDialog(page);
    if (await dialog.isVisible()) {
      const field = dialog.locator("input[name=pin]");
      if (await field.isVisible()) await field.fill(userPin);
      await dialog.locator("button[name=confirm]").click();
      await dialog.waitFor({ state: "detached" });
    }
    await page.waitForTimeout(100);
  }
  return page.evaluate(() => (window as unknown as { flowResult: { value?: T; error?: string } }).flowResult);
}

// As enveloped_info.py prints it: hex, upper case, without leading zeros.
const serial512 = () => BigInt(`0x${new X509Certificate(certificatePem).serialNumber}`).toString(16).toUpperCase();

const ALL_CHECKS = { message_digest: true, signature: true, certificate_by_ca: true, cades_bes_attributes: true };

test("the token lists the 512-bit certificate with its key and algorithm", async () => {
  const page = await openStandPage(context, `${server.url}/`);
  const { value, error } = await run<Record<string, unknown>>(
    page,
    `const key = await certificate.PublicKey();
     return {
       subject: await certificate.GetInfo(cadesplugin.CAPICOM_CERT_INFO_SUBJECT_SIMPLE_NAME),
       algorithm: await (await key.Algorithm).Value,
       name: await (await key.Algorithm).FriendlyName,
       length: await key.Length,
       hasKey: await certificate.HasPrivateKey(),
       valid: await (await certificate.IsValid()).Result,
     };`,
  );
  expect(error).toBeUndefined();
  expect(value).toEqual({ subject: commonName, algorithm: "1.2.643.7.1.1.1.2", name: "ГОСТ Р 34.10-2012 512 бит", length: 1024, hasKey: true, valid: true });
});

test("signs CAdES-BES attached and detached; the signatures verify independently and in the page", async () => {
  const page = await openStandPage(context, `${server.url}/`);
  const { value, error } = await run<{ attached: string; detached: string; verified: number }>(
    page,
    `const signer = await cadesplugin.CreateObjectAsync("CAdESCOM.CPSigner");
     await signer.propset_Certificate(certificate);
     const data = await cadesplugin.CreateObjectAsync("CAdESCOM.CadesSignedData");
     await data.propset_ContentEncoding(cadesplugin.CADESCOM_BASE64_TO_BINARY);
     await data.propset_Content(btoa("Hello 512"));
     const attached = await data.SignCades(signer, cadesplugin.CADESCOM_CADES_BES);
     const detached = await data.SignCades(signer, cadesplugin.CADESCOM_CADES_BES, true);
     const check = await cadesplugin.CreateObjectAsync("CAdESCOM.CadesSignedData");
     await check.VerifyCades(attached, cadesplugin.CADESCOM_CADES_BES);
     return { attached, detached, verified: await (await check.Signers).Count };`,
  );
  expect(error).toBeUndefined();
  expect(verifyCms(value!.attached).checks).toEqual(ALL_CHECKS);
  const detached = verifyCms(value!.detached, Buffer.from("Hello 512"));
  expect(detached.checks).toEqual(ALL_CHECKS);
  expect(detached.detached).toBe(true);
  expect(value!.verified).toBe(1);
});

test("signs a Streebog-512 hash, refuses a 256-bit one, and signs with the site's attributes in the page's own CMS", async () => {
  const page = await openStandPage(context, `${server.url}/`);
  const content = "Данные для хеша 512";
  const { value, error } = await run<{ hashSigned: string; wrongHash: string; withName: string }>(
    page,
    `const signer = await cadesplugin.CreateObjectAsync("CAdESCOM.CPSigner");
     await signer.propset_Certificate(certificate);
     const hash = await cadesplugin.CreateObjectAsync("CAdESCOM.HashedData");
     await hash.propset_Algorithm(cadesplugin.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_512);
     await hash.Hash(${JSON.stringify(content)});
     const data = await cadesplugin.CreateObjectAsync("CAdESCOM.CadesSignedData");
     const hashSigned = await data.SignHash(hash, signer, cadesplugin.CADESCOM_CADES_BES);
     const short = await cadesplugin.CreateObjectAsync("CAdESCOM.HashedData");
     await short.propset_Algorithm(cadesplugin.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256);
     await short.Hash(${JSON.stringify(content)});
     let wrongHash = "";
     try { await data.SignHash(short, signer, cadesplugin.CADESCOM_CADES_BES); } catch (e) { wrongHash = cadesplugin.getLastError(e); }
     const name = await cadesplugin.CreateObjectAsync("CADESCOM.CPAttribute");
     await name.propset_Name(cadesplugin.CADESCOM_AUTHENTICATED_ATTRIBUTE_DOCUMENT_NAME);
     await name.propset_Value("Документ 512.pdf");
     await (await signer.AuthenticatedAttributes2).Add(name);
     const named = await cadesplugin.CreateObjectAsync("CAdESCOM.CadesSignedData");
     await named.propset_Content(${JSON.stringify(content)});
     const withName = await named.SignCades(signer, cadesplugin.CADESCOM_CADES_BES);
     return { hashSigned, wrongHash, withName };`,
  );
  expect(error).toBeUndefined();
  expect(verifyCms(value!.hashSigned, Buffer.from(content, "utf16le")).checks).toEqual(ALL_CHECKS);
  expect(value!.wrongHash).toContain("0x80070057");
  const report = verifyCms(value!.withName);
  expect(report.checks).toEqual(ALL_CHECKS);
  expect(report.attributes).toContain("1.3.6.1.4.1.311.88.2.1");
});

test("RawSignature and XMLDSig with the 512-bit key verify independently and in the page", async () => {
  const page = await openStandPage(context, `${server.url}/`);
  const content = "Подпись без CMS, 512";
  const { value, error } = await run<{ raw: string; rawVerified: boolean; xml: string }>(
    page,
    `const hash = await cadesplugin.CreateObjectAsync("CAdESCOM.HashedData");
     await hash.propset_Algorithm(cadesplugin.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_512);
     await hash.propset_DataEncoding(cadesplugin.CADESCOM_BASE64_TO_BINARY);
     await hash.Hash(${JSON.stringify(Buffer.from(content).toString("base64"))});
     const raw = await (await cadesplugin.CreateObjectAsync("CAdESCOM.RawSignature")).SignHash(hash, certificate);
     await (await cadesplugin.CreateObjectAsync("CAdESCOM.RawSignature")).VerifyHash(hash, certificate, raw);
     const signer = await cadesplugin.CreateObjectAsync("CAdESCOM.CPSigner");
     await signer.propset_Certificate(certificate);
     const xml = await cadesplugin.CreateObjectAsync("CAdESCOM.SignedXML");
     await xml.propset_Content("<doc>Документ 512</doc>");
     await xml.propset_SignatureType(cadesplugin.CADESCOM_XML_SIGNATURE_TYPE_ENVELOPED);
     return { raw, rawVerified: true, xml: await xml.Sign(signer) };`,
  );
  expect(error).toBeUndefined();
  expect(value!.raw).toMatch(/^[0-9A-F]{256}$/);
  expect(verifyRaw(certificatePem, Buffer.from(content), value!.raw)).toEqual({ valid: true, length: 128 });
  const report = verifyXml(value!.xml);
  expect(report.valid).toBe(true);
  expect(report.signatures[0]!.signature_method).toBe("urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-512");
});

// The content encryption OIDs the Rutoken Plugin writes (webtools.spec.ts).
const ciphers = [
  ["GOST_28147_89", "1.2.643.2.2.21"],
  ["GOST_MAGMA", "1.2.643.7.1.1.5.1.1"],
  ["GOST_MAGMA_OMAC", "1.2.643.7.1.1.5.1.2"],
  ["GOST_KUZNYECHIK", "1.2.643.7.1.1.5.2.1"],
  ["GOST_KUZNYECHIK_OMAC", "1.2.643.7.1.1.5.2.2"],
] as const;

for (const [cipher, oid] of ciphers) {
  test(`encrypts CMS with ${cipher} for the 512-bit certificate and decrypts it on the token`, async () => {
    const page = await openStandPage(context, `${server.url}/`);
    const { value, error } = await run<{ message: string; content: string }>(
      page,
      `const enveloped = await cadesplugin.CreateObjectAsync("CAdESCOM.CPEnvelopedData");
       await (await enveloped.Algorithm).propset_Name(cadesplugin.CADESCOM_ENCRYPTION_ALGORITHM_${cipher});
       await (await enveloped.Recipients).Add(certificate);
       await enveloped.propset_Content("Секрет для ключа 512");
       const message = await enveloped.Encrypt(cadesplugin.CADESCOM_ENCODE_BASE64);
       const back = await cadesplugin.CreateObjectAsync("CAdESCOM.CPEnvelopedData");
       await back.Decrypt(message);
       return { message, content: await back.Content };`,
    );
    expect(error).toBeUndefined();
    // Encrypted with that cipher for the 512-bit certificate only, as the independent tool reads it.
    const info = envelopedInfo(value!.message);
    expect(info.content_encryption).toBe(oid);
    expect(info.recipients).toEqual([expect.objectContaining({ kind: "ktri", serial: serial512() })]);
    expect(value!.content).toBe("Секрет для ключа 512");
  });
}

test("encrypts XML for the 512-bit certificate and decrypts it on the token", async () => {
  const page = await openStandPage(context, `${server.url}/`);
  const { value, error } = await run<{ encrypted: string; decrypted: string }>(
    page,
    `const enveloped = await cadesplugin.CreateObjectAsync("CAdESCOM.EnvelopedXML");
     await (await enveloped.Recipients).Add(certificate);
     await enveloped.propset_Content("<Документ><Текст>Секрет 512</Текст></Документ>");
     const encrypted = await enveloped.Encrypt();
     const back = await cadesplugin.CreateObjectAsync("CAdESCOM.EnvelopedXML");
     await back.Decrypt(encrypted);
     return { encrypted, decrypted: await back.Content };`,
  );
  expect(error).toBeUndefined();
  expect(value!.encrypted).toContain("urn:ietf:params:xml:ns:cpxmlsec:algorithms:transport-gost2012-512");
  expect(value!.decrypted).toContain("<Документ><Текст>Секрет 512</Текст></Документ>");
});
