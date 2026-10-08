// CAdESCOM.EnvelopedXML in the browser's DOM, without the extension or the stand's token: the page code bundled with a
// fake plugin (enveloped-xml.page.ts), since the stand's fake token cannot make the VKO key decryption needs
// (docs/JOURNAL.md, 2026-10-08). The recipient is the stand CA, whose key is in software: the fake plugin's derive gets
// the key from vko256 (src/page/gost.ts, checked against RFC 7836 in the unit tests). With STAND_OPENSSL_GOST=1
// (OpenSSL's GOST engine: apt install libengine-gost-openssl) the key comes from OpenSSL instead, OpenSSL decrypts
// what Encrypt made, and the page decrypts an XML put together from OpenSSL's own encryption.
import { chromium, expect, test, type Browser, type Page } from "@playwright/test";
import { build } from "esbuild";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { aliases } from "../../scripts/build.ts";
import { repoRoot } from "../../scripts/fetch-vendor.ts";
import { caDir } from "../../scripts/provision-token.ts";
import { vko256 } from "../../src/page/gost.ts";
import { parseCertificate, pemToDer } from "../../src/page/x509.ts";
import { standCaKeyPem } from "./verify.ts";

const withOpenssl = Boolean(process.env.STAND_OPENSSL_GOST);
const caPem = readFileSync(join(caDir, "ca.pem"), "utf8");
const ca = parseCertificate(pemToDer(caPem));
// gost_ca.py keeps the key as big-endian hex; vko256 takes it little-endian.
const caKey = Uint8Array.from(Buffer.from(readFileSync(join(caDir, "ca.key"), "utf8").trim(), "hex").reverse());
const E_INVALIDARG = 0x80070057;
const NTE_BAD_DATA = 0x80090005;
const NTE_BAD_ALGID = 0x80090008;
const CRYPT_E_NO_DECRYPT_CERT = 0x8009200c;
const ERROR_XML_PARSE_ERROR = 0x800705b9;

const document =
  '<?xml version="1.0" encoding="UTF-8"?>\n<Документ xmlns="urn:example:document" xmlns:a="urn:example:a" Номер="1"><a:Текст>Привет, мир &amp; всё</a:Текст><Пусто/></Документ>';

let browser: Browser;
let page: Page;
let dir: string;

const fromHex = (hex: string) => Buffer.from(hex.replace(/:/g, ""), "hex");
const colonHex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex").replace(/(..)(?!$)/g, "$1:");

function openssl(args: string[], env: Record<string, string> = {}): Buffer {
  const run = spawnSync("openssl", args, { env: { ...process.env, ...env } });
  if (run.status !== 0) throw new Error(`openssl ${args.join(" ")}: ${run.stderr.toString()}`);
  return run.stdout;
}

function pemOf(label: string, der: Uint8Array): string {
  return `-----BEGIN ${label}-----\n${Buffer.from(der).toString("base64")}\n-----END ${label}-----\n`;
}

// The key the CA's private key and the sender's ephemeral key make, as the token's derive would answer it.
function derive(publicKey: string, ukm: string): string {
  if (!withOpenssl) return colonHex(vko256(ca.publicKeyParameters!, caKey, fromHex(publicKey), fromHex(ukm)));
  const point = fromHex(publicKey);
  const spki = Buffer.concat([Buffer.from([0x30, 0x81, ca.publicKeyAlgorithmDer.length + point.length + 5]), ca.publicKeyAlgorithmDer, Buffer.from([0x03, point.length + 3, 0x00, 0x04, point.length]), point]);
  writeFileSync(join(dir, "peer.pem"), pemOf("PUBLIC KEY", spki));
  return colonHex(openssl(["pkeyutl", "-engine", "gost", "-derive", "-inkey", join(dir, "ca-key.pem"), "-peerkey", join(dir, "peer.pem"), "-pkeyopt", `ukmhex:${ukm.replace(/:/g, "")}`]));
}

test.beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "enveloped-xml-"));
  writeFileSync(join(dir, "ca-key.pem"), standCaKeyPem());
  const bundle = await build({
    entryPoints: [join(repoRoot, "tests", "stand", "enveloped-xml.page.ts")],
    bundle: true,
    write: false,
    format: "iife",
    target: "chrome111",
    charset: "utf8",
    define: { __EXTENSION_VERSION__: JSON.stringify("0.0.0-test") },
    alias: aliases,
    logLevel: "warning",
  });
  browser = await chromium.launch({ channel: "chromium" });
  page = await browser.newPage();
  await page.exposeFunction("standDerive", derive);
  await page.setContent("<!doctype html><title>EnvelopedXML</title>");
  await page.addScriptTag({ content: bundle.outputFiles[0]!.text });
});

test.afterAll(async () => {
  await browser?.close();
  if (dir) rmSync(dir, { recursive: true, force: true });
});

interface Round {
  encrypted: string;
  decrypted: string;
  pins: number;
  derived: number;
}

// Encrypt for the CA's certificate, then Decrypt on a token that holds it.
function roundTrip(content: string): Promise<Round> {
  return page.evaluate(
    async ({ caPem, content }) => {
      const { envelopedXml, token, certificate } = window.envelopedXml;
      const fake = token(caPem);
      const xml = envelopedXml(fake) as any;
      await xml.propset_Content(content);
      await (await xml.Recipients).Add(certificate(fake, caPem));
      const encrypted: string = await xml.Encrypt();
      const back = envelopedXml(fake) as any;
      await back.Decrypt(encrypted);
      return { encrypted, decrypted: await back.Content, pins: fake.pins, derived: fake.derived.length };
    },
    { caPem, content },
  );
}

// What the encrypted document holds, read with the browser's own parser.
function summary(encrypted: string) {
  return page.evaluate((encrypted) => {
    const doc = new DOMParser().parseFromString(encrypted, "application/xml");
    const xenc = "http://www.w3.org/2001/04/xmlenc#";
    const ds = "http://www.w3.org/2000/09/xmldsig#";
    const data = doc.documentElement;
    const key = data.getElementsByTagNameNS(xenc, "EncryptedKey")[0]!;
    const methods = Array.from(doc.getElementsByTagNameNS(xenc, "EncryptionMethod"), (method) => method.getAttribute("Algorithm"));
    const values = Array.from(doc.getElementsByTagNameNS(xenc, "CipherValue"), (value) => atob(value.textContent!.replace(/\s+/g, "")).length);
    return {
      root: `${data.namespaceURI} ${data.localName} ${data.getAttribute("Type")}`,
      keyParent: `${key.parentElement!.namespaceURI} ${key.parentElement!.localName}`,
      methods,
      certificate: key.getElementsByTagNameNS(ds, "X509Certificate")[0]!.textContent!.replace(/\s+/g, ""),
      values,
      declaration: encrypted.slice(0, encrypted.indexOf("?>") + 2),
    };
  }, encrypted);
}

test("encrypts the whole document for the certificate in CryptoPro's format, and decrypts it back after the PIN", async () => {
  const { encrypted, decrypted, pins, derived } = await roundTrip(document);
  expect(await summary(encrypted)).toEqual({
    root: "http://www.w3.org/2001/04/xmlenc# EncryptedData http://www.w3.org/2001/04/xmlenc#Element",
    keyParent: "http://www.w3.org/2000/09/xmldsig# KeyInfo",
    // In document order: the content's, then the key's.
    methods: ["urn:ietf:params:xml:ns:cpxmlsec:algorithms:gost28147", "urn:ietf:params:xml:ns:cpxmlsec:algorithms:transport-gost2012-256"],
    certificate: Buffer.from(ca.der).toString("base64"),
    // The GostR3410-KeyTransport for a 256-bit key, then the IV and the padded content.
    values: [172, 8 + 8 * (Math.floor(Buffer.byteLength(document.slice(document.indexOf("<Документ"))) / 8) + 1)],
    declaration: '<?xml version="1.0" encoding="UTF-8"?>',
  });
  expect(decrypted.trim()).toBe(document);
  expect([pins, derived]).toEqual([1, 1]);
});

test("takes and gives Base64 of the document's bytes", async () => {
  const content = Buffer.from(document).toString("base64");
  const { encrypted, decrypted } = await roundTrip(content);
  expect(encrypted).toMatch(/^[A-Za-z0-9+/=\n]+$/);
  expect(Buffer.from(decrypted, "base64").toString().trim()).toBe(document);
});

test("decrypts an EncryptedData inside a document, with the namespaces declared around it", async () => {
  const decrypted = await page.evaluate(
    async ({ caPem }) => {
      const { envelopedXml, token, newContentKey, wrapContentKey, encryptContent } = window.envelopedXml;
      const cek = newContentKey();
      const base64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
      const certificate = caPem.replace(/-----[^-]+-----|\s+/g, "");
      const data =
        `<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Content">` +
        `<EncryptionMethod Algorithm="urn:ietf:params:xml:ns:cpxmlsec:algorithms:gost28147"/>` +
        `<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><EncryptedKey xmlns="http://www.w3.org/2001/04/xmlenc#">` +
        `<EncryptionMethod Algorithm="urn:ietf:params:xml:ns:cpxmlsec:algorithms:transport-gost2012-256"/>` +
        `<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>${certificate}</X509Certificate></X509Data></KeyInfo>` +
        `<CipherData><CipherValue>${base64(wrapContentKey(caPem, cek))}</CipherValue></CipherData></EncryptedKey></KeyInfo>` +
        `<CipherData><CipherValue>${base64(encryptContent(cek, "<a:Текст>секрет</a:Текст><a:Ещё/>"))}</CipherValue></CipherData></EncryptedData>`;
      const xml = envelopedXml(token(caPem)) as any;
      await xml.Decrypt(`<Документ xmlns:a="urn:example:a"><Открыто>да</Открыто>${data}</Документ>`);
      return (await xml.Content) as string;
    },
    { caPem },
  );
  expect(decrypted).toBe('<?xml version="1.0"?>\n<Документ xmlns:a="urn:example:a"><Открыто>да</Открыто><a:Текст>секрет</a:Текст><a:Ещё/></Документ>\n');
});

test("refuses what it cannot do with the codes sites see, and never asks for the PIN for a message that is not its", async () => {
  const result = await page.evaluate(
    async ({ caPem, document }) => {
      const { envelopedXml, token, certificate, getLastError } = window.envelopedXml;
      const fake = token(caPem);
      const error = async (run: () => Promise<unknown>) => {
        try {
          await run();
          return "no error";
        } catch (e) {
          return String(getLastError(e));
        }
      };
      const noRecipients = envelopedXml(fake) as any;
      await noRecipients.propset_Content(document);
      const kuznyechik = envelopedXml(fake) as any;
      await kuznyechik.propset_Content(document);
      await (await kuznyechik.Algorithm).propset_Name(45);
      await (await kuznyechik.Recipients).Add(certificate(fake, caPem));
      const plain = envelopedXml(fake) as any;
      await plain.propset_Content(document);
      await (await plain.Recipients).Add(certificate(fake, caPem));
      const encrypted: string = await plain.Encrypt();
      // A token without the recipient's certificate (an unreadable one is skipped).
      const other = token("");
      // A byte of the wrapped key changed: the key transport still reads, its MAC no longer matches.
      const tampered = encrypted.replace(/<CipherValue>([^<]+)<\/CipherValue>/, (_match, value: string) => {
        const bytes = Uint8Array.from(atob(value.replace(/\s+/g, "")), (char) => char.charCodeAt(0));
        bytes[10]! ^= 1;
        return `<CipherValue>${btoa(String.fromCharCode(...bytes))}</CipherValue>`;
      });
      return {
        noRecipients: await error(() => noRecipients.Encrypt()),
        kuznyechik: await error(() => kuznyechik.Encrypt()),
        cms: await error(() => (envelopedXml(fake) as any).Decrypt("MIAGCSqGSIb3DQEHA6CAMIACAQAxggE=")),
        notEncrypted: await error(() => (envelopedXml(fake) as any).Decrypt(document)),
        noCertificate: await error(() => (envelopedXml(other) as any).Decrypt(encrypted)),
        tampered: await error(() => (envelopedXml(fake) as any).Decrypt(tampered)),
        pins: fake.pins,
        otherPins: other.pins,
      };
    },
    { caPem, document },
  );
  const code = (value: number) => `(0x${value.toString(16).toUpperCase()})`;
  expect(result.noRecipients).toContain(code(E_INVALIDARG));
  expect(result.kuznyechik).toBe(`XML шифруется только ГОСТ 28147-89 ${code(NTE_BAD_ALGID)}`);
  expect(result.cms).toContain(code(ERROR_XML_PARSE_ERROR));
  expect(result.notEncrypted).toContain(code(NTE_BAD_DATA));
  expect(result.noCertificate).toContain(code(CRYPT_E_NO_DECRYPT_CERT));
  expect(result.tampered).toContain(code(NTE_BAD_DATA));
  // Only the tampered message reached the PIN window; the other token was never asked.
  expect([result.pins, result.otherPins]).toEqual([1, 0]);
});

test("OpenSSL decrypts the key and the content Encrypt made", async () => {
  test.skip(!withOpenssl, "needs OpenSSL's GOST engine: set STAND_OPENSSL_GOST=1");
  const { encrypted } = await roundTrip(document);
  const [key, content] = Array.from(encrypted.matchAll(/<CipherValue>([^<]+)<\/CipherValue>/g), (match) => Buffer.from(match[1]!.replace(/\s+/g, ""), "base64"));
  writeFileSync(join(dir, "transport.der"), key!);
  const cek = openssl(["pkeyutl", "-engine", "gost", "-decrypt", "-inkey", join(dir, "ca-key.pem"), "-in", join(dir, "transport.der")]);
  writeFileSync(join(dir, "content.bin"), content!.subarray(8));
  const padded = openssl(["enc", "-d", "-engine", "gost", "-gost89-cbc", "-nopad", "-K", cek.toString("hex"), "-iv", content!.subarray(0, 8).toString("hex"), "-in", join(dir, "content.bin")], {
    CRYPT_PARAMS: "id-tc26-gost-28147-param-Z",
  });
  expect(padded.subarray(0, padded.length - padded[padded.length - 1]!).toString()).toBe(document.slice(document.indexOf("<Документ")));
});

test("decrypts an XML put together from OpenSSL's encryption", async () => {
  test.skip(!withOpenssl, "needs OpenSSL's GOST engine: set STAND_OPENSSL_GOST=1");
  const root = document.slice(document.indexOf("<Документ"));
  const cek = Buffer.from(crypto.getRandomValues(new Uint8Array(32)));
  const iv = Buffer.from(crypto.getRandomValues(new Uint8Array(8)));
  writeFileSync(join(dir, "cek.bin"), cek);
  writeFileSync(join(dir, "ca-pub.pem"), openssl(["x509", "-engine", "gost", "-in", join(caDir, "ca.pem"), "-pubkey", "-noout"]));
  const transport = openssl(["pkeyutl", "-engine", "gost", "-encrypt", "-pubin", "-inkey", join(dir, "ca-pub.pem"), "-in", join(dir, "cek.bin")]);
  writeFileSync(join(dir, "plain.xml"), root);
  const content = openssl(["enc", "-e", "-engine", "gost", "-gost89-cbc", "-K", cek.toString("hex"), "-iv", iv.toString("hex"), "-in", join(dir, "plain.xml")], {
    CRYPT_PARAMS: "id-tc26-gost-28147-param-Z",
  });
  const certificate = Buffer.from(ca.der).toString("base64");
  const xml =
    `<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element">` +
    `<EncryptionMethod Algorithm="urn:ietf:params:xml:ns:cpxmlsec:algorithms:gost28147"/>` +
    `<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><EncryptedKey xmlns="http://www.w3.org/2001/04/xmlenc#">` +
    `<EncryptionMethod Algorithm="urn:ietf:params:xml:ns:cpxmlsec:algorithms:transport-gost2012-256"/>` +
    `<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>${certificate}</X509Certificate></X509Data></KeyInfo>` +
    `<CipherData><CipherValue>${transport.toString("base64")}</CipherValue></CipherData></EncryptedKey></KeyInfo>` +
    `<CipherData><CipherValue>${Buffer.concat([iv, content]).toString("base64")}</CipherValue></CipherData></EncryptedData>`;
  const decrypted = await page.evaluate(
    async ({ caPem, xml }) => {
      const { envelopedXml, token } = window.envelopedXml;
      const decryptor = envelopedXml(token(caPem)) as any;
      await decryptor.Decrypt(xml);
      return (await decryptor.Content) as string;
    },
    { caPem, xml },
  );
  expect(decrypted).toBe(`<?xml version="1.0"?>\n${root}\n`);
});
