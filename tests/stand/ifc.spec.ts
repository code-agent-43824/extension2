/// <reference types="chrome" />
// The extension as IFCPlugin, the old Gosuslugi plug-in, on the fake Rutoken: a page talks to it the way the plug-in's
// sites do, TO_IFC_EXT requests answered in order by FROM_IFC_EXT, and its signatures go to the independent verifiers.
// The answers to compare with are the real core's (docs/JOURNAL.md, 2026-11-17).
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { execFileSync, spawnSync } from "node:child_process";
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { repoRoot } from "../../scripts/fetch-vendor.ts";
import { caDir } from "../../scripts/provision-token.ts";
import { stand, standDir, userPin, venvPython } from "../../scripts/setup-stand.ts";
import { digest } from "../../src/page/gost.ts";
import { opensslExtensions, opensslName, opensslSerial, opensslTime } from "../../src/page/ifc/openssl-text.ts";
import { parseCertificate, pemToDer } from "../../src/page/x509.ts";
import { clearSites, enableSite, extensionOrigin, launchStand, openStandPage, servePages, standExtension, type PageServer } from "./harness.ts";
import { verifyCms, verifyRaw, verifyXml } from "./verify.ts";

// A page as IFCPlugin's sites write it: requests go out as JSON strings, answers come back in the same order.
const IFC_PAGE = `<!doctype html><html><head><meta charset="utf-8"><title>IFC</title></head><body><script>
const pending = [];
window.ifcFrames = [];
window.addEventListener("message", (event) => {
  if (typeof event.data !== "string") return;
  let message;
  try { message = JSON.parse(event.data); } catch { return; }
  if (message.type === "IFC_EXT_DISCONNECT") window.ifcDisconnected = true;
  if (message.type !== "FROM_IFC_EXT") return;
  window.ifcFrames.push(message.msg_data);
  if (message.msg_data.intermediate !== 1) pending.shift()?.(message.msg_data);
});
window.ifc = (func_name, params = {}) => new Promise((resolve) => {
  pending.push(resolve);
  window.postMessage(JSON.stringify({ type: "TO_IFC_EXT", msg_data: { func_name, params } }), "*");
});
</script></body></html>`;

const userPem = readFileSync(join(standDir, "user.pem"), "utf8");
const user = parseCertificate(pemToDer(userPem));
const container = `ruTokenECP/0/${user.thumbprint}`;
const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64");

// A SOAP message of SMEV 2 with the WS-Security template IFCPlugin's sign_xml fills.
const SOAP = `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"><soap:Header><wsse:Security soap:actor="http://smev.gosuslugi.ru/actors/smev"><wsse:BinarySecurityToken EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" wsu:Id="CertId"></wsse:BinarySecurityToken><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256"/><ds:Reference URI="#body"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256"/><ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue><ds:KeyInfo><wsse:SecurityTokenReference><wsse:Reference URI="#CertId" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"/></wsse:SecurityTokenReference></ds:KeyInfo></ds:Signature></wsse:Security></soap:Header><soap:Body wsu:Id="body"><a>Привет</a></soap:Body></soap:Envelope>`;

let server: PageServer;

test.beforeAll(async () => {
  server = await servePages({ "/ifc.html": { type: "text/html; charset=utf-8", body: IFC_PAGE } });
});

test.afterAll(async () => {
  await server?.close();
});

async function ifc(page: Page, func_name: string, params: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
  return page.evaluate(([name, values]) => (window as unknown as { ifc: (n: string, p: unknown) => Promise<Record<string, unknown>> }).ifc(name, values), [func_name, params] as const);
}

async function openIfcPage(context: BrowserContext): Promise<Page> {
  const page = await openStandPage(context, `${server.url}/ifc.html`);
  await page.locator("#ifc-plugin-is-installed").waitFor({ state: "attached" });
  return page;
}

test.describe("on the stand token", () => {
  let context: BrowserContext;

  test.beforeAll(async () => {
    context = await launchStand({ extensions: [stand.adapter, standExtension()] });
    await clearSites(context);
    await enableSite(context, server.url, ["ifc"]);
  });

  test.afterAll(async () => {
    await context?.close();
  });

  test("marks the page, answers the base set as the core does, and is no CryptoPro", async () => {
    const page = await openIfcPage(context);
    await expect(page.locator("#ifcplugin-extension-is-installed")).toBeAttached();
    expect(await page.evaluate(() => typeof (window as unknown as { cadesplugin?: unknown }).cadesplugin)).toBe("undefined");
    expect(await ifc(page, "version")).toEqual({ error_code: 0, version: "3.1.1" });
    expect(await ifc(page, "create", { file_config: "/etc/ifc.cfg" })).toEqual({ error_code: 0 });
    // The fork's slot description, as the core showed it; the serial is the token's, in hex (each stand build has its own).
    const list = (await ifc(page, "get_list_info")) as { ifc_list: { serial_number: string }[] };
    expect(list.ifc_list[0]!.serial_number).toMatch(/^[0-9A-F]{8}$/);
    expect(list).toEqual({
      error_code: 0,
      ifc_list: [{ alg: "gost2001", alias: "ruTokenECP", description: "Aktiv Rutoken ECP 0", model: "Rutoken ECP", name: "Актив Рутокен ЭЦП", num: "0", path: "librtpkcs11ecp.so", serial_number: list.ifc_list[0]!.serial_number, skip_pkcs11_list: "", type: "pkcs11" }],
      ifc_list_length: 1,
    });
    const entry = { cert_issuer: opensslName(user.issuer), cert_sign_alg: user.publicKeyAlgorithm, cert_sn: opensslSerial(user), cert_subject: opensslName(user.subject), cert_valid_from: opensslTime(user.notBefore), cert_valid_to: opensslTime(user.notAfter), id: user.thumbprint };
    expect(await ifc(page, "get_list_certs", { cryptoID: "ruTokenECP/0" })).toEqual({ cert_list: [entry], error_code: 0 });
    expect(await ifc(page, "get_list_certs", { cryptoID: "ruTokenECP/5" })).toEqual({ error_code: 25 });
    expect(await ifc(page, "get_list_keys", { cryptoID: "ruTokenECP/0", userPin: "1111" })).toEqual({ error_code: 160 });
    // After the PIN the key goes by its CKA_ID in Windows-1251, as the core names it, and from then on the certificate
    // too, without a PIN (src/page/key-ids.ts).
    const keys = (await ifc(page, "get_list_keys", { cryptoID: "ruTokenECP/0", userPin })) as { keys_list: Record<string, string>[] };
    const keyName = keys.keys_list[0]!.id!;
    expect(keyName).not.toBe(user.thumbprint);
    expect(keys).toEqual({ error_code: 0, keys_list: [{ ...entry, id: keyName }] });
    expect(await ifc(page, "get_list_certs", { cryptoID: "ruTokenECP/0" })).toEqual({ cert_list: [{ ...entry, id: keyName }], error_code: 0 });
    expect(await ifc(page, "load_x509_from_container", { containerId: `ruTokenECP/0/${keyName}` })).toMatchObject({ error_code: 0 });
    const { x509Handle } = (await ifc(page, "load_x509_from_container", { containerId: container })) as { x509Handle: number };
    const info = (await ifc(page, "get_x509_info", { x509Handle })) as { cert_info: Record<string, string> };
    expect(info.cert_info).toMatchObject({ base64: b64(user.der), extensions: opensslExtensions(user), version: "3" });
    const data = Buffer.from("Привет, мир!");
    expect(await ifc(page, "hash", { containerId: container, inDataType: 2, outDataType: 1, data: b64(data) })).toEqual({ error_code: 0, hashValue: b64(digest("streebog256", data)) });
    // Answers come in the order of the requests, even when sent at once.
    const together = await page.evaluate(() => {
      const call = (window as unknown as { ifc: (n: string, p?: unknown) => Promise<Record<string, unknown>> }).ifc;
      return Promise.all([call("get_list_info"), call("version"), call("no_such_function")]);
    });
    expect(together.map((answer) => Object.keys(answer))).toEqual([["error_code", "ifc_list", "ifc_list_length"], ["error_code", "version"], ["error_code"]]);
  });

  test("signs with the site's PIN and no window: bare signatures and CMS the verifiers accept", async () => {
    const page = await openIfcPage(context);
    const data = Buffer.from("Привет, мир!");
    const sign = async (signType: number) => (await ifc(page, "sign", { containerId: container, userPin, signType, inDataType: 2, outDataType: 1, data: b64(data) })).sign_value as string;
    const forward = Buffer.from(await sign(1), "base64");
    // verify_raw.py takes CryptoPro's RawSignature, whose byte order is sign type 2's.
    expect(verifyRaw(userPem, data, Buffer.from(forward).reverse().toString("hex")).valid).toBe(true);
    expect(verifyRaw(userPem, data, Buffer.from(await sign(2), "base64").toString("hex")).valid).toBe(true);
    for (const signType of [3, 4, 5, 6]) {
      const cms = await sign(signType);
      const detached = signType % 2 === 0;
      const report = verifyCms(cms, detached ? data : undefined);
      // Types 3 and 4 are CMS without the signing certificate attribute, as the core makes them: not CAdES-BES.
      expect(report.checks, `sign type ${signType}`).toEqual({ message_digest: true, signature: true, certificate_by_ca: true, cades_bes_attributes: signType >= 5 });
      expect(report.detached).toBe(detached);
      expect(report.attributes.includes("1.2.840.113549.1.9.16.2.47")).toBe(signType >= 5);
      const { x509Handle } = await ifc(page, "load_x509_from_container", { containerId: container });
      expect(await ifc(page, "verify", { containerId: container, x509Handle, signType, inDataType: 2, data: b64(data), sign: cms })).toEqual({ error_code: 0, verify_result: 0 });
      expect(await ifc(page, "verify", { containerId: container, x509Handle, signType, inDataType: 2, data: b64(Buffer.from("другое")), sign: cms })).toEqual(
        detached ? { error_code: 19, verify_result: 19 } : { error_code: 0, verify_result: 0 },
      );
    }
    await expect(page.locator("#rutoken-cades-bridge-pin")).toHaveCount(0);
  });

  test("fills the WS-Security template of sign_xml and checks it with verify_xml", async () => {
    const page = await openIfcPage(context);
    const signed = (await ifc(page, "sign_xml", { containerId: container, userPin, wsu_id: "body", inDataType: 1, outDataType: 2, data: SOAP })).sign_value as string;
    expect(signed.startsWith("<soap:Envelope")).toBe(true);
    expect(verifyXml(signed, join(caDir, "ca.pem"), userPem).valid).toBe(true);
    // The site puts the certificate into the token; verify_xml takes it from there.
    const withToken = signed.replace(/(<wsse:BinarySecurityToken[^>]*?)\/>/, `$1>${b64(user.der)}</wsse:BinarySecurityToken>`);
    expect(await ifc(page, "verify_xml", { containerId: container, wsu_id: "body", inDataType: 1, sign: withToken })).toEqual({ error_code: 0, verify_result: 0 });
    expect(await ifc(page, "verify_xml", { containerId: container, wsu_id: "body", inDataType: 1, sign: withToken.replace("Привет", "Пока") })).toEqual({ error_code: 19, verify_result: 19 });
    expect(await ifc(page, "verify_xml", { containerId: container, wsu_id: "body", inDataType: 1, sign: signed })).toEqual({ error_code: 5 });
    expect(await ifc(page, "sign_xml", { containerId: container, userPin, wsu_id: "nobody", inDataType: 1, outDataType: 2, data: SOAP })).toEqual({ error_code: 27 });
    expect(await ifc(page, "sign_xml", { containerId: container, userPin, wsu_id: "body", inDataType: 1, outDataType: 2, data: "junk" })).toEqual({ error_code: 5 });
  });

  test("asks the PIN in the extension's window when the options page says so", async () => {
    const options = await context.newPage();
    await options.goto(`${await extensionOrigin(context)}/options.html`);
    await options.locator("input[name=ifc-pin][value=window]").check();
    await options.close();
    try {
      const page = await openIfcPage(context);
      const pending = ifc(page, "sign", { containerId: container, userPin: "the site's, not used", signType: 5, inDataType: 2, outDataType: 1, data: "AAAA" });
      const dialog = page.locator("#rutoken-cades-bridge-pin [role=dialog]");
      await expect(dialog).toContainText("Запрос сайта к плагину Госуслуг (IFCPlugin).");
      await dialog.locator("input[name=pin]").fill(userPin);
      await dialog.locator("button[name=confirm]").click();
      const signature = (await pending).sign_value as string;
      expect(verifyCms(signature).valid).toBe(true);
    } finally {
      const options = await context.newPage();
      await options.goto(`${await extensionOrigin(context)}/options.html`);
      await options.locator("input[name=ifc-pin][value=site]").check();
      await options.close();
    }
  });
});

test.describe("on a copy of the token", () => {
  const outDir = join(standDir, "ifc");
  const home = join(outDir, "home");
  let context: BrowserContext;

  test.beforeAll(async () => {
    rmSync(outDir, { recursive: true, force: true });
    mkdirSync(outDir, { recursive: true });
    cpSync(stand.home, home, { recursive: true, verbatimSymlinks: true });
    context = await launchStand({ home, extensions: [stand.adapter, standExtension()] });
    await clearSites(context);
    await enableSite(context, server.url, ["ifc"]);
  });

  test.afterAll(async () => {
    await context?.close();
  });

  test("makes a named key and its request, writes the issued certificate and signs with it", async () => {
    const page = await openIfcPage(context);
    const containerId = "ruTokenECP/0/ifc-key-1";
    expect(await ifc(page, "key_gen", { containerId, userPin })).toEqual({ error_code: 0, real_id: containerId });
    expect(await ifc(page, "key_gen", { containerId, userPin })).toEqual({ error_code: 1 });
    const subject = { oids_count: 2, oid_1: "2.5.4.3", oid_type_1: 12, value_1: "Ключ IFC", oid_2: "2.5.4.6", oid_type_2: 19, value_2: "RU" };
    const request = await ifc(page, "req_gen", { containerId, userPin, subject, req_format: 1, signInstrument: "Рутокен ЭЦП 2.0", extendedKeyUsage: ["1.3.6.1.5.5.7.3.2"], certificatePolicies: ["1.2.643.100.113.1"] });
    expect(request.error_code).toBe(0);
    writeFileSync(join(outDir, "ifc.csr.pem"), request.req_pem as string);
    // OpenSSL cannot load the GOST key without its engine and says so, but prints the rest.
    const text = spawnSync("openssl", ["req", "-in", join(outDir, "ifc.csr.pem"), "-noout", "-text"], { encoding: "utf8" }).stdout;
    expect(text).toContain("Digital Signature, Non Repudiation, Key Encipherment, Data Encipherment");
    expect(text).toContain("Class of Signing Tool KC1");
    // The test CA checks the request's signature before it issues.
    execFileSync(venvPython, [join(repoRoot, "tests", "tools", "gost_ca.py"), "issue", caDir, join(outDir, "ifc.csr.pem"), join(outDir, "ifc.pem")]);
    const issued = readFileSync(join(outDir, "ifc.pem"), "utf8");
    const { x509Handle } = await ifc(page, "load_x509_from_data", { cert_data_type: 0, cert: issued });
    expect(await ifc(page, "set_x509", { containerId, userPin, x509Handle })).toEqual({ error_code: 0 });
    expect(await ifc(page, "set_x509", { containerId, userPin, x509Handle })).toEqual({ error_code: 1 });
    const thumbprint = parseCertificate(pemToDer(issued)).thumbprint;
    // set_x509's login told the extension the key's id: the certificate goes by the key's name, as with the core.
    const list = (await ifc(page, "get_list_certs", { cryptoID: "ruTokenECP/0" })).cert_list as { id: string }[];
    expect(list.map((entry) => entry.id)).toContain("ifc-key-1");
    const signature = (await ifc(page, "sign", { containerId: `ruTokenECP/0/${thumbprint}`, userPin, signType: 5, inDataType: 1, outDataType: 1, data: "Подпись новым ключом" })).sign_value as string;
    expect(verifyCms(signature).valid).toBe(true);
    // The name still works on this page.
    expect((await ifc(page, "sign", { containerId, userPin, signType: 1, inDataType: 1, outDataType: 1, data: "x" })).error_code).toBe(0);
  });
});
