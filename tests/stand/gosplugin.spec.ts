/// <reference types="chrome" />
// The extension as Gosplugin on the fake Rutoken: a page loads the plug-in's scripts with loadScripts and calls
// gosuslugiPluginSystem and gosuslugiPluginCrypto as the plug-in's sites do; the answers are compared with what the real
// extension and core gave on the stand (docs/JOURNAL.md, 2026-11-17), the signatures go to the independent verifiers.
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { repoRoot } from "../../scripts/fetch-vendor.ts";
import { caDir } from "../../scripts/provision-token.ts";
import { stand, standDir, userPin, venvPython } from "../../scripts/setup-stand.ts";
import { digest } from "../../src/page/gost.ts";
import { parseCertificate, pemToDer } from "../../src/page/x509.ts";
import { clearSites, enableSite, launchStand, openStandPage, servePages, standExtension, type PageServer } from "./harness.ts";
import { verifyCms, verifyXml } from "./verify.ts";

// A page as the plug-in's sites talk to it: its own messages for the extension, and the plug-in's objects once loaded.
const GOS_PAGE = `<!doctype html><html><head><meta charset="utf-8"><title>Gos</title></head><body><script>
window.send = (module, method, data) => new Promise((resolve) => {
  const id = crypto.randomUUID();
  const message = { id, node: "", error: "", mode: "", module: { type: module, version: "0.0.0.0" }, method: { type: method, data, result: "" },
    meta: { format: { type: "message", version: "0.0.0.0", category: "gosuslugi.plugin" }, content: { type: "application/json", charset: "utf8", transferEncoding: "" },
      routes: [{ node: "test.page", time: new Date().toLocaleString(), transfer: "" }], data: {}, userAgent: navigator.userAgent } };
  const listener = (event) => {
    if (event.data && event.data.id === id && event.data.node) { removeEventListener("message", listener); resolve(JSON.parse(JSON.stringify(event.data))); }
  };
  addEventListener("message", listener);
  postMessage(message, "*");
});
window.api = (object, method, ...args) => new Promise((resolve) => window[object][method](...args, (answer) => resolve(JSON.parse(JSON.stringify(answer)))));
</script></body></html>`;

const userPem = readFileSync(join(standDir, "user.pem"), "utf8");
const user = parseCertificate(pemToDer(userPem));
const certificate = { content: Buffer.from(user.der).toString("base64"), path: "", contentEncoding: "base64" };
const file = (text: string) => ({ content: Buffer.from(text).toString("base64"), path: "", contentEncoding: "base64" });
const pinDialog = (page: Page) => page.locator("#rutoken-cades-bridge-pin [role=dialog]");

type Answer = { method: { type: string; data: unknown; result: string; error?: string }; error?: string; code?: string; errorMessage?: string; node: string; meta: Record<string, unknown> } & Record<string, unknown>;

let server: PageServer;

test.beforeAll(async () => {
  server = await servePages({ "/gos.html": { type: "text/html; charset=utf-8", body: GOS_PAGE } });
});

test.afterAll(async () => {
  await server?.close();
});

const send = (page: Page, module: string, method: string, data: unknown) =>
  page.evaluate(([m, f, d]) => (window as unknown as { send: (...a: unknown[]) => Promise<Answer> }).send(m, f, d), [module, method, data] as const) as Promise<Answer>;
const api = (page: Page, object: string, method: string, ...args: unknown[]) =>
  page.evaluate(([o, m, a]) => (window as unknown as { api: (...x: unknown[]) => Promise<Answer> }).api(o, m, ...(a as unknown[])), [object, method, args] as const) as Promise<Answer>;

async function openGosPage(context: BrowserContext): Promise<Page> {
  const page = await openStandPage(context, `${server.url}/gos.html`);
  await page.locator('meta[property="gosuslugi.plugin.extension.content"]').waitFor({ state: "attached" });
  const loaded = await send(page, "system", "loadScripts", ["system.js", "crypto.js"]);
  expect(JSON.parse(loaded.method.result).map((entry: { script: string; status: string }) => [entry.script, entry.status])).toEqual([
    ["formats.js", "success"],
    ["system.js", "success"],
    ["crypto.js", "success"],
  ]);
  return page;
}

// The token's store name, "Rutoken ECP <serial in hex>".
async function storeName(page: Page): Promise<string> {
  const [provider] = JSON.parse((await api(page, "gosuslugiPluginCrypto", "providers", {})).method.result) as { name: string }[];
  expect(provider!.name).toMatch(/^Rutoken ECP [0-9A-F]{8}$/);
  return provider!.name;
}

// Signs through the PIN window, as a user does.
async function withPin(page: Page, call: Promise<Answer>): Promise<Answer> {
  await pinDialog(page).locator("input[name=pin]").fill(userPin);
  await pinDialog(page).locator("button[name=confirm]").click();
  return call;
}

test.describe("on the stand token", () => {
  let context: BrowserContext;

  test.beforeAll(async () => {
    context = await launchStand({ extensions: [stand.adapter, standExtension()] });
    await clearSites(context);
    // Both Gosuslugi plug-ins, as for tools/dump-gosplugins.js.
    await enableSite(context, server.url, ["ifc", "gos"]);
  });

  test.afterAll(async () => {
    await context?.close();
  });

  test("tools/dump-gosplugins.js reads both plug-ins without a PIN", async () => {
    const page = await openStandPage(context, `${server.url}/gos.html`);
    await page.locator("#ifc-plugin-is-installed").waitFor({ state: "attached" });
    const dump = JSON.parse(await page.evaluate(readFileSync(join(repoRoot, "tools", "dump-gosplugins.js"), "utf8")));
    expect(dump.ifc.markers).toEqual([true, true]);
    expect(dump.ifc.version).toEqual({ error_code: 0, version: "3.1.1" });
    expect(dump.ifc.certificates).toHaveLength(1);
    expect(dump.ifc.certificates[0].info.cert_info.base64).toBe(certificate.content);
    expect(dump.ifc.errors).toEqual({ no_slot: { error_code: 10 }, bad_slot: { error_code: 25 }, keys_without_pin: { error_code: 5 }, unknown_function: { error_code: 17 } });
    // Read before loadScripts: the extension's mark only.
    expect(dump.gos.meta).toEqual(["gosuslugi.plugin.extension.content"]);
    expect(dump.gos.certificates.method.result).toHaveLength(1);
    expect(dump.gos.unknownSignatureType.code).toBe("30022");
    await expect(pinDialog(page)).toHaveCount(0);
  });

  test("marks the page and answers the extension's own messages as the plug-in's extension does", async () => {
    const page = await openStandPage(context, `${server.url}/gos.html`);
    await expect(page.locator('meta[property="gosuslugi.plugin.extension.content"]')).toBeAttached();
    expect(await page.evaluate(() => typeof (window as unknown as { cadesplugin?: unknown }).cadesplugin)).toBe("undefined");
    const answer = await send(page, "system", "registered", "");
    expect(answer.method).toEqual({ type: "registered", data: null, result: '["gosuslugi.plugin.extension.content"]' });
    expect(answer.node).toBe("test.page");
    expect((answer.meta.routes as { node: string }[]).map((route) => route.node)).toEqual(["test.page", "gosuslugi.plugin.extension.content"]);
    expect((await send(page, "crypto", "chunkSize", "")).method.result).toBe("524288");
    expect((await send(page, "crypto", "cancelChunks", "")).method.result).toBe("true");
    expect(await page.evaluate(() => typeof (window as unknown as { gosuslugiPluginCrypto?: unknown }).gosuslugiPluginCrypto)).toBe("undefined");
    await send(page, "system", "loadScripts", ["system.js", "crypto.js"]);
    expect(await page.evaluate(() => Object.keys(window).filter((key) => /gosuslugi|_0db7|^formats$/.test(key)))).toEqual([
      "_formats_0db7d9ec48754f9080a77e237238453b",
      "formats",
      "_system_0db7d9ec48754f9080a77e237238453b",
      "gosuslugiPluginSystem",
      "_crypto_0db7d9ec48754f9080a77e237238453b",
      "gosuslugiPluginCrypto",
    ]);
    expect(await page.evaluate(() => typeof (window as unknown as Record<string, unknown>).GosuslugiPluginMessage)).toBe("function");
    const all = JSON.parse((await send(page, "system", "loadAllScripts", "")).method.result) as { script: string; status: string }[];
    expect(all.map((entry) => [entry.script, entry.status])).toEqual([
      ["formats.js", "exists"],
      ["system.js", "exists"],
      ["crypto.js", "exists"],
      ["crypto_wrapper.js", "error"],
      ["bootstrap.js", "success"],
    ]);
    const protocol = await api(page, "gosuslugiPluginSystem", "protocol");
    expect(protocol.method.result).toBe('{"type":"nmh","host":"chrome.gosuslugi.plugin","state":"OPEN"}');
  });

  test("answers system and crypto as the core does", async () => {
    const page = await openGosPage(context);
    const handshake = await api(page, "gosuslugiPluginSystem", "handshake");
    expect(Object.keys(handshake)).toEqual(["id", "module", "method", "error", "code", "errorMessage", "node", "mode", "meta"]);
    expect(handshake).toMatchObject({ method: { type: "handshake", data: null, result: "plugin handshake" }, error: "", code: "0", errorMessage: "", node: "gosuslugi.plugin.extension.system" });
    expect((handshake.meta.content as { transferEncoding: string }).transferEncoding).toBe("binary");
    expect((handshake.meta.routes as { node: string }[]).map((route) => route.node)).toEqual(["gosuslugi.plugin.extension.system", "plugin", "gosuslugi.plugin.extension.content"]);
    expect((await api(page, "gosuslugiPluginSystem", "echo", "привет")).method.result).toBe("привет");
    expect((await api(page, "gosuslugiPluginSystem", "lastError")).method.result).toBe("0 Application 'Успешное выполнение операции'");
    expect((await api(page, "gosuslugiPluginSystem", "ipConfig")).method.result).toBe("[]");
    expect(JSON.parse((await api(page, "gosuslugiPluginSystem", "config")).method.result)[1].format.type).toBe("crypto");
    // The token's serial in hex, as the core names it (each stand build has its own).
    const providers = JSON.parse((await api(page, "gosuslugiPluginCrypto", "providers", {})).method.result);
    const store = await storeName(page);
    expect(providers).toEqual([{ name: store, type: "0", version: "hardware version: 67.4 firmware version: 34.2", token: "true" }]);
    const tokens = JSON.parse((await api(page, "gosuslugiPluginCrypto", "tokens", {})).method.result);
    expect(tokens).toMatchObject([{ store, provider: store, label: "stand", serial: store.slice("Rutoken ECP ".length), model: "Rutoken ECP", containers: [user.thumbprint] }]);
    const certificates = JSON.parse((await api(page, "gosuslugiPluginCrypto", "certificates", { store: "", fields: {} })).method.result);
    expect(certificates).toHaveLength(1);
    expect(certificates[0]).toMatchObject({
      raw: certificate.content,
      version: "v3",
      thumbprint: user.thumbprint,
      friendlyName: "",
      subject: user.subject.flat().map((attribute) => `${attribute.oid}=${attribute.value}`).join(";"),
      notBefore: String(user.notBefore.getTime() / 1000),
      hasPrivateKey: "true",
      keyUsage: "dataencipherment;digitalsignature;keyagreement;keyencipherment;nonrepudiation",
      enhancedKeyUsage: "1.3.6.1.5.5.7.3.2;1.3.6.1.5.5.7.3.4",
      provider: store,
      container: user.thumbprint,
    });
    expect(JSON.parse((await api(page, "gosuslugiPluginCrypto", "certificates", { store: "", fields: { thumbprint: "00" } })).method.result)).toEqual([]);
    const fields = JSON.parse((await api(page, "gosuslugiPluginCrypto", "certificateFields", JSON.stringify({ certificate, fields: [] }))).method.result);
    expect(fields).toMatchObject({ hasPrivateKey: "false", container: "", provider: "" });
    expect(JSON.parse((await api(page, "gosuslugiPluginCrypto", "certificateFields", { certificate, fields: ["thumbprint"] })).method.result)).toEqual({ thumbprint: user.thumbprint });
    const junk = await api(page, "gosuslugiPluginCrypto", "certificateFields", { certificate: { content: "junk", path: "", contentEncoding: "base64" }, fields: [] });
    expect(junk).toMatchObject({ error: "Ошибка контекста сертификата", code: "30045", errorMessage: "30045 Crypto 'Ошибка контекста сертификата'" });
    expect((junk.meta.content as { transferEncoding: string }).transferEncoding).toBe("");
    const data = Buffer.from("Привет, мир!");
    const hash = JSON.parse((await api(page, "gosuslugiPluginCrypto", "hash", { certificate, file: file("Привет, мир!"), algorithm: "" })).method.result);
    expect(hash).toEqual({ hash: Buffer.from(digest("streebog256", data)).toString("hex").toUpperCase(), provider: store, algorithm: "1.2.643.7.1.1.2.2" });
    expect(JSON.parse((await api(page, "gosuslugiPluginCrypto", "hash", JSON.stringify({ file: file("Привет, мир!"), algorithm: "sha256" }))).method.result)).toEqual({
      hash: Buffer.from(digest("sha256", data)).toString("hex"),
      provider: "",
      algorithm: "sha256",
    });
    const normalized = await api(page, "gosuslugiPluginCrypto", "normalize", {
      file: file('<?xml version="1.0"?><ns1:doc xmlns:ns1="urn:a" xmlns:u="urn:unused"><ns1:a  b="1"   c=\'2\'>x  <ns2:b xmlns:ns2="urn:b">y</ns2:b></ns1:a><!-- c --></ns1:doc>'),
      algorithm: "urn://smev-gov-ru/xmldsig/transform",
    });
    expect(normalized.method.result).toBe('<ns1:doc xmlns:ns1="urn:a"><ns1:a b="1" c="2">x  <ns2:b xmlns:ns2="urn:b">y</ns2:b></ns1:a></ns1:doc>');
    expect(await api(page, "gosuslugiPluginCrypto", "normalize", { file: file("<doc/>"), algorithm: "urn://smev-gov-ru/xmldsig/transform" })).toMatchObject({ code: "31013" });
    expect(await api(page, "gosuslugiPluginCrypto", "normalize", { file: file("<doc/>"), algorithm: "c14n" })).toMatchObject({ code: "30008" });
  });

  test("signs attached, detached and XMLDSig after the PIN in the extension's window", async () => {
    const page = await openGosPage(context);
    const data = Buffer.from("Привет, мир!");
    const attached = await withPin(page, api(page, "gosuslugiPluginCrypto", "signature", JSON.stringify({ files: [file("Привет, мир!")], certificate, type: "attached" })));
    const [item] = JSON.parse(attached.method.result);
    expect(item).toMatchObject({ id: "", name: "", path: "", contentEncoding: "base64", contentFormat: "" });
    expect(verifyCms(item.content).valid).toBe(true);
    const detached = await withPin(page, api(page, "gosuslugiPluginCrypto", "signature", { files: [file("Привет, мир!"), file("второй")], certificate, type: "detached" }));
    const two = JSON.parse(detached.method.result);
    expect(verifyCms(two[0].content, data).valid).toBe(true);
    expect(verifyCms(two[1].content, Buffer.from("второй")).valid).toBe(true);
    const v2 = JSON.parse((await withPin(page, api(page, "gosuslugiPluginCrypto", "signatureV2", { files: [file("Привет, мир!")], certificate, type: "detached" }))).method.result);
    expect(Object.keys(v2)).toEqual(["certificate", "signatures"]);
    expect(v2.certificate).toMatchObject({ thumbprint: user.thumbprint, hasPrivateKey: "true" });
    const xml = await withPin(page, api(page, "gosuslugiPluginCrypto", "signature", { files: [file('<doc><a Id="x">1</a></doc>')], certificate, type: "xmldsig" }));
    const signed = Buffer.from(JSON.parse(xml.method.result)[0].content, "base64").toString();
    expect(signed).toMatch(/^<\?xml version="1.0" encoding="utf-8" standalone="no" \?><doc><a Id="x">1<\/a><ds:Signature xmlns:ds="http:\/\/www.w3.org\/2000\/09\/xmldsig#"><ds:SignedInfo>/);
    // The reference to the whole document without transforms digests the signature itself: as the core's, it fails a
    // verifier; SignedInfo's signature and the certificate are what can be checked.
    const report = verifyXml(signed, join(caDir, "ca.pem"), userPem);
    expect(report.signatures[0]!.checks).toMatchObject({ signature: true, certificate_by_ca: true });
  });

  test("answers a cancelled PIN and an unknown signature type with the core's errors", async () => {
    const page = await openGosPage(context);
    const pending = api(page, "gosuslugiPluginCrypto", "signature", { files: [file("x")], certificate, type: "attached" });
    await pinDialog(page).locator("button[name=cancel]").click();
    expect(await pending).toMatchObject({ error: "Операция отменена пользователем", code: "20003", errorMessage: "20003 Application 'Операция отменена пользователем'" });
    expect(await api(page, "gosuslugiPluginCrypto", "signature", { files: [file("x")], certificate, type: "cades" })).toMatchObject({
      code: "30022",
      errorMessage: "30022 Crypto 'Тип подписи не поддерживается': cades",
    });
    expect((await api(page, "gosuslugiPluginSystem", "lastError")).method.result).toBe("30022 Crypto 'Тип подписи не поддерживается': cades");
  });
});

test.describe("on a copy of the token", () => {
  const outDir = join(standDir, "gosplugin");
  const home = join(outDir, "home");
  let context: BrowserContext;

  test.beforeAll(async () => {
    rmSync(outDir, { recursive: true, force: true });
    mkdirSync(outDir, { recursive: true });
    cpSync(stand.home, home, { recursive: true, verbatimSymlinks: true });
    context = await launchStand({ home, extensions: [stand.adapter, standExtension()] });
    await clearSites(context);
    await enableSite(context, server.url, ["gos"]);
  });

  test.afterAll(async () => {
    await context?.close();
  });

  test("makes a key and request, installs the issued certificate, signs with it and deletes it", async () => {
    const page = await openGosPage(context);
    const store = await storeName(page);
    const answer = await withPin(
      page,
      api(page, "gosuslugiPluginCrypto", "certificateRequest", { subject: "2.5.4.3=Запрос Госплагина;2.5.4.6=RU", provider: store, extendedKeyUsageOids: "1.3.6.1.5.5.7.3.2", certificatePolicies: "1.2.643.100.113.1", keyUsage: "", publicKeyAlgorithmParamSet: "" }),
    );
    const result = JSON.parse(answer.method.result);
    expect(result.container.name).toMatch(/^rt1-[0-9a-f-]{36}$/);
    expect(result).toMatchObject({ request: { contentEncoding: "base64" }, exportable: "false" });
    const csr = `-----BEGIN CERTIFICATE REQUEST-----\n${result.request.content.match(/.{1,64}/g).join("\n")}\n-----END CERTIFICATE REQUEST-----\n`;
    writeFileSync(join(outDir, "gos.csr.pem"), csr);
    // The test CA checks the request's signature before it issues.
    execFileSync(venvPython, [join(repoRoot, "tests", "tools", "gost_ca.py"), "issue", caDir, join(outDir, "gos.csr.pem"), join(outDir, "gos.pem")]);
    const issued = parseCertificate(pemToDer(readFileSync(join(outDir, "gos.pem"), "utf8")));
    const issuedFile = { content: Buffer.from(issued.der).toString("base64"), path: "", contentEncoding: "base64" };
    expect(await api(page, "gosuslugiPluginCrypto", "addCertificate", { certificate: issuedFile, container: "", store: "" })).toMatchObject({ code: "30013" });
    expect((await withPin(page, api(page, "gosuslugiPluginCrypto", "addCertificate", { certificate: issuedFile, container: "", store }))).method.result).toBe("");
    // Again: there already, no PIN.
    expect((await api(page, "gosuslugiPluginCrypto", "addCertificate", { certificate: issuedFile, container: "", store })).method.result).toBe("");
    const signed = await withPin(page, api(page, "gosuslugiPluginCrypto", "signature", { files: [file("Новым ключом")], certificate: issuedFile, type: "attached" }));
    expect(verifyCms(JSON.parse(signed.method.result)[0].content).valid).toBe(true);
    expect((await withPin(page, api(page, "gosuslugiPluginCrypto", "deleteCertificate", { certificate: issuedFile, store }))).method.result).toBe("true");
    expect(await api(page, "gosuslugiPluginCrypto", "deleteCertificate", { certificate: issuedFile, store })).toMatchObject({ code: "30019" });
  });
});
