// The extension as Kontur.Plugin on the fake Rutoken: a page posts kontur-toolbox-request messages as Kontur's client
// does and reads the kontur-toolbox-response ones; the answers are compared with what the real extension and host
// gave on the stand (docs/JOURNAL.md, 2026-11-19).
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { repoRoot } from "../../scripts/fetch-vendor.ts";
import { caDir } from "../../scripts/provision-token.ts";
import { stand, standDir, userPin, venvPython } from "../../scripts/setup-stand.ts";
import { children, encode, read } from "../../src/page/asn1.ts";
import { digest } from "../../src/page/gost.ts";
import { parseCertificate, pemToDer } from "../../src/page/x509.ts";
import { clearSites, enableSite, launchStand, openStandPage, servePages, standExtension, type PageServer } from "./harness.ts";
import { envelopedInfo, verifyCms, verifyRaw } from "./verify.ts";

// A page as Kontur's client talks to the plug-in: one session, numbered commands, answers matched by commandId.
const KONTUR_PAGE = `<!doctype html><html><head><meta charset="utf-8"><title>Kontur</title></head><body><script>
let commandId = 0;
const waiting = new Map();
addEventListener("message", (event) => {
  if (!event.data || event.data.type !== "kontur-toolbox-response") return;
  const response = event.data.response;
  const resolve = waiting.get(response.commandId);
  if (resolve) { waiting.delete(response.commandId); resolve(JSON.parse(JSON.stringify(response))); }
});
window.kontur = (type, fields = {}, timeoutMs = 60000) => new Promise((resolve) => {
  const id = ++commandId;
  waiting.set(id, resolve);
  setTimeout(() => { if (waiting.delete(id)) resolve({ timeout: true }); }, timeoutMs);
  postMessage({ type: "kontur-toolbox-request", request: { sessionId: "s-test", commandId: id, type, ...fields } }, "*");
});
</script></body></html>`;

const userPem = readFileSync(join(standDir, "user.pem"), "utf8");
const user = parseCertificate(pemToDer(userPem));
const thumbprint = user.thumbprint.toLowerCase();
const byHash = { hasPrivateKey: true, hash: { data: thumbprint, size: 20, type: "hex" } };
const b64 = (bytes: Uint8Array | string) => Buffer.from(typeof bytes === "string" ? Buffer.from(bytes) : bytes).toString("base64");
const pinDialog = (page: Page) => page.locator("#rutoken-cades-bridge-pin [role=dialog]");

type Answer = { sessionId?: string; commandId?: number; result?: any; error?: { type: string; code?: number; message: string; context?: string }; timeout?: boolean };

const ask = (page: Page, type: string, fields: Record<string, unknown> = {}, timeoutMs?: number) =>
  page.evaluate(([t, f, ms]) => (window as unknown as { kontur: (...a: unknown[]) => Promise<Answer> }).kontur(t, f, ms), [type, fields, timeoutMs] as const) as Promise<Answer>;

let server: PageServer;
let context: BrowserContext;

test.beforeAll(async () => {
  server = await servePages({ "/kontur.html": { type: "text/html; charset=utf-8", body: KONTUR_PAGE } });
  context = await launchStand({ extensions: [stand.adapter, standExtension(["https://extern.kontur.ru/*"])] });
  await clearSites(context);
  await enableSite(context, server.url, ["kontur"]);
});

test.afterAll(async () => {
  await context?.close();
  await server?.close();
});

test("answers the extension's own commands and plugin.info as the real ones do, on a site that is not Kontur's", async () => {
  const page = await openStandPage(context, `${server.url}/kontur.html`);
  // No mark off Kontur's domains, as the real extension.
  expect(await page.locator("meta[kontur-toolbox-installed]").count()).toBe(0);
  expect(await ask(page, "extension.info")).toEqual({ sessionId: "s-test", commandId: 1, result: { id: "hnhppcgejeffnbnioloohhmndpmclaga", type: "chrome", version: "3.1.11" } });
  expect((await ask(page, "extension.info", { extensionId: "other" }, 1000)).timeout).toBe(true);
  const info = await ask(page, "plugin.info");
  // Enabled is allowed: not denied, unlike the real host off Kontur's domains (the owner, 2026-11-19).
  expect(info.result).toMatchObject({ architecture: "x86_64", buildType: "stable", denied: false, platform: "linux", pluginVersion: "4.15.1.6119" });
  expect(info.result.clientId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  expect((await ask(page, "no.such")).error).toEqual({ type: "plugin", code: 2, message: "PLUGIN[0x00000002] unknown command" });
  expect((await ask(page, "extension.uninstall", { extensionId: "hnhppcgejeffnbnioloohhmndpmclaga" })).error).toEqual({ type: "extension", message: "bad request" });
  // The client id is the extension's, the same on the next page.
  const next = await openStandPage(context, `${server.url}/kontur.html`);
  expect((await ask(next, "plugin.info")).result.clientId).toBe(info.result.clientId);
  await next.close();
  await page.close();
});

test("marks Kontur's own pages for the client", async () => {
  const site = "https://extern.kontur.ru";
  await enableSite(context, site, ["kontur"]);
  const page = await context.newPage();
  await page.route(`${site}/**`, (route) => route.fulfill({ contentType: "text/html; charset=utf-8", body: KONTUR_PAGE }));
  await page.goto(`${site}/kontur.html`);
  await expect(page.locator('meta[kontur-toolbox-installed="true"]')).toHaveCount(1, { timeout: 15_000 });
  expect((await ask(page, "extension.uninstall", { extensionId: "other" }, 1000)).timeout).toBe(true);
  await page.close();
});

// Signs through the extension's PIN window, as a user does: the window must show for the call to finish.
async function withPin(page: Page, call: Promise<Answer>, pin = userPin): Promise<Answer> {
  await pinDialog(page).locator("input[name=pin]").fill(pin);
  await pinDialog(page).locator("button[name=confirm]").click();
  return call;
}

test.describe("on the stand token", () => {
  let page: Page;

  test.beforeAll(async () => {
    page = await openStandPage(context, `${server.url}/kontur.html`);
  });

  test.afterAll(async () => {
    await page?.close();
  });

  test("lists the token, its provider, container and certificate as the host does", async () => {
    const [token] = (await ask(page, "crypto.getTokens")).result;
    expect(token).toMatchObject({ firmwareVersion: { major: 34, minor: 2 }, hardwareVersion: { major: 67, minor: 4 }, manufacturer: "Aktiv Co.", model: "Rutoken ECP", slot: "Aktiv Rutoken ECP 0", type: "PCSC" });
    expect(token.serialNumber).toMatch(/^[0-9A-F]{8}$/);
    expect(Object.keys(token)).toEqual(["firmwareVersion", "freeMemory", "hardwareVersion", "hasFlashDrive", "manufacturer", "model", "serialNumber", "slot", "supportsNfc", "totalMemory", "type"]);
    const provider = { slot: "Aktiv Rutoken ECP 0", token: "Rutoken ECP", type: "pkcs11", versionInfo: { major: 2, minor: 14 } };
    expect((await ask(page, "crypto.provider.search", { cryptoProviderType: "pkcs11" })).result).toEqual([provider]);
    expect((await ask(page, "crypto.getCryptoProviders")).result).toEqual([provider]);
    expect((await ask(page, "crypto.provider.search", { cryptoProviderType: "cryptoApi" })).result).toEqual([]);
    expect((await ask(page, "crypto.provider.getContainers", { provider, properties: { cert: { hash: true } } })).result).toEqual([
      { cert: { hash: byHash.hash }, name: `_HEX__${thumbprint}`, type: "pkcs11" },
    ]);
    expect((await ask(page, "crypto.provider.getContainers", { provider: { ...provider, slot: "nope" }, properties: {} })).error).toMatchObject({ type: "crypto", code: 53 });
    const all = { serialNumber: true, content: true, issuer: true, subject: true, validFrom: true, validTo: true, hasPrivateKey: true, qualified: true, extensions: true, cryptoProvider: true, containerInfo: true, publicKeyLength: true, publicKeyAlgorithm: true };
    const [found] = (await ask(page, "cert.search", { filter: { store: { storeType: "pkcs11" } }, properties: all })).result;
    expect(found).toMatchObject({
      containerInfo: { containerName: `_HEX__${thumbprint}`, provider: { slot: "Aktiv Rutoken ECP 0", token: "Rutoken ECP", type: "pkcs11" } },
      content: { data: Buffer.from(user.der).toString("base64"), size: user.der.length, type: "base64" },
      hasPrivateKey: true,
      hash: byHash.hash,
      publicKeyAlgorithm: "1.2.643.7.1.1.1.1",
      publicKeyLength: 512,
      qualified: false,
      extensions: { keyUsages: { dataEncipherment: true, digitalSignature: true, keyAgreement: true, keyEncipherment: true, nonRepudiation: true } },
    });
    expect(found.subject).toContainEqual({ CN: "Stand User" });
    expect(found.subject).toContainEqual({ СНИЛС: "00000000000" });
    expect((await ask(page, "cert.search", { filter: { store: { storeType: "pkcs11" } }, properties: {} })).result).toEqual([{ hash: byHash.hash }]);
    // CryptoAPI's stores: none on Linux, and no location taken, as the host there answers.
    expect((await ask(page, "cert.search", { filter: { store: { storeType: "cryptoApi", name: "My" } }, properties: {} })).result).toEqual([]);
    expect((await ask(page, "cert.search", { filter: { store: { storeType: "cryptoApi", name: "My", location: "CurrentUser" } }, properties: {} })).error).toEqual({ message: "invalid enumeration value" });
    const parsed = (await ask(page, "cert.parse", { cert: { content: { type: "base64", data: Buffer.from(user.der).toString("base64") } }, properties: { hasPrivateKey: true, containerInfo: true } })).result;
    expect(parsed).toEqual({ containerInfo: {}, hasPrivateKey: false, hash: byHash.hash });
    expect((await ask(page, "cert.parse", { cert: { content: { type: "base64", data: "AAAA" } }, properties: { hash: true } })).error).toMatchObject({ type: "crypto", code: 1 });
  });

  test("signs detached and attached, without attributes or the certificate, as PEM, from and to the cache; the verifiers accept them", async () => {
    const data = Buffer.from("Привет, Контур!");
    const source = { type: "base64", data: b64(data) };
    const detached = await withPin(page, ask(page, "crypto.sign", { source, sink: { type: "base64" }, certs: [byHash] }));
    expect(detached.result).toMatchObject({ type: "base64" });
    expect(verifyCms(detached.result.data, data)).toMatchObject({ valid: true, detached: true });
    const attached = await withPin(page, ask(page, "crypto.sign", { source, sink: { type: "base64" }, certs: [byHash], attached: true }));
    expect(verifyCms(attached.result.data)).toMatchObject({ valid: true, detached: false });
    const bare = await withPin(page, ask(page, "crypto.sign", { source, sink: { type: "base64" }, certs: [byHash], attached: true, includeAuthAttributes: false }));
    const bareReport = verifyCms(bare.result.data);
    expect(bareReport.valid).toBe(true);
    expect(bareReport.attributes).toEqual([]);
    const noCertificate = await withPin(page, ask(page, "crypto.sign", { source, sink: { type: "base64" }, certs: [byHash], includeSignCertificates: false }));
    expect((await ask(page, "crypto.verify", { source, signature: { type: "base64", data: noCertificate.result.data } })).result).toEqual([{ hash: byHash.hash }]);
    const pem = await withPin(page, ask(page, "crypto.sign", { source, sink: { type: "base64" }, certs: [byHash], textualEncoding: true }));
    expect(Buffer.from(pem.result.data, "base64").toString()).toMatch(/^-----BEGIN PKCS7-----\r\n[A-Za-z0-9+/=]+\r\n-----END PKCS7-----$/);
    const cached = await withPin(page, ask(page, "crypto.sign", { source, sink: { type: "cache", name: "sign" }, certs: [byHash] }));
    expect(cached.result).toEqual({ name: "sign", size: expect.any(Number), type: "cache" });
    expect((await ask(page, "crypto.verify", { source, signature: { type: "cache", name: "sign" } })).result).toEqual([{ hash: byHash.hash }]);
    expect((await ask(page, "crypto.verify", { source: { type: "base64", data: b64("other") }, signature: { type: "cache", name: "sign" } })).result).toEqual([]);
    expect((await ask(page, "crypto.verify", { source: { type: "base64", data: attached.result.data } })).result).toEqual([{ hash: byHash.hash }]);
    expect((await ask(page, "crypto.sign", { source: { type: "cache", name: "nope" }, sink: { type: "base64" }, certs: [byHash] })).error).toMatchObject({ type: "plugin", code: 101 });
    expect((await ask(page, "crypto.sign", { source, sink: { type: "base64" }, certs: [{ hash: { data: "00".repeat(20), type: "hex" } }] })).error).toMatchObject({ type: "plugin", code: 200 });
    expect((await ask(page, "crypto.sign", { source, sink: { type: "text" }, certs: [byHash] })).error).toMatchObject({ type: "plugin", code: 3 });
    expect(await pinDialog(page).count()).toBe(0);
  });

  test("signs several documents in one PIN window, a hash, and a bare signature; adds a signer; parses", async () => {
    const one = Buffer.from("первый");
    const two = Buffer.from("второй");
    const batch = await withPin(page, ask(page, "crypto.batch.sign", { source: [{ type: "base64", data: b64(one) }, { type: "base64", data: b64(two) }], sink: [{ type: "base64" }, { type: "hex" }], certs: [byHash] }));
    expect(verifyCms(batch.result[0].data, one).valid).toBe(true);
    expect(verifyCms(Buffer.from(batch.result[1].data, "hex").toString("base64"), two).valid).toBe(true);
    const hashed = await withPin(page, ask(page, "crypto.signHash", { hashes: { "1.2.643.7.1.1.2.2": { type: "hex", data: Buffer.from(digest("streebog256", one)).toString("hex") }, "1.2.643.7.1.1.2.3": { type: "hex", data: "22".repeat(64) } }, sink: { type: "base64" }, certs: [byHash] }));
    expect(verifyCms(hashed.result.data, one)).toMatchObject({ valid: true, detached: true });
    expect((await ask(page, "crypto.signHash", { hashes: { "1.2.643.7.1.1.2.3": { type: "hex", data: "22".repeat(64) } }, sink: { type: "base64" }, certs: [byHash] })).error).toMatchObject({ type: "crypto", code: 36 });
    const raw = await withPin(page, ask(page, "crypto.rawSign", { source: { type: "base64", data: b64(one) }, sink: { type: "hex" }, cert: byHash }));
    expect(raw.result.size).toBe(64);
    expect(verifyRaw(userPem, one, raw.result.data).valid).toBe(true);
    expect((await ask(page, "crypto.rawVerify", { source: { type: "base64", data: b64(one) }, signature: { type: "hex", data: raw.result.data }, cert: byHash })).result).toBe(true);
    expect((await ask(page, "crypto.rawVerify", { source: { type: "base64", data: b64(two) }, signature: { type: "hex", data: raw.result.data }, cert: { content: { type: "base64", data: Buffer.from(user.der).toString("base64") } } })).result).toBe(false);
    const attached = await withPin(page, ask(page, "crypto.sign", { source: { type: "base64", data: b64(one) }, sink: { type: "base64" }, certs: [byHash], attached: true }));
    const cosigned = await withPin(page, ask(page, "crypto.signature.addSigner", { source: { type: "base64", data: attached.result.data }, sink: { type: "base64" }, certs: [byHash] }));
    expect(verifyCms(cosigned.result.data).valid).toBe(true);
    expect((await ask(page, "crypto.verify", { source: { type: "base64", data: cosigned.result.data } })).result).toEqual([{ hash: byHash.hash }, { hash: byHash.hash }]);
    const parts = await ask(page, "crypto.signature.parse", { source: { type: "base64", data: cosigned.result.data }, properties: { content: { type: "base64" }, certs: { hash: true } } });
    expect(parts.result).toEqual({ certs: [{ hash: byHash.hash }, { hash: byHash.hash }], content: { data: b64(one), size: one.length, type: "base64" } });
    expect(await ask(page, "crypto.signature.parse", { source: { type: "base64", data: cosigned.result.data } })).toEqual({ commandId: expect.any(Number), sessionId: "s-test" });
  });

  test("encrypts with GOST 28147-89 for the token's certificate without a PIN, as the host, decrypts it back after the PIN; parses as the host", async () => {
    // Over 1024 bytes, so that CryptoPro's key meshing changes the content key.
    const data = Buffer.from("Секрет Контура. ".repeat(200));
    const encrypted = await ask(page, "crypto.encrypt", { source: { type: "base64", data: b64(data) }, sink: { type: "base64" }, certs: [byHash] });
    const info = envelopedInfo(encrypted.result.data);
    expect(info.content_encryption).toBe("1.2.643.2.2.21");
    expect(info.content_param_set).toBe("1.2.643.2.2.31.1");
    expect(info.recipients).toEqual([expect.objectContaining({ kind: "ktri", serial: user.serialNumber.replace(/^0+/, "") })]);
    const message = { type: "base64", data: encrypted.result.data };
    const parsed = await ask(page, "crypto.encryption.parse", { source: message, properties: { recipient: { issuer: true, serialNumber: { type: "hex" } }, encryptedContentInfo: { contentEncryptionAlgorithm: true } } });
    expect(parsed.result).toEqual({
      encryptedContentInfo: { contentEncryptionAlgorithm: { algorithm: "1.2.643.2.2.21" } },
      recipients: [{ issuer: [{ C: "RU" }, { O: "Стенд" }, { CN: "Stand Test CA" }], serialNumber: { data: user.serialNumber.toLowerCase(), size: user.serialNumber.length / 2, type: "hex" } }],
    });
    expect(await ask(page, "crypto.encryption.parse", { source: message, properties: {} })).toEqual({ commandId: expect.any(Number), sessionId: "s-test" });
    const decrypted = await withPin(page, ask(page, "crypto.decrypt", { source: message, sink: { type: "base64" } }));
    expect(Buffer.from(decrypted.result.data, "base64").equals(data)).toBe(true);
    expect((await ask(page, "crypto.decrypt", { source: { type: "base64", data: "AAAA" }, sink: { type: "base64" } })).result).toEqual({ data: "", size: 0, type: "base64" });
    expect((await ask(page, "crypto.encrypt", { source: message, sink: { type: "base64" }, certs: [byHash], encryptionAlgorithm: "1.2.643.7.1.1.5.2.1" })).error).toMatchObject({ type: "crypto", code: 10 });
    expect((await ask(page, "crypto.encrypt", { source: message, sink: { type: "base64" }, certs: [byHash], encryptionAlgorithm: "GOST28147" })).error).toMatchObject({ type: "crypto", code: 24 });
  });

  test("answers a cancelled PIN window as the host's cancelled one", async () => {
    const call = ask(page, "crypto.sign", { source: { type: "base64", data: b64("x") }, sink: { type: "base64" }, certs: [byHash] });
    await pinDialog(page).locator("button[name=cancel]").click();
    expect((await call).error).toEqual({ code: 51, context: "", message: "CRYPTO[0x00000033] the pkcs11 session is not authorized", type: "crypto" });
  });
});

// Keys and certificates are made on a copy of the stand HOME, removed afterwards, so the stand's token keeps its one
// certificate. The stand's browser is closed first: the Rutoken adapter of a second one meanwhile does not answer.
test.describe("on a copy of the token", () => {
  const outDir = join(standDir, "kontur-issuance");
  const home = join(outDir, "home");
  let copy: BrowserContext;
  let page: Page;

  test.beforeAll(async () => {
    await context.close();
    rmSync(outDir, { recursive: true, force: true });
    mkdirSync(outDir, { recursive: true });
    cpSync(stand.home, home, { recursive: true, verbatimSymlinks: true });
    copy = await launchStand({ home, extensions: [stand.adapter, standExtension()] });
    await clearSites(copy);
    await enableSite(copy, server.url, ["kontur"]);
    page = await openStandPage(copy, `${server.url}/kontur.html`);
  });

  test.afterAll(async () => {
    await copy?.close();
    rmSync(outDir, { recursive: true, force: true });
  });

  // CN=Запрос Контура, C=RU; keyUsage digitalSignature+nonRepudiation; challengePassword "test".
  const subject = "MDMxJDAiBgNVBAMMG9CX0LDQv9GA0L7RgSDQmtC+0L3RgtGD0YDQsDELMAkGA1UEBhMCUlU=";
  const extensions = "MBAwDgYDVR0PAQH/BAQDAgbA";
  const attribute = "MBMGCSqGSIb3DQEJBzEGDAR0ZXN0";
  const stream = (data: string) => ({ type: "base64", data });

  test("makes a key and a request as the host, installs the issued certificate next to the key and signs with it", async () => {
    const [provider] = (await ask(page, "crypto.provider.search", { cryptoProviderType: "pkcs11" })).result;
    const fields = { cryptoProvider: provider, sink: { type: "base64" }, signatureAlgorithm: "1.2.643.7.1.1.3.2", subject: stream(subject), extensions: stream(extensions), attributes: [stream(attribute)] };
    const made = await withPin(page, ask(page, "crypto.createCertRequest", fields));
    expect(made.result.path).toMatch(new RegExp(`^${provider.slot}\\\\[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`));
    const der = Buffer.from(made.result.request.data, "base64");
    // The site's subject and extensions as they came, its attribute after the extension request; the host's
    // parameters (CryptoPro XchA) and no NULL after the signature algorithm.
    const [info, algorithm] = children(read(der));
    const [, name, publicKey, attributes] = children(info!);
    expect(Buffer.from(name!.der).toString("base64")).toBe(subject);
    expect(Buffer.from(children(children(publicKey!)[0]!)[1]!.der).toString("hex")).toBe("301306072a85030202240006082a85030701010202");
    const extensionRequest = encode(0x30, Buffer.from("06092a864886f70d01090e", "hex"), encode(0x31, Buffer.from(extensions, "base64")));
    expect(Buffer.from(attributes!.der).toString("base64")).toBe(Buffer.from(encode(0xa0, extensionRequest, Buffer.from(attribute, "base64"))).toString("base64"));
    expect(Buffer.from(algorithm!.der).toString("hex")).toBe("300a06082a85030701010302");
    // The test CA checks the request's signature before it issues.
    writeFileSync(join(outDir, "kontur.csr.pem"), `-----BEGIN CERTIFICATE REQUEST-----\n${made.result.request.data}\n-----END CERTIFICATE REQUEST-----\n`);
    execFileSync(venvPython, [join(repoRoot, "tests", "tools", "gost_ca.py"), "issue", caDir, join(outDir, "kontur.csr.pem"), join(outDir, "kontur.pem")]);
    const issued = parseCertificate(pemToDer(readFileSync(join(outDir, "kontur.pem"), "utf8")));
    const install = { cryptoProvider: provider, cert: stream(Buffer.from(issued.der).toString("base64")) };
    expect(await withPin(page, ask(page, "crypto.installCert", install))).toEqual({ commandId: expect.any(Number), sessionId: "s-test" });
    // There already: no PIN.
    expect(await ask(page, "crypto.installCert", install)).toEqual({ commandId: expect.any(Number), sessionId: "s-test" });
    const hash = { data: issued.thumbprint.toLowerCase(), size: 20, type: "hex" };
    const found = await ask(page, "cert.search", { filter: { store: { storeType: "pkcs11" }, hash }, properties: { hasPrivateKey: true } });
    expect(found.result).toEqual([{ hasPrivateKey: true, hash }]);
    const signed = await withPin(page, ask(page, "crypto.sign", { source: stream(b64("Новым ключом")), sink: { type: "base64" }, certs: [{ hash }], attached: true }));
    expect(verifyCms(signed.result.data).valid).toBe(true);
    // A certificate without its key on the token: the host's 203, after the PIN as there.
    const caPem = readFileSync(join(caDir, "ca.pem"), "utf8").replace(/-----[^-]+-----|\s/g, "");
    expect((await withPin(page, ask(page, "crypto.installCert", { cryptoProvider: provider, cert: stream(caPem) }))).error).toEqual({ code: 203, message: "PLUGIN[0x000000CB] can not find container corresponding to the certificate", type: "plugin" });
  });

  test("names the container as the site asks, makes 512-bit keys, and refuses as the host", async () => {
    const [provider] = (await ask(page, "crypto.provider.search", { cryptoProviderType: "pkcs11" })).result;
    const base = { sink: { type: "base64" }, subject: stream(subject), extensions: stream("MAA=") };
    const made = await withPin(page, ask(page, "crypto.createCertRequest", { ...base, cryptoProvider: { ...provider, containerName: "kontur-key" }, signatureAlgorithm: "1.2.643.7.1.1.3.3" }));
    expect(made.result.path).toBe(`${provider.slot}\\kontur-key`);
    const [info] = children(read(Buffer.from(made.result.request.data, "base64")));
    expect(Buffer.from(children(children(children(info!)[2]!)[0]!)[1]!.der).toString("hex")).toBe("301506092a8503070102010201" + "06082a85030701010203");
    const refused = async (fields: Record<string, unknown>) => (await ask(page, "crypto.createCertRequest", { ...base, cryptoProvider: provider, signatureAlgorithm: "1.2.643.7.1.1.3.2", ...fields })).error;
    expect(await refused({ cryptoProvider: { ...provider, slot: "nope" } })).toEqual({ code: 53, context: "", message: "CRYPTO[0x00000035] unable to find a token for the specified slot", type: "crypto" });
    expect(await refused({ signatureAlgorithm: "1.2.3" })).toEqual({ code: 23, context: "", message: "CRYPTO[0x00000017] unknown signature algorithm", type: "crypto" });
    expect(await refused({ subject: stream("AAAA") })).toEqual({ code: 17, context: "", message: "ASN1[0x00000011] an error occurred while decoding asn.1 value", type: "asn1" });
    expect(await refused({ extensions: undefined })).toMatchObject({ code: 3, type: "plugin" });
    expect(await refused({ cryptoProvider: { type: "cryptoApi", name: "Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider", id: 80, containerName: "x" } })).toEqual({
      code: 0x20002000,
      context: "CryptAcquireContext",
      message: "WIN32[0x20002000]CryptAcquireContext CryptoPro module not loaded",
      type: "system",
    });
    const cert = { content: stream(Buffer.from(user.der).toString("base64")) };
    expect((await ask(page, "cert.store.install", { cert, store: { type: "cryptoApi", name: "My" } })).error).toMatchObject({ context: "CertCreateCertificateContext", type: "system" });
    expect((await ask(page, "cert.store.remove", { cert, store: { type: "cryptoApi", name: "My" } })).error).toMatchObject({ context: "CertOpenStore", type: "system" });
    expect((await ask(page, "cert.store.install", { cert, store: { type: "pkcs11" } })).error).toEqual({ code: 250, message: "PLUGIN[0x000000FA] cryptoprovider type unsupported", type: "plugin" });
    expect((await ask(page, "cert.store.remove", { cert: { hash: { type: "hex", data: "00" } }, store: { type: "cryptoApi" } })).error).toEqual({ code: 200, message: "PLUGIN[0x000000C8] certificate not found", type: "plugin" });
  });
});
