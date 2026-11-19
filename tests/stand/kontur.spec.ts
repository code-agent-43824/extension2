// The extension as Kontur.Plugin on the fake Rutoken: a page posts kontur-toolbox-request messages as Kontur's client
// does and reads the kontur-toolbox-response ones; the answers are compared with what the real extension and host
// gave on the stand (docs/JOURNAL.md, 2026-11-19).
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { stand, standDir, userPin } from "../../scripts/setup-stand.ts";
import { digest } from "../../src/page/gost.ts";
import { parseCertificate, pemToDer } from "../../src/page/x509.ts";
import { clearSites, enableSite, launchStand, openStandPage, servePages, standExtension, type PageServer } from "./harness.ts";
import { verifyCms, verifyRaw } from "./verify.ts";

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

  test("answers a cancelled PIN window as the host's cancelled one", async () => {
    const call = ask(page, "crypto.sign", { source: { type: "base64", data: b64("x") }, sink: { type: "base64" }, certs: [byHash] });
    await pinDialog(page).locator("button[name=cancel]").click();
    expect((await call).error).toEqual({ code: 51, context: "", message: "CRYPTO[0x00000033] the pkcs11 session is not authorized", type: "crypto" });
  });
});
