// The opt-in comparison with the real Kontur.Plugin (docs/PLAN.md, action 62): the same requests to its host 4.15.1 and
// to the extension playing it, on the same copy of the token (scripts/setup-kontur.ts), the answers compared where
// they must agree; each side checks the other's signatures. Run after `npm run build` and `node scripts/setup-kontur.ts`:
// STAND_KONTUR=1 npx playwright test tests/stand/kontur-reference.spec.ts
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { kontur } from "../../scripts/setup-kontur.ts";
import { stand, userPin } from "../../scripts/setup-stand.ts";
import { BUILTIN_ROOTS } from "../../src/extension/builtin-roots.ts";
import { clearSites, enableSite, launchStand, openStandPage, servePages, standExtension, type PageServer } from "./harness.ts";
import { konturHost, type KonturAnswer, type KonturHost } from "./kontur.ts";

test.skip(!process.env.STAND_KONTUR || !existsSync(kontur.home), "needs the real host: node scripts/setup-kontur.ts, then STAND_KONTUR=1");

const PAGE = `<!doctype html><html><head><meta charset="utf-8"><title>reference</title></head><body><script>
let commandId = 0;
const waiting = new Map();
addEventListener("message", (event) => {
  if (!event.data || event.data.type !== "kontur-toolbox-response") return;
  const resolve = waiting.get(event.data.response.commandId);
  if (resolve) { waiting.delete(event.data.response.commandId); resolve(JSON.parse(JSON.stringify(event.data.response))); }
});
window.kontur = (type, fields) => new Promise((resolve) => {
  const id = ++commandId;
  waiting.set(id, resolve);
  postMessage({ type: "kontur-toolbox-request", request: { sessionId: "s-ref", commandId: id, type, ...fields } }, "*");
});
</script></body></html>`;

let server: PageServer;
let context: BrowserContext;
let page: Page;
let host: KonturHost;

test.beforeAll(async () => {
  server = await servePages({ "/ref.html": { type: "text/html; charset=utf-8", body: PAGE } });
  context = await launchStand({ home: kontur.home, extensions: [stand.adapter, standExtension()] });
  await clearSites(context);
  await enableSite(context, server.url, ["kontur"]);
  page = await openStandPage(context, `${server.url}/ref.html`);
  host = konturHost();
});

test.afterAll(async () => {
  host?.close();
  await context?.close();
  await server?.close();
});

const pinDialog = () => page.locator("#rutoken-cades-bridge-pin [role=dialog]");

// The extension's answer; `pin` when the call opens the PIN window (the host signs in with the stand's PIN, which is
// its default, without a window).
async function ours(type: string, fields: Record<string, unknown> = {}, pin = false): Promise<KonturAnswer> {
  const call = page.evaluate(([t, f]) => (window as unknown as { kontur: (...a: unknown[]) => Promise<KonturAnswer> }).kontur(t, f), [type, fields] as const);
  if (pin) {
    await pinDialog().locator("input[name=pin]").fill(userPin);
    await pinDialog().locator("button[name=confirm]").click();
  }
  return call;
}

const theirs = (type: string, fields: Record<string, unknown> = {}) => host.ask(type, fields);
// What must agree: the result or the error, without the envelope.
const outcome = (answer: KonturAnswer) => ("error" in answer ? { error: answer.error } : { result: answer.result });

const all = { serialNumber: true, content: true, issuer: true, subject: true, validFrom: true, validTo: true, hasPrivateKey: true, qualified: true, extensions: true, cryptoProvider: true, containerInfo: true, publicKeyLength: true, publicKeyAlgorithm: true };

test("lists the token, the provider, containers and certificates as the host does, names and versions aside", async () => {
  // The memory is the plug-in's, the fork's PKCS#11 "unavailable" to the host; the library version is the one the
  // host carries, not the fork's; containers go by thumbprint (docs/JOURNAL.md, 2026-11-19).
  const tokens = (answer: KonturAnswer) => answer.result.map(({ freeMemory: _, totalMemory: __, ...rest }: Record<string, unknown>) => rest);
  expect(tokens(await ours("crypto.getTokens"))).toEqual(tokens(await theirs("crypto.getTokens")));
  const providers = (answer: KonturAnswer) => answer.result.map(({ versionInfo: _, ...rest }: Record<string, unknown>) => rest);
  expect(providers(await ours("crypto.provider.search", { cryptoProviderType: "pkcs11" }))).toEqual(providers(await theirs("crypto.provider.search", { cryptoProviderType: "pkcs11" })));
  expect(outcome(await ours("crypto.provider.search", { cryptoProviderType: "cryptoApi" }))).toEqual(outcome(await theirs("crypto.provider.search", { cryptoProviderType: "cryptoApi" })));
  const [provider] = (await theirs("crypto.provider.search")).result;
  const containers = (answer: KonturAnswer) => answer.result.map(({ name: _, ...rest }: Record<string, unknown>) => rest);
  const request = { provider, properties: { cert: all } };
  expect(containers(await ours("crypto.provider.getContainers", request))).toEqual(containers(await theirs("crypto.provider.getContainers", request)));
  const search = { filter: { store: { storeType: "pkcs11" } }, properties: all };
  const certificates = (answer: KonturAnswer) =>
    answer.result.map(({ containerInfo, ...rest }: Record<string, any>) => ({ ...rest, containerInfo: { ...containerInfo, containerName: undefined } })).sort((a: any, b: any) => a.hash.data.localeCompare(b.hash.data));
  expect(certificates(await ours("cert.search", search))).toEqual(certificates(await theirs("cert.search", search)));
  for (const filter of [{ store: { storeType: "pkcs11", slot: "nope" } }, { store: { storeType: "pkcs11" }, qualified: true }, { store: { storeType: "cryptoApi", name: "My" } }]) {
    expect(outcome(await ours("cert.search", { filter, properties: {} })), JSON.stringify(filter)).toEqual(outcome(await theirs("cert.search", { filter, properties: {} })));
  }
});

test("parses certificates as the host does: the built-in roots and the stand's", async () => {
  const contents = [...BUILTIN_ROOTS, readFileSync(join(kontur.dir, "..", "user.pem"), "utf8").replace(/-----[^-]+-----|\s/g, "")];
  for (const data of contents) {
    const request = { cert: { content: { type: "base64", data } }, properties: all };
    expect(outcome(await ours("cert.parse", request)), data.slice(0, 40)).toEqual(outcome(await theirs("cert.parse", request)));
  }
  for (const request of [{ cert: { content: { type: "base64", data: "AAAA" } }, properties: { hash: true } }, { cert: { content: { type: "base64", data: contents[0] } }, properties: {} }]) {
    expect(outcome(await ours("cert.parse", request))).toEqual(outcome(await theirs("cert.parse", request)));
  }
});

test("each side verifies the other's signatures, and both refuse the same mistakes alike", async () => {
  const [certificate] = (await theirs("cert.search", { filter: { store: { storeType: "pkcs11" } }, properties: { content: true } })).result;
  const cert = { hasPrivateKey: true, hash: certificate.hash };
  const data = { type: "base64", data: Buffer.from("Сверка с эталоном").toString("base64") };
  for (const flags of [{}, { attached: true }, { includeAuthAttributes: false, attached: true }]) {
    const request = { source: data, sink: { type: "base64" }, certs: [cert], ...flags };
    const mine = (await ours("crypto.sign", request, true)).result.data;
    const their = (await theirs("crypto.sign", request)).result.data;
    const check = (signature: string) => ("attached" in flags ? { source: { type: "base64", data: signature } } : { source: data, signature: { type: "base64", data: signature } });
    expect((await theirs("crypto.verify", check(mine))).result, `the host on ours, ${JSON.stringify(flags)}`).toEqual([{ hash: certificate.hash }]);
    expect((await ours("crypto.verify", check(their))).result, `ours on the host's, ${JSON.stringify(flags)}`).toEqual([{ hash: certificate.hash }]);
  }
  const raw = { source: data, sink: { type: "base64" }, cert };
  const myRaw = (await ours("crypto.rawSign", raw, true)).result;
  const theirRaw = (await theirs("crypto.rawSign", raw)).result;
  expect((await theirs("crypto.rawVerify", { source: data, signature: myRaw, cert })).result).toBe(true);
  expect((await ours("crypto.rawVerify", { source: data, signature: theirRaw, cert })).result).toBe(true);
  const attached = (await theirs("crypto.sign", { source: data, sink: { type: "base64" }, certs: [cert], attached: true })).result.data;
  const cosigned = (await ours("crypto.signature.addSigner", { source: { type: "base64", data: attached }, sink: { type: "base64" }, certs: [cert] }, true)).result.data;
  expect((await theirs("crypto.verify", { source: { type: "base64", data: cosigned } })).result).toEqual([{ hash: certificate.hash }, { hash: certificate.hash }]);
  const parse = { source: { type: "base64", data: cosigned }, properties: { content: { type: "base64" }, certs: { hash: true, subject: true } } };
  expect(outcome(await ours("crypto.signature.parse", parse))).toEqual(outcome(await theirs("crypto.signature.parse", parse)));
  // Encryption: each side opens the other's message, both parse alike; over 1024 bytes, so that CryptoPro's key
  // meshing changes the content key. Neither asks for a PIN to encrypt.
  const long = { type: "base64", data: Buffer.from("Сверка шифрования с эталоном. ".repeat(100)).toString("base64") };
  const myMessage = (await ours("crypto.encrypt", { source: long, sink: { type: "base64" }, certs: [cert] })).result.data;
  const theirMessage = (await theirs("crypto.encrypt", { source: long, sink: { type: "base64" }, certs: [cert] })).result.data;
  const openedMine = await theirs("crypto.decrypt", { source: { type: "base64", data: myMessage }, sink: { type: "base64" } });
  expect(openedMine.error, "the host on our message").toBeUndefined();
  expect(openedMine.result.data).toBe(long.data);
  const openedTheirs = await ours("crypto.decrypt", { source: { type: "base64", data: theirMessage }, sink: { type: "base64" } }, true);
  expect(openedTheirs.error, "ours on the host's message").toBeUndefined();
  expect(openedTheirs.result.data).toBe(long.data);
  const encParse = { properties: { recipient: { issuer: true, serialNumber: { type: "hex" } }, encryptedContentInfo: { contentEncryptionAlgorithm: true } } };
  expect(outcome(await ours("crypto.encryption.parse", { source: { type: "base64", data: myMessage }, ...encParse }))).toEqual(outcome(await theirs("crypto.encryption.parse", { source: { type: "base64", data: theirMessage }, ...encParse })));
  for (const [type, request] of [
    ["crypto.encrypt", { source: data, sink: { type: "base64" }, certs: [cert], encryptionAlgorithm: "1.2.643.7.1.1.5.2.1" }],
    ["crypto.encrypt", { source: data, sink: { type: "base64" }, certs: [cert], encryptionAlgorithm: "GOST28147" }],
    ["crypto.encrypt", { source: data, sink: { type: "base64" } }],
    ["crypto.decrypt", { source: { type: "base64", data: "AAAA" }, sink: { type: "base64" } }],
    ["crypto.encryption.parse", { source: { type: "base64", data: "AAAA" }, properties: { encryptedContentInfo: { contentEncryptionAlgorithm: true } } }],
    ["no.such", {}],
    ["crypto.sign", { source: data, sink: { type: "base64" } }],
    ["crypto.sign", { source: data, sink: { type: "text" }, certs: [cert] }],
    ["crypto.sign", { source: { type: "cache", name: "nope" }, sink: { type: "base64" }, certs: [cert] }],
    ["crypto.sign", { source: data, sink: { type: "base64" }, certs: [{ hash: { data: "00".repeat(20), type: "hex" } }] }],
    ["crypto.signHash", { hashes: { "1.2.643.7.1.1.2.3": { type: "hex", data: "22".repeat(64) } }, sink: { type: "base64" }, certs: [cert] }],
    ["crypto.signHash", { hashes: { "1.2.643.7.1.1.2.2": { type: "hex", data: "11".repeat(16) } }, sink: { type: "base64" }, certs: [cert] }],
    ["crypto.verify", { source: { type: "base64", data: "AAAA" } }],
    ["progress", { target: 1 }],
  ] as const) {
    // A fresh host for each: after some errors the host leaves a PKCS#11 object search open and answers the next
    // signature with "certificate not found" (docs/JOURNAL.md, 2026-11-19).
    const fresh = konturHost();
    try {
      expect(outcome(await ours(type, request)), `${type} ${JSON.stringify(request)}`).toEqual(outcome(await fresh.ask(type, request)));
    } finally {
      fresh.close();
    }
  }
});
