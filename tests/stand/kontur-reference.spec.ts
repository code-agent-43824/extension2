// The opt-in comparison with the real Kontur.Plugin (docs/PLAN.md, action 62): the same requests to its host 4.15.1 and
// to the extension playing it, on the same copy of the token (scripts/setup-kontur.ts), the answers compared where
// they must agree; each side checks the other's signatures. Run after `npm run build` and `node scripts/setup-kontur.ts`:
// STAND_KONTUR=1 npx playwright test tests/stand/kontur-reference.spec.ts
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { repoRoot } from "../../scripts/fetch-vendor.ts";
import { caDir } from "../../scripts/provision-token.ts";
import { kontur } from "../../scripts/setup-kontur.ts";
import { stand, standDir, userPin, venvPython } from "../../scripts/setup-stand.ts";
import { children, read } from "../../src/page/asn1.ts";
import { QUALIFIED_CASES, SWITCH_CASES } from "../unit/kontur-certificates.ts";
import { BUILTIN_ROOTS } from "../../src/extension/builtin-roots.ts";
import { clearSites, enableSite, launchStand, openStandPage, servePages, standExtension, type PageServer } from "./harness.ts";
import { echoServer, konturHost, type KonturAnswer, type KonturHost } from "./kontur.ts";

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

const pinDialog = (on: Page) => on.locator("#rutoken-cades-bridge-pin [role=dialog]");

// The extension's answer in the page `on`; `pin` when the call opens the PIN window (the host signs in with the
// stand's PIN, which is its default, without a window).
async function ask(on: Page, type: string, fields: Record<string, unknown> = {}, pin = false): Promise<KonturAnswer> {
  const call = on.evaluate(([t, f]) => (window as unknown as { kontur: (...a: unknown[]) => Promise<KonturAnswer> }).kontur(t, f), [type, fields] as const);
  if (pin) {
    await pinDialog(on).locator("input[name=pin]").fill(userPin);
    await pinDialog(on).locator("button[name=confirm]").click();
  }
  return call;
}

const ours = (type: string, fields: Record<string, unknown> = {}, pin = false) => ask(page, type, fields, pin);

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
  // Not CryptoAPI's My: the tokens' certificates are there on purpose (CLAUDE.md), the host has none.
  for (const filter of [{ store: { storeType: "pkcs11", slot: "nope" } }, { store: { storeType: "pkcs11" }, qualified: true }, { store: { storeType: "cryptoApi", name: "Root", location: "user" } }, { store: { storeType: "cryptoApi", name: "My", location: "other" } }]) {
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

test("applies the qualified rules as the host, with its messages, and converts text alike", async () => {
  for (const { label, der, rules } of QUALIFIED_CASES) {
    const cert = { content: { type: "base64", data: Buffer.from(der).toString("base64") } };
    const verify = { cert, qualified: { log: true } };
    const their = outcome(await theirs("cert.verify", verify));
    expect(their.result?.errors?.map((failure: { rule: string }) => failure.rule), `the host on ${label}`).toEqual(rules);
    expect(outcome(await ours("cert.verify", verify)), label).toEqual(their);
    const parse = { cert, properties: { qualified: true } };
    expect(outcome(await ours("cert.parse", parse)), label).toEqual(outcome(await theirs("cert.parse", parse)));
  }
  for (const { label, der, rules, switches } of SWITCH_CASES) {
    const verify = { cert: { content: { type: "base64", data: Buffer.from(der).toString("base64") } }, qualified: { log: true, rules: switches } };
    const their = outcome(await theirs("cert.verify", verify));
    expect(their.result?.errors?.map((failure: { rule: string }) => failure.rule), `the host on ${label}`).toEqual(rules);
    expect(outcome(await ours("cert.verify", verify)), label).toEqual(their);
  }
  const user = { content: { type: "base64", data: readFileSync(join(standDir, "user.pem"), "utf8").replace(/-----[^-]+-----|\s/g, "") } };
  const hex = (data: string) => ({ type: "hex", data });
  for (const [type, request] of [
    ["cert.verify", { cert: user, qualified: true }],
    ["cert.verify", { cert: user, qualified: { log: false } }],
    ["cert.verify", { cert: user, qualified: { log: "yes" } }],
    ["cert.verify", { cert: user, qualified: { log: true, rules: [] } }],
    ["cert.verify", { cert: user, qualified: { log: true, rules: {} } }],
    ["cert.verify", { cert: user, qualified: { log: true, rules: ["subject.cn.exist"] } }],
    ["cert.verify", { cert: user, qualified: { log: true, rules: { "no.such.rule": true } } }],
    ["cert.verify", { cert: user, qualified: { log: true, rules: { "subject.cn.exist": 1 } } }],
    ["cert.verify", { cert: user, qualified: { log: true, rules: { "subject.type.valid": true } } }],
    ["cert.verify", { cert: user, qualified: { log: true, rules: { "extensions.exist": false } } }],
    ["cert.verify", { cert: { content: { type: "base64", data: "AAAA" } }, qualified: { log: true } }],
    ["cert.verify", { cert: { hash: { type: "hex", data: "00" } }, qualified: { log: true } }],
    ["cert.verify", {}],
    ["cert.display", { cert: user }],
    ["io.decode", { source: { type: "base64", data: "z/Do4uXy" }, codePage: 1251 }],
    // Without a code page: what is certain (src/page/kontur/text.ts).
    ["io.decode", { source: { type: "base64", data: "0J/RgNC40LLQtdGC" } }],
    ["io.decode", { source: hex("c3") }],
    ["io.decode", { source: hex("48656c6c6f") }],
    ["io.decode", { source: hex("") }],
    ["io.decode", { source: hex("fffe1f044004") }],
    ["io.decode", { source: hex("ff98"), codePage: 1251 }],
    ["io.decode", { source: hex("8fe0a8a2a5e2"), codePage: 866 }],
    ["io.decode", { source: hex("f0d2c9d7c5d4"), codePage: 20866 }],
    ["io.decode", { source: hex("1f0440043804"), codePage: 1200 }],
    ["io.decode", { source: hex("cff0"), codePage: 28595 }],
    ["io.decode", { source: hex("8081"), codePage: 1252 }],
    ["io.decode", { source: hex("cff0"), codePage: 12345 }],
    ["io.decode", { source: hex("cff0"), codePage: "1251" }],
    ["io.encode", { value: "Привет", codePage: 1251, sink: { type: "base64" } }],
    ["io.encode", { value: "Привет ё№", sink: { type: "hex" } }],
    ["io.encode", { value: "Привет", codePage: 866, sink: { type: "hex" } }],
    ["io.encode", { value: "Привет", codePage: 21866, sink: { type: "hex" } }],
    ["io.encode", { value: "Привет", codePage: 1201, sink: { type: "hex" } }],
    ["io.encode", { value: "€", codePage: 1252, sink: { type: "hex" } }],
    ["io.encode", { value: "日本", codePage: 1251, sink: { type: "hex" } }],
    ["io.encode", { value: "Привет", codePage: 10007, sink: { type: "hex" } }],
    ["io.encode", { value: "Привет", codePage: 28591, sink: { type: "hex" } }],
    ["io.encode", { value: 5, sink: { type: "hex" } }],
    ["io.encode", { value: "x", codePage: 1251 }],
  ] as const) {
    expect(outcome(await ours(type, request)), `${type} ${JSON.stringify(request).slice(0, 120)}`).toEqual(outcome(await theirs(type, request)));
  }
});

test("makes HTTP requests that reach the server alike, and fails alike", async () => {
  const echo = await echoServer();
  try {
    const gzipped = "H4sIADgv/2oC/8tIzcnJBwCGphA2BQAAAA==";
    // What the server got and what came back, without what only one side sends (the browser's own headers).
    const seen = (answer: KonturAnswer) => {
      if ("error" in answer) return { error: answer.error };
      const sent = JSON.parse(Buffer.from(answer.result.content.data, "base64").toString("latin1"));
      const type = String(sent.headers["content-type"] ?? "").replace(/boundary=.*/, "boundary=");
      return { status: answer.result.statusCode, reason: answer.result.statusLine.reasonPhrase, method: sent.method, path: sent.path, type, body: type.startsWith("multipart") ? undefined : sent.body };
    };
    for (const request of [
      { uri: `${echo.url}/get`, method: "GET" },
      { uri: `${echo.url}/q?x=1`, query: [{ name: "y", value: "2 3" }, { name: "я", value: "&" }], method: "DELETE" },
      { uri: `${echo.url}/form`, method: "PUT", body: { type: "form", data: [{ name: "a", value: "1 2" }, { name: "б", value: "в~!'()*" }] } },
      { uri: `${echo.url}/plain`, method: "POST", body: { type: "plain", data: { type: "base64", data: "aGVsbG8=" } } },
      { uri: `${echo.url}/plain`, method: "POST", header: [{ name: "Content-Type", value: "text/xml" }], body: { type: "plain", data: { type: "base64", data: "aGVsbG8=" } } },
      { uri: `${echo.url}/gzip`, method: "POST", body: { type: "plain", data: { type: "base64", data: gzipped }, compression: "gzip" } },
      { uri: `${echo.url}/multi`, method: "POST", body: { type: "form-data", data: [{ name: "a", value: "1" }, { name: "f", source: { type: "base64", data: "aGVsbG8=" }, filename: "f.txt" }] } },
      { uri: `${echo.url}/missing`, method: "GET" },
      { uri: `${echo.url}/slow`, method: "GET", timeout: 1 },
      { uri: `${echo.url}/plain`, method: "POST", body: { type: "plain", data: { type: "base64", data: "aGVsbG8=" }, compression: "gzip" } },
      { uri: "http://127.0.0.1:1/x", method: "GET" },
      { uri: "notaurl", method: "GET" },
      { uri: `${echo.url}/x`, method: "get" },
      { uri: `${echo.url}/x` },
      { uri: `${echo.url}/x`, method: "POST", body: { type: "json" } },
      { uri: `${echo.url}/x`, method: "PUT" },
    ]) {
      expect(seen(await ours("http.request", request)), JSON.stringify(request)).toEqual(seen(await theirs("http.request", request)));
    }
  } finally {
    await echo.close();
  }
});

test("hashes, moves and deletes streams as the host, one command after another in one session", async () => {
  const data = { type: "base64", data: "aGVsbG8=" };
  const cache = (name: string) => ({ type: "cache", name });
  for (const [type, request] of [
    ["hash.md5", { source: data, sink: { type: "hex" } }],
    ["hash.md5", { source: data }],
    ["hash.sha256", { source: data, sink: { type: "base64" } }],
    ["hash.crc32", { source: data }],
    ["hash.crc32", { source: { type: "hex", data: "" } }],
    ["io.transfer", { source: data, sink: cache("c") }],
    ["io.getInfo", { source: cache("c") }],
    ["io.transfer", { source: data, sink: cache("c"), sinkOffset: 3 }],
    ["io.transfer", { source: cache("c"), sink: { type: "hex" } }],
    ["io.transfer", { source: data, sink: cache("c"), sinkOffset: 10 }],
    ["io.transfer", { source: cache("c"), sink: { type: "hex" }, sourceOffset: 2, count: 4 }],
    ["io.transfer", { source: data, sink: { type: "hex" }, sinkOffset: 2 }],
    ["io.transfer", { source: data, sink: { type: "hex" }, count: 100 }],
    ["io.transfer", { source: data, sink: { type: "hex" }, sourceOffset: 5 }],
    ["io.transfer", { source: data, sink: { type: "hex" }, sourceOffset: 6 }],
    ["io.getInfo", { source: { type: "hex", data: "0102" } }],
    ["io.delete", { source: cache("c") }],
    ["io.getInfo", { source: cache("c") }],
    ["io.delete", { source: cache("c") }],
    ["io.delete", { source: data }],
  ] as const) {
    expect(outcome(await ours(type, request)), `${type} ${JSON.stringify(request)}`).toEqual(outcome(await theirs(type, request)));
  }
});

// Keys and certificates are made on another copy of the token, removed afterwards, so the one above keeps its single
// certificate. The browser above is closed first: the Rutoken adapter of a second one meanwhile does not answer.
test.describe("on another copy of the token", () => {
  const outDir = join(standDir, "kontur-reference");
  const home = join(outDir, "home");
  let copy: BrowserContext;
  let copyPage: Page;
  let copyHost: KonturHost;

  test.beforeAll(async () => {
    await context.close();
    rmSync(outDir, { recursive: true, force: true });
    mkdirSync(outDir, { recursive: true });
    cpSync(kontur.home, home, { recursive: true, verbatimSymlinks: true });
    copy = await launchStand({ home, extensions: [stand.adapter, standExtension()] });
    await clearSites(copy);
    await enableSite(copy, server.url, ["kontur"]);
    copyPage = await openStandPage(copy, `${server.url}/ref.html`);
    copyHost = konturHost("s-stand", home);
  });

  test.afterAll(async () => {
    copyHost?.close();
    await copy?.close();
    rmSync(outDir, { recursive: true, force: true });
  });

  const mineOn = (type: string, fields: Record<string, unknown> = {}, pin = false) => ask(copyPage, type, fields, pin);
  const theirsOn = (type: string, fields: Record<string, unknown> = {}) => copyHost.ask(type, fields);

  test("makes requests laid out as the host's, and each side installs a certificate for the other's key", async () => {
    const [provider] = (await theirsOn("crypto.provider.search", { cryptoProviderType: "pkcs11" })).result;
    const stream = (data: string) => ({ type: "base64", data });
    // CN=Сверка, keyUsage digitalSignature, challengePassword "test".
    const fields = {
      cryptoProvider: provider,
      sink: { type: "base64" },
      signatureAlgorithm: "1.2.643.7.1.1.3.2",
      subject: stream("MBcxFTATBgNVBAMMDNCh0LLQtdGA0LrQsA=="),
      extensions: stream("MBAwDgYDVR0PAQH/BAQDAgeA"),
      attributes: [stream("MBMGCSqGSIb3DQEJBzEGDAR0ZXN0")],
    };
    const mine = (await mineOn("crypto.createCertRequest", fields, true)).result;
    const their = (await theirsOn("crypto.createCertRequest", fields)).result;
    // All but the key and the signature, which differ by nature, and the container's random name.
    const layout = (made: { path: string; request: { data: string } }) => {
      const [info, algorithm] = children(read(Buffer.from(made.request.data, "base64")));
      const [version, subject, publicKey, attributes] = children(info!);
      return { path: made.path.replace(/[^\\]+$/, ""), parts: [version, subject, children(publicKey!)[0], attributes, algorithm].map((node) => Buffer.from(node!.der).toString("hex")) };
    };
    expect(layout(mine)).toEqual(layout(their));
    const dir = mkdtempSync(join(standDir, "kontur-ref-"));
    try {
      const issue = (made: { request: { data: string } }, name: string) => {
        writeFileSync(join(dir, `${name}.csr.pem`), `-----BEGIN CERTIFICATE REQUEST-----\n${made.request.data}\n-----END CERTIFICATE REQUEST-----\n`);
        // The test CA checks the request's signature before it issues.
        execFileSync(venvPython, [join(repoRoot, "tests", "tools", "gost_ca.py"), "issue", caDir, join(dir, `${name}.csr.pem`), join(dir, `${name}.pem`)]);
        return stream(readFileSync(join(dir, `${name}.pem`), "utf8").replace(/-----[^-]+-----|\s/g, ""));
      };
      expect(outcome(await theirsOn("crypto.installCert", { cryptoProvider: provider, cert: issue(mine, "ours") }))).toEqual({ result: undefined });
      expect(outcome(await mineOn("crypto.installCert", { cryptoProvider: provider, cert: issue(their, "theirs") }, true))).toEqual({ result: undefined });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
    const caCert = stream(readFileSync(join(caDir, "ca.pem"), "utf8").replace(/-----[^-]+-----|\s/g, ""));
    expect(outcome(await mineOn("crypto.installCert", { cryptoProvider: provider, cert: caCert }, true))).toEqual(outcome(await theirsOn("crypto.installCert", { cryptoProvider: provider, cert: caCert })));
    const userCert = { content: stream(readFileSync(join(standDir, "user.pem"), "utf8").replace(/-----[^-]+-----|\s/g, "")) };
    for (const [type, request] of [
      ["crypto.createCertRequest", { ...fields, cryptoProvider: { ...provider, slot: "nope" } }],
      ["crypto.createCertRequest", { ...fields, signatureAlgorithm: "1.2.3" }],
      ["crypto.createCertRequest", { ...fields, subject: stream("AAAA") }],
      ["crypto.createCertRequest", { ...fields, extensions: undefined }],
      ["crypto.createCertRequest", { ...fields, cryptoProvider: { type: "cryptoApi", name: "Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider", id: 80, containerName: "x" } }],
      ["crypto.installCert", { cryptoProvider: provider, cert: stream("AAAA") }],
      ["crypto.installCert", { cryptoProvider: { ...provider, slot: "nope" }, cert: caCert }],
      ["crypto.installCert", { cryptoProvider: { type: "cryptoApi", name: "Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider", id: 80 }, cert: caCert }],
      ["cert.store.install", { cert: userCert, store: { type: "cryptoApi", name: "My" } }],
      ["cert.store.remove", { cert: userCert, store: { type: "cryptoApi", name: "My" } }],
      ["cert.store.install", { cert: userCert, store: { type: "pkcs11" } }],
      ["cert.store.install", { cert: { content: stream("AAAA") }, store: { type: "cryptoApi" } }],
      ["cert.store.remove", { cert: { hash: { type: "hex", data: "00" } }, store: { type: "cryptoApi" } }],
      ["cert.store.install", { cert: userCert }],
    ] as const) {
      const fresh = konturHost("s-stand", home);
      try {
        expect(outcome(await mineOn(type, request)), `${type} ${JSON.stringify(request).slice(0, 200)}`).toEqual(outcome(await fresh.ask(type, request)));
      } finally {
        fresh.close();
      }
    }
  });
});
