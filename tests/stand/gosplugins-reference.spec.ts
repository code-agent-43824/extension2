/// <reference types="chrome" />
// The opt-in comparison with the real Gosuslugi plug-ins (docs/PLAN.md, action 47): the same requests to the real cores
// of IFCPlugin 3.1.1 and Gosplugin 1.3.42 and to the extension playing them, on the same copy of the token
// (scripts/setup-gosplugins.ts), and the answers compared where they must agree; the signatures of each are checked by
// the other. Run after `npm run build` and `node scripts/setup-gosplugins.ts`:
// STAND_GOSPLUGINS=1 npx playwright test tests/stand/gosplugins-reference.spec.ts
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { existsSync } from "node:fs";
import { gosplugins } from "../../scripts/setup-gosplugins.ts";
import { stand, userPin } from "../../scripts/setup-stand.ts";
import { gosHost, gosMessage, ifcHost, type NativeHost } from "./gosplugins.ts";
import { clearSites, enableSite, launchStand, openStandPage, servePages, standExtension, type PageServer } from "./harness.ts";
import { verifyCms } from "./verify.ts";

test.skip(!process.env.STAND_GOSPLUGINS || !existsSync(gosplugins.home), "needs the real plug-ins' cores: node scripts/setup-gosplugins.ts, then STAND_GOSPLUGINS=1");

const PAGE = `<!doctype html><html><head><meta charset="utf-8"><title>reference</title></head><body><script>
const pending = [];
addEventListener("message", (event) => {
  if (typeof event.data !== "string") return;
  let message;
  try { message = JSON.parse(event.data); } catch { return; }
  if (message.type === "FROM_IFC_EXT" && message.msg_data.intermediate !== 1) pending.shift()?.(message.msg_data);
});
window.ifc = (func_name, params = {}) => new Promise((resolve) => {
  pending.push(resolve);
  postMessage(JSON.stringify({ type: "TO_IFC_EXT", msg_data: { func_name, params } }), "*");
});
window.send = (module, method, data) => new Promise((resolve) => {
  const id = crypto.randomUUID();
  const message = { id, node: "", error: "", mode: "", module: { type: module, version: "0.0.0.0" }, method: { type: method, data, result: "" },
    meta: { format: { type: "message", version: "0.0.0.0", category: "gosuslugi.plugin" }, content: { type: "application/json", charset: "utf8", transferEncoding: "" },
      routes: [{ node: "gosuslugi.plugin.extension.crypto", time: new Date().toLocaleString(), transfer: "" }], data: {}, userAgent: navigator.userAgent } };
  const listener = (event) => { if (event.data && event.data.id === id && event.data.node) { removeEventListener("message", listener); resolve(JSON.parse(JSON.stringify(event.data))); } };
  addEventListener("message", listener);
  postMessage(message, "*");
});
</script></body></html>`;

type Answer = Record<string, unknown>;

let server: PageServer;
let context: BrowserContext;
let page: Page;

test.beforeAll(async () => {
  server = await servePages({ "/reference.html": { type: "text/html; charset=utf-8", body: PAGE } });
  context = await launchStand({ home: gosplugins.home, extensions: [stand.adapter, standExtension()] });
  await clearSites(context);
  await enableSite(context, server.url, ["ifc", "gos"]);
  page = await openStandPage(context, `${server.url}/reference.html`);
  await page.locator("#ifc-plugin-is-installed").waitFor({ state: "attached" });
});

test.afterAll(async () => {
  await context?.close();
  await server?.close();
});

const ours = (name: string, params: Answer = {}) => page.evaluate(([f, p]) => (window as unknown as { ifc: (f: string, p: Answer) => Promise<Answer> }).ifc(f, p), [name, params] as const);

const withoutIds = (list: Answer[]) => list.map(({ id: _, ...rest }) => rest).sort((a, b) => String(a.cert_sn).localeCompare(String(b.cert_sn)));

test.describe("IFCPlugin", () => {
  let core: NativeHost;

  test.beforeAll(async () => {
    core = ifcHost();
    await core.ask({ func_name: "create", params: { file_config: gosplugins.ifc.config } });
  });

  test.afterAll(() => core?.close());

  const real = (name: string, params: Answer = {}) => core.ask({ func_name: name, params }) as Promise<Answer>;

  test("lists the token, certificates and keys as the core does, ids aside", async () => {
    expect(await ours("version")).toEqual(await real("version"));
    const [mine, theirs] = [(await ours("get_list_info")) as { ifc_list: Answer[] }, (await real("get_list_info")) as { ifc_list: Answer[] }];
    // The core's name is its configuration's cp1251 read as UTF-8 on Linux (docs/JOURNAL.md, 2026-11-17).
    expect(mine.ifc_list.map(({ name: _, ...rest }) => rest)).toEqual(theirs.ifc_list.map(({ name: _, ...rest }) => rest));
    const certs = (answer: Answer) => withoutIds(answer.cert_list as Answer[]);
    // The core leaves out a certificate whose key's id has a zero byte; the extension shows it.
    const theirCerts = certs(await real("get_list_certs", { cryptoID: "ruTokenECP/0" }));
    const myCerts = certs(await ours("get_list_certs", { cryptoID: "ruTokenECP/0" }));
    expect(myCerts).toEqual(expect.arrayContaining(theirCerts));
    // After a login the extension knows the keys' ids: then the ids are the core's too.
    expect((await ours("get_list_keys", { cryptoID: "ruTokenECP/0", userPin })).error_code).toBe(0);
    const sorted = (answer: Answer) => [...(answer.cert_list as Answer[])].sort((a, b) => String(a.cert_sn).localeCompare(String(b.cert_sn)));
    expect(sorted(await ours("get_list_certs", { cryptoID: "ruTokenECP/0" }))).toEqual(expect.arrayContaining(sorted(await real("get_list_certs", { cryptoID: "ruTokenECP/0" }))));
    for (const params of [{ cryptoID: "ruTokenECP" }, { cryptoID: "ruTokenECP/5" }, { cryptoID: "ruTokenECP/0", userPin: "1111" }]) {
      const name = "userPin" in params ? "get_list_keys" : "get_list_certs";
      expect(await ours(name, params), JSON.stringify(params)).toEqual(await real(name, params));
    }
  });

  test("prints a certificate, hashes and fails as the core does; each verifies the other's signature", async () => {
    const theirList = (await real("get_list_certs", { cryptoID: "ruTokenECP/0" })).cert_list as Answer[];
    const myList = (await ours("get_list_certs", { cryptoID: "ruTokenECP/0" })).cert_list as Answer[];
    for (const theirs of theirList) {
      const mine = myList.find((entry) => entry.cert_sn === theirs.cert_sn)!;
      const theirContainer = `ruTokenECP/0/${theirs.id}`;
      const myContainer = `ruTokenECP/0/${mine.id}`;
      const theirHandle = (await real("load_x509_from_container", { containerId: theirContainer })).x509Handle;
      const myHandle = (await ours("load_x509_from_container", { containerId: myContainer })).x509Handle;
      expect(await ours("get_x509_info", { x509Handle: myHandle })).toEqual(await real("get_x509_info", { x509Handle: theirHandle }));
      const data = Buffer.from("Сверка с эталоном").toString("base64");
      expect(await ours("hash", { containerId: myContainer, inDataType: 2, outDataType: 1, data })).toEqual(await real("hash", { containerId: theirContainer, inDataType: 2, outDataType: 1, data }));
      for (const params of [{ signType: 9 }, { signType: 1, outDataType: 2 }, { signType: 3, inDataType: 4 }, { signType: 1, userPin: undefined }, { signType: 1, userPin: "1111" }]) {
        const request = { userPin, inDataType: 2, outDataType: 1, data, ...params };
        expect(await ours("sign", { containerId: myContainer, ...request }), JSON.stringify(params)).toEqual(await real("sign", { containerId: theirContainer, ...request }));
      }
      for (const signType of [1, 2, 5, 6]) {
        const request = { userPin, signType, inDataType: 2, outDataType: 1, data };
        const theirSignature = (await real("sign", { containerId: theirContainer, ...request })).sign_value;
        const mySignature = (await ours("sign", { containerId: myContainer, ...request })).sign_value;
        const check = { signType, inDataType: 2, data };
        expect(await ours("verify", { containerId: myContainer, x509Handle: myHandle, sign: theirSignature, ...check }), `ours on the core's, type ${signType}`).toEqual({ error_code: 0, verify_result: 0 });
        expect(await real("verify", { containerId: theirContainer, x509Handle: theirHandle, sign: mySignature, ...check }), `the core on ours, type ${signType}`).toEqual({ error_code: 0, verify_result: 0 });
      }
    }
  });
});

test.describe("Gosplugin", () => {
  let core: NativeHost;

  test.beforeAll(() => {
    core = gosHost();
  });

  test.afterAll(() => core?.close());

  const mine = (module: string, method: string, data: unknown = "") => page.evaluate(([m, f, d]) => (window as unknown as { send: (...a: unknown[]) => Promise<Answer> }).send(m, f, d), [module, method, data] as const);
  const theirs = (module: string, method: string, data: unknown = "") => core.ask(gosMessage(module, method, typeof data === "string" ? data : JSON.stringify(data))) as Promise<Answer>;
  // What must agree: the result and the error, as the page reads them.
  const outcome = (answer: Answer) => ({ result: (answer.method as Answer).result, error: answer.error, code: answer.code, errorMessage: answer.errorMessage });
  // The container names: the key's CKA_ID by the core, the certificate's thumbprint by the extension.
  const comparable = (text: unknown) => JSON.parse(String(text), (key, value) => (key === "container" || key === "containers" ? undefined : value));

  test("answers system, the token and its certificates as the core does, container names aside", async () => {
    for (const [module, method, data] of [["system", "handshake", ""], ["system", "echo", "привет"], ["system", "nosuch", ""]] as const) {
      expect(outcome(await mine(module, method, data)), method).toEqual(outcome(await theirs(module, method, data)));
    }
    expect(outcome(await mine("crypto", "providers", "{}"))).toEqual(outcome(await theirs("crypto", "providers", "{}")));
    const certificates = async (answer: Answer) => (comparable((answer.method as Answer).result) as Answer[]).sort((a, b) => String(a.thumbprint).localeCompare(String(b.thumbprint)));
    const theirCertificates = await certificates(await theirs("crypto", "certificates", { store: "", fields: {} }));
    const myCertificates = await certificates(await mine("crypto", "certificates", JSON.stringify({ store: "", fields: {} })));
    expect(myCertificates).toEqual(theirCertificates);
    const tokens = async (answer: Answer) => comparable((answer.method as Answer).result) as { certificates: Answer[] }[];
    const [myToken] = await tokens(await mine("crypto", "tokens", "{}"));
    const [theirToken] = await tokens(await theirs("crypto", "tokens", "{}"));
    const byThumbprint = (list: Answer[]) => [...list].sort((a, b) => String(a.thumbprint).localeCompare(String(b.thumbprint)));
    expect({ ...myToken, certificates: byThumbprint(myToken!.certificates) }).toEqual({ ...theirToken, certificates: byThumbprint(theirToken!.certificates) });
  });

  test("answers fields, hashes, the SMEV transform and the errors as the core does", async () => {
    const [first] = comparable(((await theirs("crypto", "certificates", { store: "", fields: {} })).method as Answer).result) as Answer[];
    const certificate = { content: first!.raw, path: "", contentEncoding: "base64" };
    const file = (text: string) => ({ content: Buffer.from(text).toString("base64"), path: "", contentEncoding: "base64" });
    const requests: [string, Answer][] = [
      ["certificateFields", { certificate, fields: [] }],
      ["certificateFields", { certificate, fields: ["subject", "thumbprint"] }],
      ["certificateFields", { certificate: { content: "junk", path: "", contentEncoding: "base64" }, fields: [] }],
      ["hash", { certificate, file: file("Сверка"), algorithm: "" }],
      ["hash", { file: file("Сверка"), algorithm: "1.2.643.7.1.1.2.3" }],
      ["hash", { file: file("Сверка"), algorithm: "sha256" }],
      ["normalize", { file: file('<?xml version="1.0"?><ns1:doc xmlns:ns1="urn:a" xmlns:u="urn:unused"><ns1:a  b="1"   c=\'2\'>x  <ns2:b xmlns:ns2="urn:b">y</ns2:b></ns1:a><!-- c --></ns1:doc>'), algorithm: "urn://smev-gov-ru/xmldsig/transform" }],
      ["normalize", { file: file("<doc/>"), algorithm: "urn://smev-gov-ru/xmldsig/transform" }],
      ["normalize", { file: file("<doc/>"), algorithm: "c14n" }],
      ["signature", { files: [file("x")], certificate, type: "cades" }],
    ];
    for (const [method, data] of requests) {
      expect(outcome(await mine("crypto", method, JSON.stringify(data))), `${method} ${JSON.stringify(data).slice(0, 80)}`).toEqual(outcome(await theirs("crypto", method, data)));
    }
  });

  test("signs so that the stand's verifier accepts the extension's signature like the core's", async () => {
    const [first] = comparable(((await theirs("crypto", "certificates", { store: "", fields: {} })).method as Answer).result) as Answer[];
    const certificate = { content: first!.raw, path: "", contentEncoding: "base64" };
    const pending = mine("crypto", "signature", JSON.stringify({ files: [{ content: Buffer.from("Сверка").toString("base64"), path: "", contentEncoding: "base64" }], certificate, type: "attached" }));
    const dialog = page.locator("#rutoken-cades-bridge-pin [role=dialog]");
    await dialog.locator("input[name=pin]").fill(userPin);
    await dialog.locator("button[name=confirm]").click();
    const [signed] = JSON.parse(String(((await pending).method as Answer).result)) as { content: string }[];
    expect(verifyCms(signed!.content).checks).toMatchObject({ message_digest: true, signature: true, certificate_by_ca: true });
  });
});
