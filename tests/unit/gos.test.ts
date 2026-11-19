// Gosplugin's core over the fake plugin (src/page/gos/core.ts), and its messages; XML needs the browser's DOM and runs on
// the stand (tests/stand/gosplugin.spec.ts).
import { describe, expect, it } from "vitest";
import { children, read } from "../../src/page/asn1.ts";
import { digest } from "../../src/page/gost.ts";
import { callCore, newCoreContext } from "../../src/page/gos/core.ts";
import { coreAnswer, GosError, localAnswer, type PageMessage } from "../../src/page/gos/messages.ts";
import { encodeSubject, KEY_USAGE, requestInfo, signedRequest } from "../../src/page/ifc/request.ts";
import type { RutokenPlugin } from "../../src/page/rutoken.ts";
import { pkcs11Serial } from "../../src/page/token.ts";
import { parseCertificate, pemToDer } from "../../src/page/x509.ts";
import { fakePlugin, FakePinDialog, fakeSession, pem, tokenSerial, userPin } from "./fakes.ts";

const user = parseCertificate(pemToDer(pem));
const b64 = (bytes: Uint8Array) => btoa(Array.from(bytes, (byte) => String.fromCharCode(byte)).join(""));
const certificate = { content: b64(user.der), path: "", contentEncoding: "base64" };
const store = `Rutoken ECP ${pkcs11Serial(tokenSerial)}`;

function setup(overrides: Partial<RutokenPlugin> = {}, pins: (string | null)[] = []) {
  const plugin = fakePlugin([pem], overrides);
  const dialog = new FakePinDialog(pins);
  const context = newCoreContext(fakeSession(plugin, dialog));
  const call = (module: string, method: string, data: unknown = "") => callCore(context, module, method, data);
  return { plugin, dialog, context, call };
}

const message: PageMessage = {
  id: "1",
  node: "",
  error: "",
  mode: "",
  module: { type: "crypto", version: "0.0.0.0" },
  method: { type: "hash", data: "{}", result: "" },
  meta: { format: { category: "gosuslugi.plugin" }, routes: [{ node: "gosuslugi.plugin.extension.crypto", time: "t", transfer: "" }], data: {} },
};

describe("Gosplugin's messages", () => {
  it("answers as the core: code, errorMessage, its routes, binary on success only", () => {
    const ok = coreAnswer(message, "r") as Record<string, any>;
    expect(Object.keys(ok)).toEqual(["id", "module", "method", "error", "code", "errorMessage", "node", "mode", "meta"]);
    expect(ok).toMatchObject({ method: { type: "hash", data: null, result: "r" }, code: "0", node: "gosuslugi.plugin.extension.crypto" });
    expect(ok.meta.content.transferEncoding).toBe("binary");
    expect(ok.meta.routes.map((route: { node: string }) => route.node)).toEqual(["gosuslugi.plugin.extension.crypto", "plugin", "gosuslugi.plugin.extension.content"]);
    const failed = coreAnswer(message, "", new GosError(30022, "cades")) as Record<string, any>;
    expect(failed).toMatchObject({ error: "Тип подписи не поддерживается", code: "30022", errorMessage: "30022 Crypto 'Тип подписи не поддерживается': cades", method: { result: "" } });
    expect(failed.meta.content.transferEncoding).toBe("");
  });

  it("answers the extension's own messages with the page's message", () => {
    const answer = localAnswer(message, "true");
    expect(answer).toMatchObject({ id: "1", node: "gosuslugi.plugin.extension.crypto", method: { type: "hash", data: null, result: "true" } });
    expect(answer.meta!.routes!.map((route) => route.node)).toEqual(["gosuslugi.plugin.extension.crypto", "gosuslugi.plugin.extension.content"]);
    expect(message.method!.data).toBe("{}");
  });
});

describe("Gosplugin's core", () => {
  it("answers system's methods, keeping the last error", async () => {
    const { call, context } = setup();
    expect(await call("system", "handshake")).toBe("plugin handshake");
    expect(await call("system", "echo", "привет")).toBe("привет");
    // Made up: the built-in identity when the extension gave none, named as on Linux for an unknown platform.
    const interfaces = JSON.parse(await call("system", "ipConfig"));
    expect(interfaces.map((entry: { name: string; hardwareAddress: string }) => [entry.name, entry.hardwareAddress])).toEqual([["enp3s0", "3C:52:82:A1:6E:08"], ["lo", "00:00:00:00:00:00"]]);
    expect(interfaces[0].networkAddressEntries[0]).toEqual({
      ip: { loopback: "false", multicast: "false", scopeId: "", address: "192.168.1.37" },
      netmask: { loopback: "false", multicast: "false", scopeId: "", address: "255.255.255.0" },
      broadcast: { loopback: "false", multicast: "false", scopeId: "", address: "192.168.1.255" },
    });
    expect(await call("system", "lastError")).toBe("0 Application 'Успешное выполнение операции'");
    await expect(call("system", "nosuch")).rejects.toMatchObject({ code: 20005, errorMessage: "20005 Application 'Не найден метод': nosuch" });
    context.lastError = "x";
    expect(await call("system", "lastError")).toBe("x");
    expect(await call("rutoken", "test")).toBe("rutoken");
  });

  it("lists providers, tokens and certificates with the core's fields", async () => {
    const { call } = setup();
    expect(JSON.parse(await call("crypto", "providers", "{}"))).toEqual([{ name: store, type: "0", version: "hardware version: 67.4 firmware version: 34.2", token: "true" }]);
    const [token] = JSON.parse(await call("crypto", "tokens", "{}"));
    expect(token).toMatchObject({ store, provider: store, label: "stand", serial: pkcs11Serial(tokenSerial), model: "Rutoken ECP", containers: [user.thumbprint] });
    const [fields] = JSON.parse(await call("crypto", "certificates", JSON.stringify({ store: "", fields: {} })));
    expect(Object.keys(fields)).toEqual(["raw", "version", "serialNumber", "signatureAlgorithm", "thumbprint", "friendlyName", "subject", "issuer", "notBefore", "notAfter", "hasPrivateKey", "keyUsage", "enhancedKeyUsage", "privateKeyNotBefore", "privateKeyNotAfter", "provider", "container"]);
    expect(fields).toMatchObject({ version: "v3", hasPrivateKey: "true", keyUsage: "dataencipherment;digitalsignature;keyagreement;keyencipherment;nonrepudiation", provider: store, container: user.thumbprint });
    expect(JSON.parse(await call("crypto", "certificates", JSON.stringify({ store: "", fields: { thumbprint: user.thumbprint.toLowerCase() } })))).toHaveLength(1);
    expect(JSON.parse(await call("crypto", "certificates", JSON.stringify({ store: "other", fields: {} })))).toEqual([]);
    // ESIA's request: the personal store holds the tokens' certificates (the owner, 2026-11-19); Root stays empty.
    for (const my of ["My", "my"]) expect(JSON.parse(await call("crypto", "certificates", JSON.stringify({ store: my, fields: { hasPrivateKey: "true" } })))).toEqual([fields]);
    expect(JSON.parse(await call("crypto", "certificates", JSON.stringify({ store: "Root", fields: {} })))).toEqual([]);
    expect(JSON.parse(await call("crypto", "certificateFields", { certificate, fields: ["subject", "container"] }))).toEqual({ subject: fields.subject, container: "" });
    await expect(call("crypto", "certificateFields", { certificate: { content: "junk", contentEncoding: "base64" }, fields: [] })).rejects.toMatchObject({ code: 30045 });
  });

  it("hashes by the algorithm's OID, the key's size or a common name", async () => {
    const { call } = setup();
    const file = { content: b64(new TextEncoder().encode("abc")), path: "", contentEncoding: "base64" };
    const hex = (bytes: Uint8Array) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
    const data = new TextEncoder().encode("abc");
    expect(JSON.parse(await call("crypto", "hash", { certificate, file, algorithm: "" }))).toEqual({ hash: hex(digest("streebog256", data)).toUpperCase(), provider: store, algorithm: "1.2.643.7.1.1.2.2" });
    expect(JSON.parse(await call("crypto", "hash", { file, algorithm: "1.2.643.7.1.1.2.3" }))).toMatchObject({ hash: hex(digest("streebog512", data)).toUpperCase(), algorithm: "1.2.643.7.1.1.2.3" });
    expect(JSON.parse(await call("crypto", "hash", JSON.stringify({ file, algorithm: "sha1" })))).toEqual({ hash: hex(digest("sha1", data)), provider: "", algorithm: "sha1" });
    await expect(call("crypto", "hash", { file, algorithm: "" })).rejects.toMatchObject({ code: 30015 });
    await expect(call("crypto", "hash", { file, algorithm: "whirlpool" })).rejects.toMatchObject({ code: 30008 });
  });

  it("signs every file after one PIN with the plugin's CAdES-BES, and answers the core's errors", async () => {
    const { call, plugin, dialog } = setup({}, [userPin]);
    const files = [{ content: b64(new TextEncoder().encode("a")), path: "", contentEncoding: "base64" }, { content: "Yg==", path: "p", contentEncoding: "base64", id: "i", name: "n" }];
    const result = JSON.parse(await call("crypto", "signature", { files, certificate, type: "detached" }));
    expect(result).toEqual([
      { id: "", name: "", path: "", content: "MIIsignature", contentEncoding: "base64", contentFormat: "" },
      { id: "i", name: "n", path: "p", content: "MIIsignature", contentEncoding: "base64", contentFormat: "" },
    ]);
    expect(plugin.calls.sign.map((entry) => [entry.data, entry.options])).toEqual(
      ["YQ==", "Yg=="].map((data) => [data, { detached: true, addUserCertificate: true, addEssCert: true, addSignTime: true }]),
    );
    expect(dialog.requests).toHaveLength(1);
    await expect(call("crypto", "signature", { files, certificate, type: "cades" })).rejects.toMatchObject({ code: 30022, errorMessage: "30022 Crypto 'Тип подписи не поддерживается': cades" });
    const other = parseCertificate(pemToDer((await import("node:fs")).readFileSync(new URL("../fixtures/stand-ca.pem", import.meta.url), "utf8")));
    await expect(call("crypto", "signature", { files, certificate: { content: b64(other.der), contentEncoding: "base64" }, type: "attached" })).rejects.toMatchObject({ code: 30005 });
    // The user cancels the window.
    await expect(call("crypto", "signature", { files, certificate, type: "attached" })).rejects.toMatchObject({ code: 20003 });
  });

  it("makes the key rt1-<uuid> and the request with the token's signing tool", async () => {
    const spki = children(children(read(user.der))[0]!)[6]!.der;
    const csr = signedRequest(requestInfo(encodeSubject([{ oid: "2.5.4.3", type: 12, value: "x" }]), spki, [KEY_USAGE]), "1.2.643.7.1.1.3.2", new Uint8Array(64));
    const csrPem = `-----BEGIN CERTIFICATE REQUEST-----\n${b64(csr)}\n-----END CERTIFICATE REQUEST-----\n`;
    const { call, plugin } = setup({ createPkcs10: async () => csrPem }, [userPin]);
    const result = JSON.parse(await call("crypto", "certificateRequest", JSON.stringify({ subject: "2.5.4.3=Ключ;2.5.4.6=RU", provider: store, extendedKeyUsageOids: "1.3.6.1.5.5.7.3.2", certificatePolicies: "", keyUsage: "", publicKeyAlgorithmParamSet: "" })));
    expect(result.container.name).toMatch(/^rt1-[0-9a-f-]{36}$/);
    const options = plugin.calls.generateKeyPair[0]![3] as { id: string; paramset: string };
    expect(options.paramset).toBe("XA");
    expect(String.fromCharCode(...options.id.split(":").map((pair) => parseInt(pair, 16)))).toBe(result.container.name);
    const [info, algorithm] = children(read(Uint8Array.from(atob(result.request.content), (char) => char.charCodeAt(0))));
    expect(children(algorithm!)).toHaveLength(1);
    const extensions = children(children(children(children(children(info!)[3]!)[0]!)[1]!)[0]!);
    expect(extensions).toHaveLength(2);
    expect(new TextDecoder().decode(read(children(extensions[1]!)[1]!.value).value)).toBe("Рутокен ЭЦП 3.0");
  });

  it("writes and deletes a certificate by the store's name", async () => {
    const { call, plugin } = setup({}, [userPin, userPin]);
    await expect(call("crypto", "addCertificate", { certificate, container: "", store: "" })).rejects.toMatchObject({ code: 30013 });
    // On the token already: nothing to do, no PIN.
    expect(await call("crypto", "addCertificate", { certificate, container: "", store })).toBe("");
    expect(plugin.calls.importCertificate).toEqual([]);
    expect(await call("crypto", "deleteCertificate", { certificate, store })).toBe("true");
    expect(plugin.calls.deleteCertificate).toHaveLength(1);
  });
});
