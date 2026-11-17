import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { children, decodeOid, read } from "../../src/page/asn1.ts";
import { decodeCp1251, encodeCp1251 } from "../../src/page/cp1251.ts";
import { digest } from "../../src/page/gost.ts";
import { answer, createContext } from "../../src/page/ifc/ifc-plugin.ts";
import { asn1Parse, opensslExtensions, opensslName, opensslSerial, opensslTime } from "../../src/page/ifc/openssl-text.ts";
import { encodeSubject, KEY_USAGE, nconfExtension, requestInfo, signedRequest } from "../../src/page/ifc/request.ts";
import type { RutokenPlugin } from "../../src/page/rutoken.ts";
import { parseCertificate, pemToDer } from "../../src/page/x509.ts";
import { fakePlugin, FakePinDialog, fakeSession, pem, tokenSerial, userPin } from "./fakes.ts";

const fixture = JSON.parse(readFileSync(new URL("../fixtures/ifc-x509-info.json", import.meta.url), "utf8")) as {
  certificates: { source: string; cert_info: Record<string, string> }[];
};

describe("IFCPlugin's certificate text", () => {
  it.each(fixture.certificates.map((entry, index) => [`${index} ${entry.source}`, entry.cert_info] as const))("prints %s as the core does", (_, info) => {
    const x509 = parseCertificate(Uint8Array.from(atob(info.base64!), (char) => char.charCodeAt(0)));
    expect(opensslName(x509.subject)).toBe(info.cert_subject);
    expect(opensslName(x509.issuer)).toBe(info.cert_issuer);
    expect(opensslSerial(x509)).toBe(info.cert_sn);
    expect(opensslTime(x509.notBefore)).toBe(info.cert_valid_from);
    expect(opensslTime(x509.notAfter)).toBe(info.cert_valid_to);
    expect(x509.publicKeyAlgorithm).toBe(info.cert_sign_alg);
    expect(opensslExtensions(x509)).toBe(info.extensions);
  });

  it("dumps an element as asn1parse does", () => {
    const octets = Uint8Array.from([0x04, 0x05, 0x65, 0x04, 0x75, 0x29, 0xc9]);
    expect(asn1Parse(octets)).toBe("    0:d=0  hl=2 l=   5 prim: OCTET STRING      \n      0000 - 65 04 75 29 c9                                    e.u).\n");
    expect(asn1Parse(Uint8Array.from([0x30, 0x03, 0x02, 0x01, 0x00]))).toBe("    0:d=0  hl=2 l=   3 cons: SEQUENCE          \n    2:d=1  hl=2 l=   1 prim:  INTEGER           :00\n");
  });
});

const verifyFixture = JSON.parse(readFileSync(new URL("../fixtures/verify.json", import.meta.url), "utf8")) as { cryptopro: Record<string, string>; content: string };
const standUser = parseCertificate(pemToDer(pem));
const container = `ruTokenECP/0/${standUser.thumbprint}`;
const b64 = (bytes: Uint8Array) => btoa(Array.from(bytes, (byte) => String.fromCharCode(byte)).join(""));
const bytes = (text: string) => Uint8Array.from(atob(text), (char) => char.charCodeAt(0));

function setup(overrides: Partial<RutokenPlugin> = {}, ifcPinWindow = false, dialog = new FakePinDialog([])) {
  const plugin = fakePlugin([pem], overrides);
  const frames: Record<string, unknown>[] = [];
  const context = createContext(fakeSession(plugin, dialog), Promise.resolve({ ifcPinWindow }), (frame) => frames.push(frame));
  const ask = (func_name: string, params: Record<string, unknown> = {}) => answer(context, { func_name, params });
  return { plugin, context, frames, ask, dialog };
}

describe("IFCPlugin's functions", () => {
  it("reports the core's version, takes any configuration and refuses what it does not have", async () => {
    const { ask } = setup();
    expect(await ask("version")).toEqual({ error_code: 0, version: "3.1.1" });
    expect(await ask("create", { file_config: "/etc/ifc.cfg" })).toEqual({ error_code: 0 });
    expect(await ask("encrypt")).toEqual({ error_code: 17 });
    expect(await answer(setup().context, {})).toEqual({ error_code: 17 });
  });

  it("lists the token as the core does, its serial in hex, and nothing for a crypto type", async () => {
    const { ask } = setup();
    const info = await ask("get_list_info");
    expect(Object.keys(info)).toEqual(["error_code", "ifc_list", "ifc_list_length"]);
    expect(info).toEqual({
      error_code: 0,
      ifc_list: [{ alg: "gost2001", alias: "ruTokenECP", description: "Aktiv Rutoken ECP 0", model: "Rutoken ECP", name: "Актив Рутокен ЭЦП", num: "0", path: "librtpkcs11ecp.so", serial_number: Number(tokenSerial).toString(16).toUpperCase().padStart(8, "0"), skip_pkcs11_list: "", type: "pkcs11" }],
      ifc_list_length: 1,
    });
    expect(await ask("get_list_info", { cryptoType: 0 })).toEqual({ error_code: 0, ifc_list: [], ifc_list_length: 0 });
  });

  it("lists certificates by token with the core's codes for a wrong token", async () => {
    const { ask } = setup();
    const standInfo = fixture.certificates.find((entry) => entry.source.endsWith("stand-user.pem"))!.cert_info;
    expect(await ask("get_list_certs", { cryptoID: "ruTokenECP/0" })).toEqual({
      cert_list: [{ cert_issuer: standInfo.cert_issuer, cert_sign_alg: standInfo.cert_sign_alg, cert_sn: standInfo.cert_sn, cert_subject: standInfo.cert_subject, cert_valid_from: standInfo.cert_valid_from, cert_valid_to: standInfo.cert_valid_to, id: standUser.thumbprint }],
      error_code: 0,
    });
    expect(await ask("get_list_certs")).toEqual({ error_code: 5 });
    expect(await ask("get_list_certs", { cryptoID: "ruTokenECP" })).toEqual({ error_code: 10 });
    expect(await ask("get_list_certs", { cryptoID: "ruTokenECP/5" })).toEqual({ error_code: 25 });
    expect(await ask("get_list_certs", { cryptoID: "jacarta/0" })).toEqual({ error_code: 7 });
  });

  it("sends the progress frames before the list of several tokens' certificates", async () => {
    const { ask, frames } = setup();
    const result = await ask("get_list_certs_by_cryptoid_array", { cryptoID_array: ["ruTokenECP/0"], show_progress: true });
    expect(frames).toEqual([0, 1].map((counter) => ({ certs_count: 1, error_code: 0, intermediate: 1, progress_counter: counter })));
    expect(result).toMatchObject({ error_code: 0, intermediate: 0, result_array: [{ crypto_id: "ruTokenECP/0" }] });
    expect(await ask("get_list_certs_by_cryptoid_array", { cryptoID_array: ["ruTokenECP/0", "ruTokenECP/1"] })).toEqual({ error_code: 25 });
    expect(await ask("get_list_certs_by_cryptoid_array", {})).toEqual({ error_code: 0, result_array: [] });
  });

  it("lists keys after the site's PIN: a certificate's, and one without a certificate by its id in Windows-1251", async () => {
    const { ask, plugin } = setup();
    expect(await ask("get_list_keys", { cryptoID: "ruTokenECP/0" })).toEqual({ error_code: 5 });
    expect(await ask("get_list_keys", { cryptoID: "ruTokenECP/0", userPin: "1111" })).toEqual({ error_code: 160 });
    const keys = (await ask("get_list_keys", { cryptoID: "ruTokenECP/0", userPin })) as { keys_list: Record<string, string>[] };
    expect(keys.keys_list.map((key) => key.id)).toEqual([standUser.thumbprint, decodeCp1251(Uint8Array.of(0x0a, 0xbc))]);
    expect(keys.keys_list[1]).toEqual({ cert_issuer: "", cert_sign_alg: "", cert_sn: "", cert_subject: "", cert_valid_from: "", cert_valid_to: "", id: "\nј" });
    // No window: the PIN is the site's, and the login ends with the request (the refused one never began).
    expect(plugin.calls.login).toEqual(["1111", userPin]);
    expect(plugin.calls.logout).toBe(1);
  });

  it("asks the PIN in the extension's window instead when the user chose so", async () => {
    const dialog = new FakePinDialog([userPin]);
    const { ask } = setup({}, true, dialog);
    const keys = (await ask("get_list_keys", { cryptoID: "ruTokenECP/0", userPin: "the site's" })) as { keys_list: unknown[] };
    expect(keys.keys_list).toHaveLength(2);
    expect(dialog.requests[0]?.details[0]).toBe("Запрос сайта к плагину Госуслуг (IFCPlugin).");
    expect(await ask("get_list_keys", { cryptoID: "ruTokenECP/0" })).toEqual({ error_code: 1 });
  });

  it("loads certificates under handles and prints them as the core does", async () => {
    const { ask } = setup();
    const standInfo = fixture.certificates.find((entry) => entry.source.endsWith("stand-user.pem"))!.cert_info;
    expect(await ask("load_x509_from_container", { containerId: container })).toEqual({ error_code: 0, x509Handle: 2 });
    expect(await ask("get_x509_info", { x509Handle: 2 })).toEqual({ cert_info: standInfo, error_code: 0 });
    expect(await ask("load_x509_from_data", { cert_data_type: 0, cert: pem })).toEqual({ error_code: 0, x509Handle: 3 });
    expect(await ask("load_x509_from_data", { cert_data_type: 0, cert: standInfo.base64 })).toEqual({ error_code: 0, x509Handle: 4 });
    expect(await ask("load_x509_from_data", { cert_data_type: 0, cert: "junk" })).toEqual({ error_code: 9 });
    expect(await ask("load_x509_from_data", { cert_data_type: 1, cert: pem })).toEqual({ error_code: 17 });
    expect(await ask("load_x509_from_data", { cert: pem })).toEqual({ error_code: 5 });
    expect(await ask("load_x509_from_container", { containerId: "ruTokenECP/0/nope" })).toEqual({ error_code: 1 });
    expect(await ask("get_x509_info", { x509Handle: 999 })).toEqual({ error_code: 9 });
    expect(await ask("free_x509", { x509Handle: 2 })).toEqual({ error_code: 0 });
    expect(await ask("get_x509_info", { x509Handle: 2 })).toEqual({ error_code: 9 });
  });

  it("hashes with the key's Streebog, the data as text or Base64", async () => {
    const { ask } = setup();
    const data = new TextEncoder().encode("Привет, мир!");
    expect(await ask("hash", { containerId: container, inDataType: 2, outDataType: 1, data: b64(data) })).toEqual({ error_code: 0, hashValue: b64(digest("streebog256", data)) });
    expect(await ask("hash", { containerId: container, inDataType: 1, outDataType: 1, data: "Привет, мир!" })).toEqual({ error_code: 0, hashValue: b64(digest("streebog256", data)) });
    expect(await ask("hash", { containerId: container, inDataType: 2, outDataType: 2, data: b64(data) })).toEqual({ error_code: 17 });
    expect(await ask("hash", { containerId: container, inDataType: 3, outDataType: 1, data: "x" })).toEqual({ error_code: 17 });
    expect(await ask("hash", { inDataType: 2, outDataType: 1, data: "AAAA" })).toEqual({ error_code: 5 });
    expect(await ask("hash", { containerId: "ruTokenECP/0/zzz", inDataType: 2, outDataType: 1, data: "AAAA" })).toEqual({ error_code: 1 });
  });

  it("signs a hash bare (type 2 reversed) or as CMS with the plugin, with the core's codes", async () => {
    const { ask, plugin } = setup();
    const data = new TextEncoder().encode("Привет, мир!");
    const hash = digest("streebog256", data);
    // The fake rawSign answers the hash twice.
    const raw = Uint8Array.from([...hash, ...hash]);
    expect(await ask("sign", { containerId: container, userPin, signType: 1, inDataType: 2, outDataType: 1, data: b64(data) })).toEqual({ error_code: 0, sign_value: b64(raw) });
    expect(await ask("sign", { containerId: container, userPin, signType: 2, inDataType: 4, outDataType: 1, data: b64(hash) })).toEqual({ error_code: 0, sign_value: b64(raw.reverse()) });
    expect(await ask("sign", { containerId: container, userPin, signType: 5, inDataType: 2, outDataType: 1, data: b64(data) })).toEqual({ error_code: 0, sign_value: "MIIsignature" });
    expect(plugin.calls.sign.at(-1)?.options).toEqual({ detached: false, addUserCertificate: true, addEssCert: true, addSignTime: true });
    await ask("sign", { containerId: container, userPin, signType: 4, inDataType: 1, outDataType: 1, data: "Привет, мир!" });
    expect(plugin.calls.sign.at(-1)).toMatchObject({ data: b64(data), options: { detached: true, addEssCert: false } });
    expect(await ask("sign", { containerId: container, userPin, signType: 9, inDataType: 2, outDataType: 1, data: "AAAA" })).toEqual({ error_code: 14 });
    expect(await ask("sign", { containerId: container, userPin, signType: 3, inDataType: 4, outDataType: 1, data: b64(hash) })).toEqual({ error_code: 1 });
    expect(await ask("sign", { containerId: container, userPin, signType: 1, inDataType: 2, outDataType: 2, data: "AAAA" })).toEqual({ error_code: 17 });
    expect(await ask("sign", { containerId: container, signType: 1, inDataType: 2, outDataType: 1, data: "AAAA" })).toEqual({ error_code: 1 });
    expect(await ask("sign", { containerId: container, userPin: "1111", signType: 1, inDataType: 2, outDataType: 1, data: "AAAA" })).toEqual({ error_code: 160 });
  });

  it("verifies a CMS signature by the container's or the handle's certificate", async () => {
    const { ask } = setup();
    const cms = verifyFixture.cryptopro.bes!;
    const signer = children(children(children(read(bytes(cms)))[1]!)[0]!)[3]!;
    const certificate = b64(children(signer)[0]!.der);
    const { x509Handle } = (await ask("load_x509_from_data", { cert_data_type: 0, cert: certificate })) as { x509Handle: number };
    const containerId = `ruTokenECP/0/${parseCertificate(bytes(certificate)).thumbprint}`;
    expect(await ask("verify", { containerId, x509Handle, signType: 3, inDataType: 2, data: "", sign: cms })).toEqual({ error_code: 0, verify_result: 0 });
    const tampered = bytes(cms);
    tampered[tampered.length - 5] ^= 1;
    expect(await ask("verify", { containerId, x509Handle, signType: 3, inDataType: 2, data: "", sign: b64(tampered) })).toEqual({ error_code: 19, verify_result: 19 });
    expect(await ask("verify", { containerId, x509Handle, signType: 1, inDataType: 2, data: "AAAA", sign: b64(new Uint8Array(64)) })).toEqual({ error_code: 19, verify_result: 19 });
    expect(await ask("verify", { containerId, signType: 3, inDataType: 2, data: "", sign: cms })).toEqual({ error_code: 5 });
  });

  it("makes a key named by the site, with the name's bytes as its id and the core's parameters", async () => {
    const { ask, plugin } = setup();
    expect(await ask("key_gen", { containerId: "ruTokenECP/0/newkey1", userPin })).toEqual({ error_code: 0, real_id: "ruTokenECP/0/newkey1" });
    expect(plugin.calls.generateKeyPair[0]![3]).toEqual({ publicKeyAlgorithm: 3, signatureSize: 512, keySpec: 8, paramset: "XA", id: "6e:65:77:6b:65:79:31" });
    // A key with that id is there already (the fake's second key, 0a:bc).
    expect(await ask("key_gen", { containerId: `ruTokenECP/0/${decodeCp1251(Uint8Array.of(0x0a, 0xbc))}`, userPin })).toEqual({ error_code: 1 });
    expect(await ask("key_gen", { containerId: "ruTokenECP/0/newkey1" })).toEqual({ error_code: 1 });
  });

  it("builds the request with the core's extensions and signs it with rawSign", async () => {
    const spki = children(children(read(standUser.der))[0]!)[6]!.der;
    const csr = signedRequest(requestInfo(encodeSubject([{ oid: "2.5.4.3", type: 12, value: "x" }]), spki, [KEY_USAGE]), "1.2.643.7.1.1.3.2", new Uint8Array(64));
    const csrPem = `-----BEGIN CERTIFICATE REQUEST-----\n${b64(csr)}\n-----END CERTIFICATE REQUEST-----\n`;
    const { ask } = setup({ createPkcs10: async () => csrPem });
    const subject = { oids_count: 2, oid_1: "2.5.4.3", oid_type_1: 12, value_1: "Новый ключ", oid_2: "2.5.4.6", oid_type_2: 19, value_2: "RU" };
    const params = { containerId: container, userPin, subject, req_format: 1, signInstrument: "СКЗИ «Рутокен ЭЦП 2.0»", extendedKeyUsage: ["1.3.6.1.5.5.7.3.2"], certificatePolicies: ["1.2.643.100.113.1"], csrExtensions: { oids_count: 1, oid_1: "1.3.6.1.4.1.311.21.7", value_1: "ASN1:UTF8String:Шаблон" } };
    const result = (await ask("req_gen", params)) as { req_pem: string; req_pem_length: number };
    expect(result.req_pem).toMatch(/^-----BEGIN CERTIFICATE REQUEST-----\n(.{64}\n)+.{1,64}\n-----END CERTIFICATE REQUEST-----\n$/);
    expect(result.req_pem_length).toBe(result.req_pem.length);
    const [info, algorithm] = children(read(pemToDer(result.req_pem)));
    const [, name, key, attributes] = children(info!);
    expect(name!.der).toEqual(encodeSubject([{ oid: "2.5.4.3", type: 12, value: "Новый ключ" }, { oid: "2.5.4.6", type: 19, value: "RU" }]));
    expect(key!.der).toEqual(spki);
    const extensions = children(children(children(children(attributes!)[0]!)[1]!)[0]!).map((extension) => children(extension));
    expect(extensions.map(([oid]) => decodeOid(oid!.value))).toEqual(["2.5.29.15", "2.5.29.37", "2.5.29.32", "1.2.643.100.111", "1.3.6.1.4.1.311.21.7"]);
    expect(b64(extensions[0]![1]!.value)).toBe(b64(Uint8Array.of(0x03, 0x02, 0x04, 0xf0)));
    expect(new TextDecoder().decode(read(extensions[3]![1]!.value).value)).toBe("СКЗИ «Рутокен ЭЦП 2.0»");
    expect(read(extensions[4]![1]!.value).tag).toBe(0x0c);
    expect(new TextDecoder().decode(read(extensions[4]![1]!.value).value)).toBe("Шаблон");
    expect(b64(children(algorithm!)[1]!.der)).toBe("BQA=");
    const base64Request = (await ask("req_gen", { ...params, req_format: undefined })) as { req_base64: string; req_base64_length: number };
    expect(base64Request.req_base64_length).toBe(base64Request.req_base64.length);
    expect(await ask("req_gen", { ...params, req_format: 3 })).toEqual({ error_code: 17 });
    expect(await ask("req_gen", { ...params, subject: { oids_count: 1, oid_0: "2.5.4.3", oid_type_0: 12, value_0: "x" } })).toEqual({ error_code: 5 });
    expect(await ask("req_gen", { ...params, csrExtensions: { oids_count: 1, oid_1: "1.2.3", value_1: "nonsense" } })).toEqual({ error_code: 1 });
  });

  it("writes a certificate onto the token once", async () => {
    const other = fixture.certificates.find((entry) => entry.source.includes("cryptopro/bes"))!.cert_info;
    const { ask, plugin } = setup();
    const { x509Handle } = (await ask("load_x509_from_data", { cert_data_type: 0, cert: other.base64 })) as { x509Handle: number };
    expect(await ask("set_x509", { containerId: "ruTokenECP/0/newkey1", userPin, x509Handle })).toEqual({ error_code: 0 });
    expect(plugin.calls.importCertificate).toHaveLength(1);
    const own = (await ask("load_x509_from_container", { containerId: container })) as { x509Handle: number };
    expect(await ask("set_x509", { containerId: container, userPin, x509Handle: own.x509Handle })).toEqual({ error_code: 1 });
  });

  it("makes GUIDs as the core writes them", async () => {
    const { ask } = setup();
    expect(((await ask("get_guid")) as { guid: string }).guid).toMatch(/^[0-9A-Z]{8}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{12}$/);
    expect(((await ask("get_guid", { prefix: "x" })) as { guid: string }).guid).toMatch(/^x[0-9A-Z]{8}-/);
  });

  it("names keys in Windows-1251 both ways", () => {
    expect(encodeCp1251("newkey1")).toEqual(new TextEncoder().encode("newkey1"));
    expect(decodeCp1251(encodeCp1251("Ключ №1")!)).toBe("Ключ №1");
    expect(encodeCp1251("ключ 😀")).toBeUndefined();
  });
});
