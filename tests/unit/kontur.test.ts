// Kontur.Plugin's page side and plugin.info (docs/PLAN.md, action 57), as the real extension 3.1.11 and host 4.15.1
// answered on the stand (docs/JOURNAL.md, 2026-11-19).
import { describe, expect, it } from "vitest";
import { encode } from "../../src/page/asn1.ts";
import { answerCommand, newKonturContext, sortKeys } from "../../src/page/kontur/commands.ts";
import { isoTime, keyUsages, names } from "../../src/page/kontur/certificate.ts";
import { storeCommand } from "../../src/page/kontur/issuance.ts";
import { CERT_TRUST_IS_PARTIAL_CHAIN, qualificationFailures, trustStatus, verifyCertificate } from "../../src/page/kontur/qualified.ts";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { repoRoot } from "../../scripts/fetch-vendor.ts";
import { pemToDer } from "../../src/page/x509.ts";
import { decodeText, encodeText } from "../../src/page/kontur/text.ts";
import { parseCertificate } from "../../src/page/x509.ts";
import { QUALIFIED_CASES, SWITCH_CASES } from "./kontur-certificates.ts";
import { builtInIdentity } from "../../src/page/identity.ts";
import { pemText } from "../../src/page/kontur/signing.ts";
import { fromBase64, readStream, writeStream } from "../../src/page/kontur/streams.ts";
import { KonturError } from "../../src/page/kontur/errors.ts";
import { extensionInfo, isKonturHost } from "../../src/page/kontur/kontur-plugin.ts";
import { CadesError } from "../../src/page/errors.ts";
import { SCARD_W_CANCELLED_BY_USER } from "../../src/page/token-login.ts";
import type { ChosenFile, FileDialogs } from "../../src/page/kontur/file-dialog.ts";
import { fakePlugin, FakePinDialog, fakeSession } from "./fakes.ts";

const clientId = "0b3c3f5e-2d7a-4a8b-9c1d-112233445566";

// File windows that answer as told: the files to choose, the name to save under, the folder's yes.
function fakeDialogs(answers: { files?: ChosenFile[] | null; name?: string | null; folder?: boolean } = {}): FileDialogs & { asked: unknown[] } {
  const asked: unknown[] = [];
  return {
    asked,
    open: async (options) => (asked.push(options), answers.files ?? null),
    save: async (options) => (asked.push(options), answers.name ?? null),
    folder: async (options) => (asked.push(options), answers.folder ?? false),
  };
}

function setup(platform = "Linux x86_64", dialogs: FileDialogs = fakeDialogs()) {
  const downloads: [string, string][] = [];
  const context = newKonturContext(fakeSession(fakePlugin(), new FakePinDialog([])), Promise.resolve({ ifcPinWindow: false, konturClientId: clientId }), platform, {
    dialogs,
    download: (name, bytes) => downloads.push([name, new TextDecoder().decode(bytes)]),
    identity: async () => builtInIdentity(1, platform),
    navigator: { userAgent: platform.startsWith("Win") ? "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" : "Mozilla/5.0 (X11; Linux x86_64)", platform } as Navigator,
  });
  return { context, downloads, ask: (type: string, fields: Record<string, unknown> = {}) => answerCommand(context, { sessionId: "s", type, ...fields }) };
}

describe("Kontur.Plugin", () => {
  it("is the real extension to the page: its id and version, Chrome's or Firefox's", () => {
    expect(extensionInfo("Mozilla/5.0 (X11; Linux x86_64) Chrome/153.0.0.0 Safari/537.36")).toEqual({ id: "hnhppcgejeffnbnioloohhmndpmclaga", type: "chrome", version: "3.1.11" });
    expect(extensionInfo("Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0")).toMatchObject({ id: "kontur.extension@kontur.ru", type: "firefox" });
  });

  it("marks only Kontur's domains, as the real extension", () => {
    for (const host of ["extern.kontur.ru", "ca.kontur-ca.ru", "a.kontur-extern.ru", "x.kontur", "auth.testkontur.ru"]) expect(isKonturHost(host), host).toBe(true);
    for (const host of ["kontur.ru.example.com", "127.0.0.1", "example.ru"]) expect(isKonturHost(host), host).toBe(false);
  });

  it("answers plugin.info as the host on the stand, not denied, with the extension's client id", async () => {
    expect(await setup().ask("plugin.info")).toEqual({ architecture: "x86_64", buildType: "stable", clientId, denied: false, platform: "linux", pluginVersion: "4.15.1.6119" });
    expect(await setup("Win32").ask("plugin.info")).toMatchObject({ platform: "windows" });
    expect(await setup("MacIntel").ask("plugin.info")).toMatchObject({ platform: "mac" });
  });

  it("answers an unknown command and a cancelled PIN window with the host's errors", async () => {
    await expect(setup().ask("no.such")).rejects.toMatchObject({ answer: { type: "plugin", code: 2, message: "PLUGIN[0x00000002] unknown command" } });
    expect(KonturError.of(new CadesError("cancelled", SCARD_W_CANCELLED_BY_USER)).answer).toEqual({ type: "crypto", code: 51, context: "", message: "CRYPTO[0x00000033] the pkcs11 session is not authorized" });
    expect(KonturError.of(new Error("boom")).answer).toEqual({ type: "plugin", code: 0, message: "PLUGIN[0x00000000] boom" });
    // The Rutoken Plugin rejects with an object whose message is its error code.
    expect(KonturError.of({ message: 20 }).answer).toEqual({ type: "plugin", code: 0, message: "PLUGIN[0x00000000] Rutoken Plugin error 20" });
  });

  it("reads key usage bits as the host does, counting from the first one set (fourteen sets checked on the host)", () => {
    const usages = (unused: number, ...bytes: number[]) => Object.keys(keyUsages(encode(0x03, Uint8Array.of(unused, ...bytes)))).sort();
    expect(usages(3, 0xf8)).toEqual(["dataEncipherment", "digitalSignature", "keyAgreement", "keyEncipherment", "nonRepudiation"]);
    expect(usages(1, 0x86)).toEqual(["crlSign", "digitalSignature", "keyCertSign"]);
    expect(usages(1, 0x06)).toEqual(["digitalSignature", "nonRepudiation"]);
    expect(usages(5, 0xa0)).toEqual(["digitalSignature", "keyEncipherment"]);
    expect(usages(3, 0x18)).toEqual(["digitalSignature", "nonRepudiation"]);
    for (const [unused, byte] of [[7, 0x80], [5, 0x20], [2, 0x04], [6, 0x40], [0, 0x01], [0, 0x80]] as const) expect(usages(unused, byte)).toEqual(["digitalSignature"]);
    expect(usages(7, 0x00, 0x80)).toEqual(["digitalSignature"]);
    expect(usages(7, 0x80, 0x80)).toEqual(["decipherOnly", "digitalSignature"]);
  });

  it("names attributes, writes times and keys as the host does", () => {
    expect(names([[{ oid: "2.5.4.3", value: "a" }], [{ oid: "1.2.643.100.3", value: "b" }, { oid: "2.5.4.5", value: "c" }]])).toEqual([{ CN: "a" }, { СНИЛС: "b" }, { "2.5.4.5": "c" }]);
    expect(isoTime(new Date(Date.UTC(2025, 11, 17, 10, 6, 0, 876)))).toBe("2025-12-17T10:06:00.876Z");
    expect(isoTime(new Date(Date.UTC(2033, 11, 17, 10, 6, 0)))).toBe("2033-12-17T10:06:00Z");
    expect(JSON.stringify(sortKeys({ type: "x", code: 3, nested: [{ b: 1, a: 2 }] }))).toBe('{"code":3,"nested":[{"a":2,"b":1}],"type":"x"}');
  });

  it("reads and writes streams as the host does: lenient Base64, the cache by name, files refused", () => {
    const cache = new Map<string, Uint8Array>();
    expect(Array.from(fromBase64("AQ I=\n"))).toEqual([1, 2]);
    expect(Array.from(fromBase64("@@@"))).toEqual([]);
    expect(writeStream(cache, { type: "cache", name: "n" }, Uint8Array.of(1, 2))).toEqual({ name: "n", size: 2, type: "cache" });
    expect(Array.from(readStream(cache, { type: "cache", name: "n" }))).toEqual([1, 2]);
    expect(writeStream(cache, { type: "hex" }, Uint8Array.of(0xab))).toEqual({ data: "ab", size: 1, type: "hex" });
    expect(() => readStream(cache, { type: "cache", name: "nope" })).toThrow(expect.objectContaining({ answer: expect.objectContaining({ code: 101 }) }));
    expect(() => readStream(cache, { type: "file", path: "/etc/passwd" })).toThrow(expect.objectContaining({ answer: expect.objectContaining({ code: 16 }) }));
    expect(() => writeStream(cache, { type: "text" }, new Uint8Array())).toThrow(expect.objectContaining({ answer: expect.objectContaining({ code: 3 }) }));
    expect(new TextDecoder().decode(pemText(Uint8Array.of(1, 2, 3)))).toBe("-----BEGIN PKCS7-----\r\nAQID\r\n-----END PKCS7-----");
  });

  it("answers CryptoAPI's stores as the host without CryptoPro, a bad certificate before that", () => {
    const cache = new Map<string, Uint8Array>();
    const answer = (request: Record<string, unknown>, install = true) => {
      try {
        storeCommand(request, cache, install);
      } catch (error) {
        return (error as KonturError).answer;
      }
      throw new Error("no answer");
    };
    const name = { type: "base64", data: "MBAxDjAMBgNVBAMMBVByb2Jl" };
    expect(answer({ cert: { content: name } })).toMatchObject({ code: 3 });
    expect(answer({ cert: name, store: { type: "cryptoApi" } })).toMatchObject({ code: 3 });
    expect(answer({ cert: { content: name }, store: { type: "pkcs11" } })).toEqual({ type: "plugin", code: 250, message: "PLUGIN[0x000000FA] cryptoprovider type unsupported" });
    expect(answer({ cert: { hash: { type: "hex", data: "00" } }, store: { type: "cryptoApi" } }, false)).toEqual({ type: "plugin", code: 200, message: "PLUGIN[0x000000C8] certificate not found" });
    expect(answer({ cert: { content: { type: "base64", data: "AAAA" } }, store: { type: "cryptoApi" } })).toEqual({ type: "crypto", code: 1, context: "", message: "CRYPTO[0x00000001] wrong ASN1 value structure" });
    expect(answer({ cert: { content: name }, store: { type: "cryptoApi" } })).toEqual({ type: "asn1", code: 4, context: "", message: "ASN1[0x00000004] required collection element not found" });
  });

  for (const { label, der, rules } of QUALIFIED_CASES) {
    it(`applies the host's qualified rules: ${label}`, () => {
      expect(qualificationFailures(parseCertificate(der)).map((failure) => failure.rule)).toEqual(rules);
    });
  }

  for (const { label, der, rules, switches } of SWITCH_CASES) {
    it(`switches the host's qualified rules: ${label}`, () => {
      expect(qualificationFailures(parseCertificate(der), switches).map((failure) => failure.rule)).toEqual(rules);
    });
  }

  it("converts text in code pages as the host", () => {
    const cache = new Map<string, Uint8Array>();
    const hex = (data: string) => ({ type: "hex", data });
    const answer = (call: () => unknown) => {
      try {
        return call();
      } catch (error) {
        return (error as KonturError).answer;
      }
    };
    expect(decodeText({ source: { type: "base64", data: "z/Do4uXy" }, codePage: 1251 }, cache)).toBe("Привет");
    expect(decodeText({ source: { type: "base64", data: "0J/RgNC40LLQtdGC" } }, cache)).toBe("Привет");
    expect(decodeText({ source: hex("cff0"), codePage: 28595 }, cache)).toBe("Я№");
    expect(answer(() => decodeText({ source: hex("c3") }, cache))).toEqual({ type: "plugin", code: 105, message: "PLUGIN[0x00000069] unable to determine the encoding" });
    expect(answer(() => decodeText({ source: hex("ff98"), codePage: 1251 }, cache))).toEqual({ type: "babel", code: 2, context: "", message: "BABEL[0x00000002] invalid multibyte sequence has been encountered in the input" });
    expect(answer(() => decodeText({ source: hex("cff0"), codePage: 12345 }, cache))).toEqual({ type: "babel", code: 1, context: "", message: "BABEL[0x00000001] unknown codepage" });
    expect(answer(() => decodeText({ codePage: 1251 }, cache))).toMatchObject({ code: 3 });
    expect(encodeText({ value: "Привет", codePage: 1251, sink: { type: "base64" } }, cache)).toEqual({ data: "z/Do4uXy", size: 6, type: "base64" });
    expect(encodeText({ value: "Привет", sink: { type: "base64" } }, cache)).toEqual({ data: "0J/RgNC40LLQtdGC", size: 12, type: "base64" });
    expect(encodeText({ value: "Привет", codePage: 866, sink: { type: "hex" } }, cache)).toEqual({ data: "8fe0a8a2a5e2", size: 6, type: "hex" });
    expect(encodeText({ value: "Привет", codePage: 20866, sink: { type: "hex" } }, cache)).toEqual({ data: "f0d2c9d7c5d4", size: 6, type: "hex" });
    expect(encodeText({ value: "Привет", codePage: 1200, sink: { type: "hex" } }, cache)).toEqual({ data: "1f0440043804320435044204", size: 12, type: "hex" });
    expect(answer(() => encodeText({ value: "日本 ё", codePage: 1251, sink: { type: "hex" } }, cache))).toMatchObject({ type: "babel", code: 2 });
    expect(answer(() => encodeText({ value: "Привет", codePage: 10007, sink: { type: "hex" } }, cache))).toEqual({ type: "babel", code: 5, context: "", message: "BABEL[0x00000005] conversion is not supported by the implementation" });
    expect(answer(() => encodeText({ value: "Привет", codePage: "1251", sink: { type: "hex" } }, cache))).toMatchObject({ code: 3 });
    expect(answer(() => encodeText({ value: 5, codePage: 1251, sink: { type: "hex" } }, cache))).toMatchObject({ code: 3 });
  });

  it("opens the files the user chose and saves to the downloads, refusing any other path", async () => {
    const files = [
      { name: "a.txt", bytes: new TextEncoder().encode("первый") },
      { name: "b.txt", bytes: new TextEncoder().encode("второй") },
    ];
    const dialogs = fakeDialogs({ files, name: "подпись.sig", folder: true });
    const { ask, downloads } = setup("Linux x86_64", dialogs);
    const first = await ask("ui.openFile", { filter: [{ name: "Текст", pattern: "*.txt;*.xml" }] });
    expect(first).toBe("/browser/opened-1/a.txt");
    expect(dialogs.asked[0]).toMatchObject({ title: "Выберите файл", multiple: false, accept: ".txt,.xml" });
    expect(await ask("ui.openFile", { multiple: true, title: "Документы" })).toBe("/browser/opened-2|a.txt|b.txt");
    expect(await ask("ui.openFile", { multiple: true, resultFormat: "array" })).toEqual(["/browser/opened-3/a.txt", "/browser/opened-3/b.txt"]);
    expect(await ask("io.decode", { source: { type: "file", path: "/browser/opened-2/b.txt" }, codePage: 65001 })).toBe("второй");
    const saved = await ask("ui.saveFile", { filename: "x.sig" });
    expect(saved).toBe("/browser/saved-4/подпись.sig");
    expect(await ask("io.encode", { value: "подпись", sink: { type: "file", path: saved } })).toEqual({ path: saved, size: 14, type: "file" });
    expect(await ask("io.decode", { source: { type: "file", path: saved }, codePage: 65001 })).toBe("подпись");
    const folder = await ask("ui.selectFolder");
    expect(folder).toBe("/browser/saved-5");
    await ask("io.encode", { value: "в папке", sink: { type: "file", path: `${folder}/c.txt` } });
    expect(downloads).toEqual([["подпись.sig", "подпись"], ["c.txt", "в папке"]]);
    const answer = async (type: string, fields: Record<string, unknown>) => {
      try {
        await ask(type, fields);
      } catch (error) {
        return (error as KonturError).answer;
      }
      throw new Error("no error");
    };
    expect(await answer("io.encode", { value: "x", sink: { type: "file", path: saved } })).toEqual({ type: "system", code: 17, context: "open", message: "POSIX[0x00000011]open File exists" });
    expect(await answer("io.encode", { value: "x", sink: { type: "file", path: first } })).toMatchObject({ code: 17 });
    expect(await answer("io.decode", { source: { type: "file", path: "/etc/passwd" }, codePage: 65001 })).toMatchObject({ code: 16 });
    expect(await answer("io.encode", { value: "x", sink: { type: "file", path: "/tmp/x" } })).toMatchObject({ code: 16 });
    expect(await answer("ui.openFile", { filter: "x" })).toMatchObject({ code: 3 });
    expect(await answer("ui.openFile", { multiple: "yes" })).toMatchObject({ code: 3 });
    expect(await answer("ui.saveFile", { filename: 5 })).toMatchObject({ code: 3 });
  });

  it("answers an empty path when the user cancels a file window, Windows paths in Windows", async () => {
    const { ask } = setup("Win32", fakeDialogs({ files: [{ name: "a.txt", bytes: new Uint8Array() }] }));
    expect(await ask("ui.openFile", {})).toBe("C:\\Browser\\opened-1\\a.txt");
    expect(await ask("ui.saveFile", {})).toBe("");
    expect(await ask("ui.selectFolder", {})).toBe("");
    expect(await setup().ask("ui.openFile", { resultFormat: "array" })).toBe("");
  });

  it("checks trust as the CryptoPro emulation's IsValid(): by dates, or the chain to the enabled roots", async () => {
    const fixture = (name: string) => parseCertificate(pemToDer(readFileSync(join(repoRoot, "tests", "fixtures", name), "utf8")));
    const user = fixture("stand-user.pem");
    const ca = fixture("stand-ca.pem");
    const store = (extendedValidity: boolean, roots = [ca], intermediates: typeof roots = []) => ({ roots, intermediates, extendedValidity, offerRoot: false });
    const now = user.notBefore.getTime() + 1000;
    expect(trustStatus(user, store(false, []), now)).toBe(0);
    expect(trustStatus(user, store(false, []), user.notAfter.getTime() + 1000)).toBe(0x1);
    expect(trustStatus(user, store(true), now)).toBe(0);
    expect(trustStatus(user, store(true, []), now)).toBe(CERT_TRUST_IS_PARTIAL_CHAIN);
    expect(trustStatus(user, store(true, [], [ca]), now)).toBe(0x20);
    // Kontur's client: trustStatus 487 and the qualified rules, which the stand user's certificate does not pass.
    const verify = (request: Record<string, unknown>, extendedValidity: boolean) => verifyCertificate(request, user, async () => store(extendedValidity, []));
    expect(await verify({ trustStatus: 487 }, false)).toEqual({ ok: true, trustStatus: 0 });
    expect(await verify({ trustStatus: 487 }, true)).toEqual({ ok: true, trustStatus: CERT_TRUST_IS_PARTIAL_CHAIN });
    expect(await verify({ trustStatus: 0x10000 }, true)).toEqual({ ok: false, trustStatus: CERT_TRUST_IS_PARTIAL_CHAIN });
    expect(await verify({}, true)).toEqual({ ok: false, trustStatus: CERT_TRUST_IS_PARTIAL_CHAIN });
    const logged = (await verify({ trustStatus: 487, qualified: { log: true } }, false)) as { ok: boolean; trustStatus: number; errors: { rule: string }[] };
    expect(logged).toMatchObject({ ok: false, trustStatus: 0 });
    expect(logged.errors.map((failure) => failure.rule)).toContain("extensions.policies.exist");
    expect(await verify({ qualified: true }, false)).toEqual({ ok: false });
  });

  it("makes up the computer from Gosplugin's identity: its id, environment and system", async () => {
    const linux = setup();
    const id = await linux.ask("machine.uniqueId");
    expect(id).toMatch(/^[0-9a-f]{64}$/);
    expect(await linux.ask("machine.uniqueId")).toBe(id);
    expect(await linux.ask("os.getEnvironmentVariable", { name: "HOME" })).toBe("/home/ekaterina");
    expect(await linux.ask("os.getEnvironmentVariable", { name: "HOSTNAME" })).toBe("ekaterina-pc");
    await expect(linux.ask("os.getEnvironmentVariable", { name: "home" })).rejects.toMatchObject({ answer: { type: "plugin", code: 13, message: "PLUGIN[0x0000000D] environment variable is not defined" } });
    await expect(linux.ask("os.getEnvironmentVariable", {})).rejects.toMatchObject({ answer: { code: 3 } });
    expect(await linux.ask("os.info")).toEqual({ bitness: 64, family: "Linux", name: "Linux", release: "" });
    const windows = setup("Win32");
    expect(await windows.ask("machine.uniqueId")).not.toBe(id);
    expect(await windows.ask("os.getEnvironmentVariable", { name: "userprofile" })).toBe("C:\\Users\\ekaterina");
    expect(await windows.ask("os.getEnvironmentVariable", { name: "COMPUTERNAME" })).toBe("DESKTOP-9H2LX8D");
    expect(await windows.ask("os.info")).toMatchObject({ bitness: 64, family: "Windows", release: "10.0" });
  });

  it("hashes and moves streams as the host on the stand", async () => {
    const { ask } = setup();
    const data = { type: "base64", data: "aGVsbG8=" };
    expect(await ask("hash.md5", { source: data, sink: { type: "hex" } })).toEqual({ data: "5d41402abc4b2a76b9719d911017c592", size: 16, type: "hex" });
    expect(await ask("hash.sha256", { source: data, sink: { type: "base64" } })).toEqual({ data: "LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=", size: 32, type: "base64" });
    expect(await ask("hash.crc32", { source: data })).toBe(907060870);
    expect(await ask("io.transfer", { source: data, sink: { type: "cache", name: "c" }, sinkOffset: 2 })).toEqual({ name: "c", size: 7, type: "cache" });
    expect(await ask("io.transfer", { source: data, sink: { type: "cache", name: "c" }, sinkOffset: 3 })).toEqual({ name: "c", size: 8, type: "cache" });
    expect(await ask("io.transfer", { source: { type: "cache", name: "c" }, sink: { type: "hex" } })).toEqual({ data: "00006868656c6c6f", size: 8, type: "hex" });
    expect(await ask("io.getInfo", { source: { type: "cache", name: "c" } })).toEqual({ name: "c", size: 8, type: "cache" });
    expect(await ask("io.delete", { source: { type: "cache", name: "c" } })).toBe(true);
    expect(await ask("io.delete", { source: { type: "cache", name: "c" } })).toBe(false);
    await expect(ask("io.transfer", { source: data, sink: { type: "hex" }, sourceOffset: 6 })).rejects.toMatchObject({ answer: { type: "iostreams", code: 6 } });
  });

  it("extracts a zip into a folder the user chose, that is into the downloads", async () => {
    const { ask, downloads } = setup("Linux x86_64", fakeDialogs({ folder: true }));
    const cache = { type: "cache", name: "z" };
    await ask("archive.zip.addEntry", { source: { type: "base64", data: "aGVsbG8=" }, sink: cache, name: "a.txt" });
    await ask("archive.zip.addEntry", { source: { type: "hex", data: "d0bcd0b8d180" }, sink: cache, name: "папка/b.txt", compressionLevel: "best" });
    expect(await ask("archive.zip.getEntries", { source: cache })).toEqual([
      { compressionSize: expect.any(Number), index: 0, isDirectory: false, name: "a.txt", size: 5 },
      { compressionSize: expect.any(Number), index: 1, isDirectory: false, name: "папка/b.txt", size: 6 },
    ]);
    const folder = await ask("ui.selectFolder");
    expect(await ask("archive.zip.extract", { source: cache, destination: folder })).toBeUndefined();
    expect(downloads).toEqual([["a.txt", "hello"], ["b.txt", "мир"]]);
    await expect(ask("archive.zip.extract", { source: cache, destination: "/tmp" })).rejects.toMatchObject({ answer: { code: 16 } });
    const gz = await ask("archive.gzip", { source: { type: "base64", data: "aGVsbG8=" }, sink: { type: "base64" } });
    expect(await ask("archive.ungzip", { source: { type: "base64", data: (gz as { data: string }).data }, sink: { type: "base64" } })).toEqual({ data: "aGVsbG8=", size: 5, type: "base64" });
  });
});
