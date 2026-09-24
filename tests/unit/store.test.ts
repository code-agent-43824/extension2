import { afterEach, describe, expect, it, vi } from "vitest";
import { constants } from "../../src/page/constants.ts";
import type { Certificate, Certificates } from "../../src/page/objects/certificate.ts";
import { createObject } from "../../src/page/objects/index.ts";
import type { Store } from "../../src/page/objects/store.ts";
import type { RutokenPlugin } from "../../src/page/rutoken.ts";
import { base64ToDer } from "../../src/extension/roots.ts";
import { BUILTIN_ROOTS } from "../../src/extension/builtin-roots.ts";
import { parseCertificate, type X509 } from "../../src/page/x509.ts";
import { certId, fakePlugin, FakePinDialog, fakeSession, pem } from "./fakes.ts";

const roots = BUILTIN_ROOTS.map((der) => parseCertificate(base64ToDer(der)));

async function openStore(plugin: RutokenPlugin, ...args: unknown[]): Promise<Certificates> {
  return openStoreWith(plugin, [], ...args);
}

async function openStoreWith(plugin: RutokenPlugin, rootStore: X509[], ...args: unknown[]): Promise<Certificates> {
  const store = createObject("CAdESCOM.Store", fakeSession(plugin, new FakePinDialog([]), rootStore)) as Store;
  await (store.Open as (...a: unknown[]) => Promise<void>)(...args);
  return store.Certificates;
}

afterEach(() => {
  vi.useRealTimers();
});

describe("CAdESCOM.Store", () => {
  it("lists the token's user certificates in My, with and without arguments, and in the container store", async () => {
    const plugin = fakePlugin();
    for (const args of [[], [constants.CAPICOM_CURRENT_USER_STORE, "My", constants.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED], [constants.CADESCOM_CONTAINER_STORE]]) {
      expect(await (await openStore(plugin, ...args)).Count).toBe(1);
    }
  });

  it("lists the root store in Root, in either location and any case, and keeps CA empty", async () => {
    const { CAPICOM_CURRENT_USER_STORE: user, CAPICOM_LOCAL_MACHINE_STORE: machine } = constants;
    for (const [location, name] of [[user, "Root"], [machine, "Root"], [user, "root"]] as const) {
      expect(await (await openStoreWith(fakePlugin(), roots, location, name)).Count).toBe(roots.length);
    }
    expect(await (await openStore(fakePlugin(), user, "Root")).Count).toBe(0);
    expect(await (await openStoreWith(fakePlugin(), roots, user, "CA")).Count).toBe(0);
  });

  it("finds a root by SHA-1 as lkip2.nalog.ru does, without a key, as CryptoPro answers for its Root store", async () => {
    const certs = await openStoreWith(fakePlugin(), roots, constants.CAPICOM_CURRENT_USER_STORE, "Root", constants.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED);
    const found = await certs.Find(constants.CAPICOM_CERTIFICATE_FIND_SHA1_HASH, "8CAE88BBFD404A7A53630864F9033606E1DC45E2");
    expect(await found.Count).toBe(1);
    const root = await found.Item(1);
    expect(await root.SubjectName).toContain("CN=Головной удостоверяющий центр");
    expect(await root.HasPrivateKey()).toBe(false);
    await expect(root.PrivateKey).rejects.toMatchObject({ number: 0x80092004 });
  });

  it("finds the certificates with a key by their extended property, as markirovka.crpt.ru asks", async () => {
    const { CAPICOM_CERTIFICATE_FIND_EXTENDED_PROPERTY: property, CAPICOM_CURRENT_USER_STORE: user } = constants;
    expect(await (await (await openStore(fakePlugin())).Find(property, 2)).Count).toBe(1);
    expect(await (await (await openStore(fakePlugin())).Find(property, 9)).Count).toBe(0);
    expect(await (await (await openStore(fakePlugin())).Find(property)).Count).toBe(0);
    const root = await openStoreWith(fakePlugin(), roots, user, "Root");
    expect(await (await root.Find(property, 2)).Count).toBe(0);
    expect(await (await root.Find(property, 3)).Count).toBe(roots.length);
    for (const bad of [31, "2"]) await expect(root.Find(property, bad)).rejects.toMatchObject({ number: 0x80070057 });
  });

  it("finds by one key usage flag and refuses anything else, as sberbank-ast.ru asks and CryptoPro answers", async () => {
    const { CAPICOM_CERTIFICATE_FIND_KEY_USAGE: usage, CAPICOM_DIGITAL_SIGNATURE_KEY_USAGE: signature, CAPICOM_CURRENT_USER_STORE: user } = constants;
    const my = await openStore(fakePlugin());
    expect(await (await my.Find(usage, signature)).Count).toBe(1);
    expect(await (await my.Find(usage, 4)).Count).toBe(0);
    const root = await openStoreWith(fakePlugin(), roots, user, "Root");
    // By asn1crypto: 4 of the 12 built-in roots have digitalSignature, all have keyCertSign.
    expect(await (await root.Find(usage, signature)).Count).toBe(4);
    expect(await (await root.Find(usage, 4)).Count).toBe(12);
    for (const bad of [132, 0, "128", "DigitalSignature", undefined]) {
      await expect(root.Find(usage, bad)).rejects.toMatchObject({ number: 0x80070057 });
    }
  });

  it("finds by validity time, now or at the given time", async () => {
    const { CAPICOM_CERTIFICATE_FIND_TIME_VALID: valid, CAPICOM_CERTIFICATE_FIND_TIME_NOT_YET_VALID: notYet, CAPICOM_CERTIFICATE_FIND_TIME_EXPIRED: expired } = constants;
    const my = await openStore(fakePlugin());
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2027-01-01T00:00:00Z"));
    expect(await (await my.Find(valid)).Count).toBe(1);
    expect(await (await my.Find(notYet)).Count).toBe(0);
    expect(await (await my.Find(expired)).Count).toBe(0);
    expect(await (await my.Find(valid, "2029-01-01T00:00:00.000Z")).Count).toBe(0);
    expect(await (await my.Find(expired, "2029-01-01T00:00:00.000Z")).Count).toBe(1);
    expect(await (await my.Find(notYet, "2026-01-01T00:00:00.000Z")).Count).toBe(1);
  });

  it("answers Certificates after an Open that was not awaited, and Close after both", async () => {
    const store = createObject("CAdESCOM.Store", fakeSession(fakePlugin(), new FakePinDialog([]))) as Store;
    void store.Open(constants.CAPICOM_CURRENT_USER_STORE, "My");
    const listed = store.Certificates;
    void store.Close();
    expect(await (await listed).Count).toBe(1);
    expect(await (await store.Certificates).Count).toBe(0);
  });

  it("skips a certificate that does not parse", async () => {
    expect(await (await openStore(fakePlugin([pem, "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"]))).Count).toBe(1);
  });

  it("indexes certificates from 1 and rejects out-of-range indexes", async () => {
    const certs = await openStore(fakePlugin());
    await expect(certs.Item(1)).resolves.toBeDefined();
    await expect(certs.Item(0)).rejects.toThrow("индекс");
    await expect(certs.Item(2)).rejects.toThrow("индекс");
  });
});

describe("CAdESCOM.Certificate", () => {
  async function certificate(): Promise<Certificate> {
    return (await openStore(fakePlugin())).Item(1);
  }

  it("finds certificates by thumbprint in any case and by a piece of the subject name", async () => {
    const all = await openStore(fakePlugin());
    const byHash = await all.Find(constants.CAPICOM_CERTIFICATE_FIND_SHA1_HASH, "cdea7eab5be6b167f22b713bf376e9b28adb14a3");
    expect(await byHash.Count).toBe(1);
    expect(await (await byHash.Item(1)).Thumbprint).toBe("CDEA7EAB5BE6B167F22B713BF376E9B28ADB14A3");
    expect(await (await all.Find(constants.CAPICOM_CERTIFICATE_FIND_SUBJECT_NAME, "stand user")).Count).toBe(1);
    expect(await (await all.Find(constants.CAPICOM_CERTIFICATE_FIND_SHA1_HASH, "00")).Count).toBe(0);
    await expect(all.Find(constants.CAPICOM_CERTIFICATE_FIND_TEMPLATE_NAME, "x")).rejects.toThrow("0x80004001");
  });

  it("exports itself as base64 in 64-column LF lines, and refuses binary", async () => {
    const cert = await certificate();
    const text = await cert.Export(constants.CADESCOM_ENCODE_BASE64);
    expect(text.replace(/\n/g, "")).toBe(pem.replace(/-----[^-]+-----|\s/g, ""));
    expect(text.split("\n").slice(0, -2).every((line) => line.length === 64)).toBe(true);
    expect(text.endsWith("\n")).toBe(true);
    expect(() => cert.Export(constants.CADESCOM_ENCODE_BINARY)).toThrow("0x80070057");
  });

  it("reports what the demo page's certificate card reads", async () => {
    const cert = await certificate();
    expect(await cert.Thumbprint).toBe("CDEA7EAB5BE6B167F22B713BF376E9B28ADB14A3");
    expect(await cert.SerialNumber).toBe("4C348384107C9CE89D96A8855FF9672B");
    expect(await cert.SubjectName).toMatch(/^E=stand@example\.com, .*CN=Stand User, .*C=RU$/);
    expect(await cert.IssuerName).toBe("CN=Stand Test CA, O=Стенд, C=RU");
    expect(await cert.ValidFromDate).toBe("2026-09-22T14:10:24.000Z");
    expect(await cert.ValidToDate).toBe("2028-09-22T14:10:24.000Z");
    expect(await cert.PrivateKeyUsagePeriodFrom).toBe("2026-09-22T14:10:24.000Z");
    expect(await cert.PrivateKeyUsagePeriodTo).toBe("2027-09-23T14:10:24.000Z");
    expect(await cert.HasPrivateKey()).toBe(true);
    expect(await (await (await cert.PublicKey()).Algorithm).FriendlyName).toBe("ГОСТ Р 34.10-2012 256 бит");
    const key = await cert.PrivateKey;
    expect(await key.ProviderName).toBe("Rutoken Plugin 4.12.3.0");
    expect(await key.UniqueContainerName).toBe(`\\\\.\\Rutoken 1669552163\\${certId}`);
    await key.propset_CachePin(false);
    expect(await key.CachePin).toBe(false);
  });

  it("is valid only inside its validity period", async () => {
    const cert = await certificate();
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2027-01-01T00:00:00Z"));
    expect(await (await cert.IsValid()).Result).toBe(true);
    vi.setSystemTime(new Date("2029-01-01T00:00:00Z"));
    expect(await (await cert.IsValid()).Result).toBe(false);
  });
});
