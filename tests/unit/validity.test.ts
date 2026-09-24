// Certificate.IsValid() in both modes, CAdESCOM.Certificate.Import and Store.Add (docs/PLAN.md, action 20), with
// the answers CryptoPro's plug-in 2.0.15700 gave (docs/JOURNAL.md, 2026-09-24); and the service worker's side
// of Store.Add (src/extension/install.ts).
/// <reference types="chrome" />
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { repoRoot } from "../../scripts/fetch-vendor.ts";
import { ERROR_CANCELLED, Installer } from "../../src/extension/install.ts";
import { extraStore } from "../../src/extension/roots.ts";
import { STORAGE_KEY } from "../../src/extension/sites.ts";
import { CERT_TRUST_IS_NOT_SIGNATURE_VALID, CERT_TRUST_IS_NOT_TIME_VALID, CERT_TRUST_IS_UNTRUSTED_ROOT, validationChain } from "../../src/page/chain.ts";
import { parseSignedData } from "../../src/page/cms.ts";
import { constants } from "../../src/page/constants.ts";
import type { Certificate, Certificates } from "../../src/page/objects/certificate.ts";
import { createObject } from "../../src/page/objects/index.ts";
import type { Store } from "../../src/page/objects/store.ts";
import { derToBase64, parseCertificate, pemToDer, type X509 } from "../../src/page/x509.ts";
import { fakePlugin, FakePinDialog, fakeSession, type FakeStores } from "./fakes.ts";

const fixture = (name: string) => readFileSync(join(repoRoot, "tests", "fixtures", name), "utf8");
const standCaPem = fixture("stand-ca.pem");
const standCa = parseCertificate(pemToDer(standCaPem));
const standUser = parseCertificate(pemToDer(fixture("stand-user.pem")));
const verify = JSON.parse(fixture("verify.json")) as { ca: string; crafted: Record<string, string> };
const der = (base64: string) => Uint8Array.from(Buffer.from(base64, "base64"));
// The CA of the crafted signatures has the stand CA's name and another key.
const otherCa = parseCertificate(der(verify.ca));
const signed = (name: string) => parseSignedData(der(verify.crafted[name]!)).certificates;

const E_INVALIDARG = 0x80070057;
const E_ACCESSDENIED = 0x80070005;
const E_NOTIMPL = 0x80004001;

const thumbprints = (certificates: X509[]) => certificates.map((certificate) => certificate.thumbprint);

describe("the chain of the extended check", () => {
  it("is trusted up to a root of the store, every status clear", () => {
    const chain = validationChain(standUser, [], [standCa]);
    expect(thumbprints(chain.certificates)).toEqual([standUser.thumbprint, standCa.thumbprint]);
    expect(chain.statuses).toEqual([0, 0]);
    expect(chain.valid).toBe(true);
  });

  it("marks a self-signed top the store lacks as an untrusted root, and a certificate out of its period", () => {
    const untrusted = validationChain(standUser, [standCa], []);
    expect(untrusted.statuses).toEqual([0, CERT_TRUST_IS_UNTRUSTED_ROOT]);
    expect(untrusted.valid).toBe(false);
    const expired = validationChain(standUser, [], [standCa], standUser.notAfter.getTime() + 1000);
    expect(expired.statuses).toEqual([CERT_TRUST_IS_NOT_TIME_VALID, 0]);
    expect(expired.valid).toBe(false);
    const root = validationChain(standCa, [], []);
    expect(root.statuses).toEqual([CERT_TRUST_IS_UNTRUSTED_ROOT]);
  });

  it("ends where no issuer is found, without a status and not valid", () => {
    const chain = validationChain(standUser, [], []);
    expect(thumbprints(chain.certificates)).toEqual([standUser.thumbprint]);
    expect(chain.statuses).toEqual([0]);
    expect(chain.valid).toBe(false);
  });

  it("marks an issuer found by name whose key does not verify, on the issuer", () => {
    const chain = validationChain(standUser, [], [otherCa]);
    expect(thumbprints(chain.certificates)).toEqual([standUser.thumbprint, otherCa.thumbprint]);
    expect(chain.statuses).toEqual([0, CERT_TRUST_IS_NOT_SIGNATURE_VALID]);
    // With the right one beside it, the right one is taken.
    expect(validationChain(standUser, [], [otherCa, standCa]).valid).toBe(true);
  });

  it("goes through an intermediate of the store", () => {
    const certificates = signed("intermediate");
    const signer = certificates.find((certificate) => !certificates.some((other) => other !== certificate && same(other.issuerDer, certificate.subjectDer)))!;
    const middle = certificates.find((certificate) => certificate !== signer)!;
    expect(validationChain(signer, [middle], [otherCa]).statuses).toEqual([0, 0, 0]);
    expect(validationChain(signer, [], [otherCa]).valid).toBe(false);
  });
});

function same(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

function session(roots: X509[], intermediates: X509[], stores: FakeStores) {
  return fakeSession(fakePlugin(), new FakePinDialog([]), roots, intermediates, stores);
}

async function tokenCertificate(stores: FakeStores, roots: X509[] = [], intermediates: X509[] = []): Promise<Certificate> {
  const store = createObject("CAdESCOM.Store", session(roots, intermediates, stores)) as Store;
  await store.Open();
  return (await store.Certificates).Item(1);
}

describe("Certificate.IsValid()", () => {
  it("off: only the dates, whatever the stores hold, and no chain", async () => {
    const status = await (await tokenCertificate({})).IsValid();
    expect(await status.Result).toBe(true);
    expect(status.ValidationCertificates).toBeUndefined();
    expect(status.ErrorStatuses).toBeUndefined();
  });

  it("on: the chain from the root down, the statuses from the certificate up, as the demo page reads them", async () => {
    const untrusted = await (await tokenCertificate({ extendedValidity: true }, [], [standCa])).IsValid();
    expect(await untrusted.Result).toBe(false);
    const chain = (await untrusted.ValidationCertificates) as Certificates;
    expect(await chain.Count).toBe(2);
    expect(await (await chain.Item(1)).Thumbprint).toBe(standCa.thumbprint);
    const statuses = (await untrusted.ErrorStatuses)!;
    expect(await statuses.Count).toBe(2);
    expect(await statuses.Item(1)).toBe(0);
    expect(await statuses.Item(2)).toBe(constants.CERT_TRUST_IS_UNTRUSTED_ROOT);
    await expect(statuses.Item(0)).rejects.toMatchObject({ number: E_INVALIDARG });
    await expect(statuses.Item(3)).rejects.toMatchObject({ number: E_INVALIDARG });
    const trusted = await (await tokenCertificate({ extendedValidity: true }, [standCa])).IsValid();
    expect(await trusted.Result).toBe(true);
  });

  it("on: decides what Certificates.Find keeps with its valid-only flag", async () => {
    const store = createObject("CAdESCOM.Store", session([], [], { extendedValidity: true })) as Store;
    await store.Open();
    const found = await (await store.Certificates).Find(constants.CAPICOM_CERTIFICATE_FIND_SHA1_HASH, standUser.thumbprint, true);
    expect(await found.Count).toBe(0);
  });
});

describe("CAdESCOM.Certificate", () => {
  const create = () => createObject("CAdESCOM.Certificate", session([], [], {})) as Certificate;
  const body = standCaPem.replace(/-----[^-]+-----|\s/g, "");

  it("is empty until Import, and then answers for the certificate", async () => {
    const certificate = create();
    expect(() => certificate.SubjectName).toThrow(expect.objectContaining({ number: 0x8007139f }));
    expect(() => certificate.HasPrivateKey()).toThrow(expect.objectContaining({ number: 0x8007139f }));
    for (const text of [standCaPem, standCaPem.replace(/\n/g, "\r\n"), body, body.replace(/(.{64})/g, "$1\n")]) {
      await create().Import(text);
    }
    await certificate.Import(standCaPem);
    expect(await certificate.Thumbprint).toBe(standCa.thumbprint);
    expect(await certificate.HasPrivateKey()).toBe(false);
  });

  it("refuses an empty text and one that is not a certificate with the plug-in's codes", () => {
    expect(() => create().Import("")).toThrow(expect.objectContaining({ number: E_INVALIDARG }));
    expect(() => create().Import("hello")).toThrow(expect.objectContaining({ number: 0x8007054f }));
  });
});

describe("Store.Add", () => {
  async function opened(stores: FakeStores, ...args: unknown[]): Promise<Store> {
    const store = createObject("CAdESCOM.Store", session([], [], stores)) as Store;
    await (store.Open as (...a: unknown[]) => Promise<void>)(...args);
    return store;
  }
  const imported = async () => {
    const certificate = createObject("CAdESCOM.Certificate", session([], [], {})) as Certificate;
    await certificate.Import(standCaPem);
    return certificate;
  };

  it("hands a certificate added to Root or CA to the extension, and lists it", async () => {
    const stores: FakeStores = { added: [] };
    const root = await opened(stores, constants.CAPICOM_CURRENT_USER_STORE, "ROOT", constants.CAPICOM_STORE_OPEN_READ_WRITE);
    await root.Add(await imported());
    const ca = await opened(stores, constants.CAPICOM_CURRENT_USER_STORE, "CA");
    await ca.Add(await imported());
    expect(stores.added!.map(({ store, certificate }) => [store, certificate.thumbprint])).toEqual([
      ["root", standCa.thumbprint],
      ["ca", standCa.thumbprint],
    ]);
    expect(await (await root.Certificates).Count).toBe(1);
  });

  it("answers as the plug-in: not open or not a certificate, read-only, My, and a refusal passed on", async () => {
    const certificate = await imported();
    const closed = createObject("CAdESCOM.Store", session([], [], {})) as Store;
    await expect(closed.Add(certificate)).rejects.toMatchObject({ number: E_INVALIDARG });
    await expect((await opened({}, 2, "CA", 1)).Add("MIIB")).rejects.toMatchObject({ number: E_INVALIDARG });
    await expect((await opened({}, 2, "Root", 0)).Add(certificate)).rejects.toMatchObject({ number: E_ACCESSDENIED });
    await expect((await opened({})).Add(certificate)).rejects.toMatchObject({ number: E_INVALIDARG });
    await expect((await opened({}, 2, "AddressBook", 1)).Add(certificate)).rejects.toMatchObject({ number: E_NOTIMPL });
    const refusal = Object.assign(new Error("Пользователь не разрешил добавить сертификат."), { number: ERROR_CANCELLED });
    await expect((await opened({ refuse: refusal }, 2, "Root", 1)).Add(certificate)).rejects.toBe(refusal);
  });
});

function fakeChrome(sites: string[]) {
  const store: Record<string, unknown> = { [STORAGE_KEY]: sites };
  const windows: { url: string; id: number }[] = [];
  const api = {
    storage: {
      local: {
        get: async (keys: string | string[]) =>
          Object.fromEntries([keys].flat().filter((key) => key in store).map((key) => [key, structuredClone(store[key])])),
        set: async (items: Record<string, unknown>) => void Object.assign(store, structuredClone(items)),
      },
    },
    runtime: { getURL: (path: string) => `chrome-extension://id/${path}` },
    windows: {
      create: async ({ url }: { url: string }) => {
        const window = { url, id: windows.length + 1 };
        windows.push(window);
        return window;
      },
    },
  };
  return { api: api as unknown as typeof chrome, windows };
}

const site = "https://ca.example";
const tick = () => new Promise((resolve) => setTimeout(resolve));

describe("the service worker adding a site's certificate", () => {
  const root = derToBase64(standCa.der);
  const leaf = derToBase64(standUser.der);

  it("adds an intermediate to CA at once", async () => {
    const { api, windows } = fakeChrome([site]);
    expect(await new Installer(api).add({ store: "ca", certificate: leaf }, `${site}/page`)).toEqual({});
    expect(windows).toEqual([]);
    expect((await extraStore(api)).certificates).toHaveLength(1);
  });

  it("adds a root after the user says yes in its window, and not after a no or a closed window", async () => {
    const { api, windows } = fakeChrome([site]);
    const installer = new Installer(api);
    const answered = installer.add({ store: "root", certificate: root }, `${site}/page`);
    await tick();
    const id = new URL(windows[0]!.url).searchParams.get("id");
    expect(installer.details(id)).toEqual({ origin: site, store: "root", certificate: root });
    installer.answer(id, true);
    expect(await answered).toEqual({});
    expect((await extraStore(api)).certificates).toHaveLength(1);
    expect(installer.details(id)).toBeUndefined();

    const refused = installer.add({ store: "ca", certificate: root }, `${site}/page`);
    await tick();
    installer.answer(new URL(windows[1]!.url).searchParams.get("id"), false);
    expect((await refused).error?.code).toBe(ERROR_CANCELLED);
    const closed = installer.add({ store: "root", certificate: leaf }, `${site}/page`);
    await tick();
    installer.windowClosed(windows[2]!.id);
    expect((await closed).error?.code).toBe(ERROR_CANCELLED);
    expect((await extraStore(api)).certificates).toHaveLength(1);
  });

  it("refuses a site that is not enabled and anything but one certificate for Root or CA", async () => {
    const { api, windows } = fakeChrome([site]);
    const installer = new Installer(api);
    expect((await installer.add({ store: "ca", certificate: leaf }, "https://other.example/")).error?.code).toBe(E_ACCESSDENIED);
    expect((await installer.add({ store: "my" as "ca", certificate: leaf }, site)).error?.code).toBe(E_INVALIDARG);
    expect((await installer.add({ store: "ca", certificate: "AAAA" }, site)).error?.code).toBe(E_INVALIDARG);
    expect(windows).toEqual([]);
  });
});
