/// <reference types="chrome" />
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { repoRoot } from "../../scripts/fetch-vendor.ts";
import { formatName } from "../../src/page/dn.ts";
import { parseCertificate, pemToDer } from "../../src/page/x509.ts";
import { BUILTIN_ROOTS } from "../../src/extension/builtin-roots.ts";
import {
  addRoots,
  base64ToDer,
  certificateOf,
  isBuiltin,
  removeRoot,
  rootStore,
  ROOTS_KEY,
  setAllRootsEnabled,
  setRootEnabled,
  setStoreEnabled,
} from "../../src/extension/roots.ts";

const caPem = readFileSync(join(repoRoot, "tests", "fixtures", "stand-ca.pem"), "utf8");
const userPem = readFileSync(join(repoRoot, "tests", "fixtures", "stand-user.pem"), "utf8");
const caThumbprint = parseCertificate(pemToDer(caPem)).thumbprint;
const userThumbprint = parseCertificate(pemToDer(userPem)).thumbprint;
// The roots lkip2.nalog.ru looks for in the Root store (docs/JOURNAL.md): the head CA and the Ministry.
const headCa = "8CAE88BBFD404A7A53630864F9033606E1DC45E2";
const ministry = "2F0CB09BE3550EF17EC4F29C90ABD18BFCAAD63A";

function fakeChrome() {
  const store: Record<string, unknown> = {};
  const api = {
    storage: {
      local: {
        get: async (key: string) => (key in store ? { [key]: structuredClone(store[key]) } : {}),
        set: async (items: Record<string, unknown>) => void Object.assign(store, structuredClone(items)),
      },
    },
  };
  return { api: api as unknown as typeof chrome, store };
}

const encoder = new TextEncoder();
const thumbprints = async (api: typeof chrome) => (await rootStore(api)).certificates.map((root) => certificateOf(root).thumbprint);

describe("built-in roots", () => {
  it("are the self-signed roots from CryptoPro's package, with the ones lkip2.nalog.ru looks for", () => {
    const certificates = BUILTIN_ROOTS.map((der) => parseCertificate(base64ToDer(der)));
    expect(certificates).toHaveLength(12);
    expect(new Set(certificates.map((certificate) => certificate.thumbprint)).size).toBe(12);
    for (const certificate of certificates) expect(formatName(certificate.issuer)).toBe(formatName(certificate.subject));
    expect(certificates.map((certificate) => certificate.thumbprint)).toEqual(expect.arrayContaining([headCa, ministry]));
    expect(isBuiltin(headCa)).toBe(true);
    expect(isBuiltin(caThumbprint)).toBe(false);
  });

  it("include one with fractional seconds in its key usage period, which parses", () => {
    const root = BUILTIN_ROOTS.map((der) => parseCertificate(base64ToDer(der))).find(
      (certificate) => certificate.thumbprint === "9EC1A7DD438D8D647AC40976FC85C33F5D0FBA2B",
    );
    expect(root?.privateKeyNotBefore?.toISOString()).toBe("2025-12-17T10:06:00.876Z");
    expect(root?.privateKeyNotAfter?.toISOString()).toBe("2033-12-17T10:06:00.000Z");
  });
});

describe("root store", () => {
  it("starts as the built-in roots, all enabled, and saves that", async () => {
    const chrome = fakeChrome();
    const store = await rootStore(chrome.api);
    expect(store.enabled).toBe(true);
    expect(store.certificates.map((root) => root.der)).toEqual(BUILTIN_ROOTS);
    expect(store.certificates.every((root) => root.enabled)).toBe(true);
    expect(chrome.store[ROOTS_KEY]).toEqual(store);
  });

  it("switches one certificate, all of them, and the store as a whole", async () => {
    const { api } = fakeChrome();
    await setRootEnabled(headCa, false, api);
    let store = await rootStore(api);
    expect(store.certificates.filter((root) => !root.enabled).map((root) => certificateOf(root).thumbprint)).toEqual([headCa]);
    await setAllRootsEnabled(false, api);
    expect((await rootStore(api)).certificates.every((root) => !root.enabled)).toBe(true);
    await setAllRootsEnabled(true, api);
    expect((await rootStore(api)).certificates.every((root) => root.enabled)).toBe(true);
    await setStoreEnabled(false, api);
    store = await rootStore(api);
    expect(store.enabled).toBe(false);
    expect(store.certificates.every((root) => root.enabled)).toBe(true);
  });

  it("removes a certificate, built-in ones included, and keeps it removed", async () => {
    const { api } = fakeChrome();
    await removeRoot(headCa, api);
    expect(await thumbprints(api)).toHaveLength(11);
    expect(await thumbprints(api)).not.toContain(headCa);
  });

  it("adds PEM, DER and headerless base64, and does not add a certificate twice", async () => {
    const { api } = fakeChrome();
    const pem = await addRoots(encoder.encode(caPem), api);
    expect(pem.added.map((certificate) => certificate.thumbprint)).toEqual([caThumbprint]);
    expect((await addRoots(pemToDer(caPem), api)).present.map((certificate) => certificate.thumbprint)).toEqual([caThumbprint]);
    await removeRoot(caThumbprint, api);
    expect((await addRoots(pemToDer(caPem), api)).added).toHaveLength(1);
    await removeRoot(caThumbprint, api);
    const bare = caPem.replace(/-----[^-]+-----/g, "");
    expect((await addRoots(encoder.encode(bare), api)).added).toHaveLength(1);
    const all = await rootStore(api);
    expect(all.certificates).toHaveLength(13);
    expect(all.certificates.at(-1)).toEqual({ der: expect.any(String), enabled: true });
  });

  it("adds every certificate of a PEM bundle with CRLF line ends", async () => {
    const { api } = fakeChrome();
    const bundle = `Bag Attributes\r\n${caPem}\r\n${userPem}`.replaceAll("\n", "\r\n");
    const result = await addRoots(encoder.encode(bundle), api);
    expect(result.added.map((certificate) => certificate.thumbprint)).toEqual([caThumbprint, userThumbprint]);
  });

  it("refuses a file that is not a certificate, adding nothing", async () => {
    const { api } = fakeChrome();
    const der = pemToDer(caPem);
    for (const bytes of [encoder.encode("hello"), encoder.encode(""), Uint8Array.of(...der, 0), der.subarray(0, 100), encoder.encode("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")]) {
      await expect(addRoots(bytes, api)).rejects.toThrow("не похож на сертификат X.509");
    }
    expect(await thumbprints(api)).toHaveLength(12);
  });
});
