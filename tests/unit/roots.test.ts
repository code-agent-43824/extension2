/// <reference types="chrome" />
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { repoRoot } from "../../scripts/fetch-vendor.ts";
import { formatName } from "../../src/page/dn.ts";
import { parseCertificate, pemToDer } from "../../src/page/x509.ts";
import { BUILTIN_ROOTS } from "../../src/extension/builtin-roots.ts";
import { storeCertificates, ROOTS_REQUEST, ROOTS_RESPONSE, ROOTS_WAIT_MS } from "../../src/page/roots.ts";
import type { Clock } from "../../src/page/rutoken.ts";
import {
  addCertificates,
  base64ToDer,
  certificateOf,
  certificateStores,
  enabledCertificates,
  EXTRA_KEY,
  extraStore,
  isBuiltin,
  removeCertificate,
  rootStore,
  ROOTS_KEY,
  setAllEnabled,
  setCertificateEnabled,
  setStoreEnabled,
} from "../../src/extension/roots.ts";

const caPem = readFileSync(join(repoRoot, "tests", "fixtures", "stand-ca.pem"), "utf8");
const userPem = readFileSync(join(repoRoot, "tests", "fixtures", "stand-user.pem"), "utf8");
const caThumbprint = parseCertificate(pemToDer(caPem)).thumbprint;
const userThumbprint = parseCertificate(pemToDer(userPem)).thumbprint;
// The roots lkip2.nalog.ru looks for in the Root store (docs/JOURNAL.md): the head CA and the Ministry.
const headCa = "8CAE88BBFD404A7A53630864F9033606E1DC45E2";
const headCaDer = () => base64ToDer(BUILTIN_ROOTS.find((der) => parseCertificate(base64ToDer(der)).thumbprint === headCa)!);
const ministry = "2F0CB09BE3550EF17EC4F29C90ABD18BFCAAD63A";

function fakeChrome() {
  const store: Record<string, unknown> = {};
  const api = {
    storage: {
      local: {
        get: async (keys: string | string[]) =>
          Object.fromEntries([keys].flat().filter((key) => key in store).map((key) => [key, structuredClone(store[key])])),
        set: async (items: Record<string, unknown>) => void Object.assign(store, structuredClone(items)),
      },
    },
  };
  return { api: api as unknown as typeof chrome, store };
}

const encoder = new TextEncoder();
const thumbprints = async (api: typeof chrome) => (await rootStore(api)).certificates.map((root) => certificateOf(root).thumbprint);
const extraThumbprints = async (api: typeof chrome) => (await extraStore(api)).certificates.map((root) => certificateOf(root).thumbprint);
const thumbprintOfDer = (der: string) => parseCertificate(base64ToDer(der)).thumbprint;

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

describe("certificate stores", () => {
  it("start as the built-in roots, all enabled, and an empty second store, and save that", async () => {
    const chrome = fakeChrome();
    const store = await rootStore(chrome.api);
    expect(store.enabled).toBe(true);
    expect(store.certificates.map((root) => root.der)).toEqual(BUILTIN_ROOTS);
    expect(store.certificates.every((root) => root.enabled)).toBe(true);
    expect(chrome.store[ROOTS_KEY]).toEqual(store);
    expect(chrome.store[EXTRA_KEY]).toEqual({ enabled: true, certificates: [] });
  });

  it("switch one certificate, all of them, and a store as a whole", async () => {
    const { api } = fakeChrome();
    await setCertificateEnabled("roots", headCa, false, api);
    let store = await rootStore(api);
    expect(store.certificates.filter((root) => !root.enabled).map((root) => certificateOf(root).thumbprint)).toEqual([headCa]);
    await setAllEnabled("roots", false, api);
    expect((await rootStore(api)).certificates.every((root) => !root.enabled)).toBe(true);
    await setAllEnabled("roots", true, api);
    expect((await rootStore(api)).certificates.every((root) => root.enabled)).toBe(true);
    await setStoreEnabled("roots", false, api);
    store = await rootStore(api);
    expect(store.enabled).toBe(false);
    expect(store.certificates.every((root) => root.enabled)).toBe(true);
    expect((await extraStore(api)).enabled).toBe(true);
  });

  it("remove a built-in root and keep it removed, until its file is added back", async () => {
    const { api } = fakeChrome();
    await removeCertificate("roots", headCa, api);
    expect(await thumbprints(api)).toHaveLength(11);
    expect(await thumbprints(api)).not.toContain(headCa);
    const result = await addCertificates(headCaDer(), api);
    expect(result.restored.map((certificate) => certificate.thumbprint)).toEqual([headCa]);
    expect(result.added).toEqual([]);
    expect(await thumbprints(api)).toContain(headCa);
    expect(await extraThumbprints(api)).toEqual([]);
    expect((await addCertificates(headCaDer(), api)).present).toHaveLength(1);
  });

  it("add PEM, DER and headerless base64 to the second store, and not a certificate twice", async () => {
    const { api } = fakeChrome();
    const pem = await addCertificates(encoder.encode(caPem), api);
    expect(pem.added.map((certificate) => certificate.thumbprint)).toEqual([caThumbprint]);
    expect((await addCertificates(pemToDer(caPem), api)).present.map((certificate) => certificate.thumbprint)).toEqual([caThumbprint]);
    await removeCertificate("extra", caThumbprint, api);
    expect((await addCertificates(pemToDer(caPem), api)).added).toHaveLength(1);
    await removeCertificate("extra", caThumbprint, api);
    const bare = caPem.replace(/-----[^-]+-----/g, "");
    expect((await addCertificates(encoder.encode(bare), api)).added).toHaveLength(1);
    expect(await thumbprints(api)).toHaveLength(12);
    expect((await extraStore(api)).certificates).toEqual([{ der: expect.any(String), enabled: true }]);
  });

  it("add every certificate of a PEM bundle with CRLF line ends", async () => {
    const { api } = fakeChrome();
    const bundle = `Bag Attributes\r\n${caPem}\r\n${userPem}`.replaceAll("\n", "\r\n");
    const result = await addCertificates(encoder.encode(bundle), api);
    expect(result.added.map((certificate) => certificate.thumbprint)).toEqual([caThumbprint, userThumbprint]);
    expect(await extraThumbprints(api)).toEqual([caThumbprint, userThumbprint]);
  });

  it("refuse a file that is not a certificate, adding nothing", async () => {
    const { api } = fakeChrome();
    const der = pemToDer(caPem);
    for (const bytes of [encoder.encode("hello"), encoder.encode(""), Uint8Array.of(...der, 0), der.subarray(0, 100), encoder.encode("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")]) {
      await expect(addCertificates(bytes, api)).rejects.toThrow("не похож на сертификат X.509");
    }
    expect(await thumbprints(api)).toHaveLength(12);
    expect(await extraThumbprints(api)).toEqual([]);
  });

  it("move certificates added to the root store before 1.1.0 to the second store, as enabled as they were", async () => {
    const chrome = fakeChrome();
    const ca = { der: Buffer.from(pemToDer(caPem)).toString("base64"), enabled: false };
    chrome.store[ROOTS_KEY] = { enabled: true, certificates: [...BUILTIN_ROOTS.slice(1).map((der) => ({ der, enabled: true })), ca] };
    const stores = await certificateStores(chrome.api);
    expect(stores.roots.certificates.map((root) => root.der)).toEqual(BUILTIN_ROOTS.slice(1));
    expect(stores.extra).toEqual({ enabled: true, certificates: [ca] });
    expect(chrome.store[EXTRA_KEY]).toEqual(stores.extra);
    expect(chrome.store[ROOTS_KEY]).toEqual(stores.roots);
  });
});

describe("what sites see", () => {
  it("is the enabled roots, none with a store off, and the built-in ones before anything is saved", async () => {
    const chrome = fakeChrome();
    expect(await enabledCertificates(chrome.api)).toEqual({ roots: BUILTIN_ROOTS, intermediates: [] });
    expect(chrome.store[ROOTS_KEY]).toBeUndefined();
    await setCertificateEnabled("roots", headCa, false, chrome.api);
    const rest = (await enabledCertificates(chrome.api)).roots;
    expect(rest).toHaveLength(11);
    expect(rest.map(thumbprintOfDer)).not.toContain(headCa);
    await setStoreEnabled("roots", false, chrome.api);
    expect(await enabledCertificates(chrome.api)).toEqual({ roots: [], intermediates: [] });
  });

  it("takes a self-signed certificate added from a file as a root, any other as an intermediate", async () => {
    const { api } = fakeChrome();
    await addCertificates(encoder.encode(caPem + userPem), api);
    let seen = await enabledCertificates(api);
    expect(seen.roots.map(thumbprintOfDer)).toEqual([...BUILTIN_ROOTS.map(thumbprintOfDer), caThumbprint]);
    expect(seen.intermediates.map(thumbprintOfDer)).toEqual([userThumbprint]);
    await setStoreEnabled("roots", false, api);
    seen = await enabledCertificates(api);
    expect(seen.roots.map(thumbprintOfDer)).toEqual([caThumbprint]);
    await setCertificateEnabled("extra", userThumbprint, false, api);
    expect((await enabledCertificates(api)).intermediates).toEqual([]);
    await setStoreEnabled("extra", false, api);
    expect(await enabledCertificates(api)).toEqual({ roots: [], intermediates: [] });
  });
});

// A window as far as postMessage goes: messages are delivered asynchronously with the window as source.
function fakeWindow() {
  const target = new EventTarget();
  const win = Object.assign(target, {
    postMessage(data: unknown) {
      setTimeout(() => target.dispatchEvent(Object.assign(new Event("message"), { data, source: win })));
    },
  });
  return win as unknown as Window;
}

class ManualClock implements Clock {
  timers: (() => void)[] = [];
  setTimeout(callback: () => void) {
    this.timers.push(callback);
  }
  now() {
    return 0;
  }
}

describe("page.js asking for the stores", () => {
  it("gets them from the bridge's answer to its own request", async () => {
    const win = fakeWindow();
    win.addEventListener("message", (event) => {
      const { data } = event as MessageEvent;
      if (data?.type !== ROOTS_REQUEST) return;
      // An answer to another request, then a broken certificate among good ones: both are ignored.
      win.postMessage({ type: ROOTS_RESPONSE, id: "other", certificates: [] }, "*");
      win.postMessage(
        { type: ROOTS_RESPONSE, id: data.id, certificates: [BUILTIN_ROOTS[0], "AAAA", BUILTIN_ROOTS[1]], intermediates: [7, BUILTIN_ROOTS[2]] },
        "*",
      );
    });
    const { roots, intermediates } = await storeCertificates(win, new ManualClock());
    expect(roots.map((certificate) => certificate.thumbprint)).toEqual(BUILTIN_ROOTS.slice(0, 2).map(thumbprintOfDer));
    expect(intermediates.map((certificate) => certificate.thumbprint)).toEqual([thumbprintOfDer(BUILTIN_ROOTS[2]!)]);
  });

  it("takes an answer without intermediates, from a bridge before 1.1.0", async () => {
    const win = fakeWindow();
    win.addEventListener("message", (event) => {
      const { data } = event as MessageEvent;
      if (data?.type === ROOTS_REQUEST) win.postMessage({ type: ROOTS_RESPONSE, id: data.id, certificates: [BUILTIN_ROOTS[0]] }, "*");
    });
    expect((await storeCertificates(win, new ManualClock())).intermediates).toEqual([]);
  });

  it("sees an empty store when nothing answers in time", async () => {
    const clock = new ManualClock();
    const pending = storeCertificates(fakeWindow(), clock);
    expect(clock.timers).toHaveLength(1);
    clock.timers[0]!();
    expect(await pending).toEqual({ roots: [], intermediates: [] });
    expect(ROOTS_WAIT_MS).toBeGreaterThan(0);
  });
});
