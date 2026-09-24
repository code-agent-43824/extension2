// The extension's own certificate stores, kept in chrome.storage.local and edited on the options page, apart from
// the Rutoken Plugin and the token (docs/PLAN.md of stage 5, actions 12, 13 and 18). Two of them, on two tabs:
// the root certificates CryptoPro CSP installs (builtin-roots.ts), and the ones the user adds from files, roots
// of other CAs and intermediate CAs. Enabled sites see the enabled roots of both as CryptoPro's "Root" store and
// the intermediates as "CA" (roots-bridge.ts, src/page/roots.ts); verification chains through the intermediates.
import { read } from "../page/asn1.ts";
import { derToBase64, parseCertificate, pemToDer, type X509 } from "../page/x509.ts";
import { BUILTIN_ROOTS } from "./builtin-roots.ts";

export const ROOTS_KEY = "roots";
export const EXTRA_KEY = "extraCertificates";

// Which store: the built-in roots' tab, or the tab of the certificates added from files.
export type Tab = "roots" | "extra";
const keyOf = (tab: Tab) => (tab === "roots" ? ROOTS_KEY : EXTRA_KEY);

type Api = typeof chrome;

export interface StoredRoot {
  // The certificate, base64 DER.
  der: string;
  enabled: boolean;
}

export interface RootStore {
  enabled: boolean;
  certificates: StoredRoot[];
}

export function builtinStore(): RootStore {
  return { enabled: true, certificates: BUILTIN_ROOTS.map((der) => ({ der, enabled: true })) };
}

const emptyStore = (): RootStore => ({ enabled: true, certificates: [] });

function isStore(value: unknown): value is RootStore {
  const store = value as RootStore | undefined;
  return (
    typeof store?.enabled === "boolean" &&
    Array.isArray(store.certificates) &&
    store.certificates.every((item) => typeof item?.der === "string" && typeof item.enabled === "boolean")
  );
}

export interface Stores {
  roots: RootStore;
  extra: RootStore;
}

// Both stores from what is saved, and whether that needs saving: the first time the built-in roots and an empty
// second store; certificates added from files before the second store existed (0.5.4 to 1.0.0 kept them with the
// built-in roots) move to it, enabled or not as they were.
function settle(roots: unknown, extra: unknown): Stores & { changed: boolean } {
  let rootsStore = isStore(roots) ? roots : builtinStore();
  let extraStore = isStore(extra) ? extra : emptyStore();
  const moved = rootsStore.certificates.filter((root) => !isBuiltin(thumbprintOf(root)));
  if (moved.length) {
    const known = new Set(extraStore.certificates.map(thumbprintOf));
    rootsStore = { ...rootsStore, certificates: rootsStore.certificates.filter((root) => isBuiltin(thumbprintOf(root))) };
    extraStore = { ...extraStore, certificates: [...extraStore.certificates, ...moved.filter((root) => !known.has(thumbprintOf(root)))] };
  }
  return { roots: rootsStore, extra: extraStore, changed: !isStore(roots) || !isStore(extra) || moved.length > 0 };
}

async function saved(api: Api): Promise<{ roots: unknown; extra: unknown }> {
  const items = await api.storage.local.get([ROOTS_KEY, EXTRA_KEY]);
  return { roots: items[ROOTS_KEY], extra: items[EXTRA_KEY] };
}

// Both stores as saved, settled and saved again when that changed them.
export async function certificateStores(api: Api = chrome): Promise<Stores> {
  const { roots, extra } = await saved(api);
  const { changed, ...stores } = settle(roots, extra);
  if (changed) await api.storage.local.set({ [ROOTS_KEY]: stores.roots, [EXTRA_KEY]: stores.extra });
  return stores;
}

export async function rootStore(api: Api = chrome): Promise<RootStore> {
  return (await certificateStores(api)).roots;
}

export async function extraStore(api: Api = chrome): Promise<RootStore> {
  return (await certificateStores(api)).extra;
}

export function isSelfSigned(certificate: X509): boolean {
  const { subjectDer, issuerDer } = certificate;
  return subjectDer.length === issuerDer.length && subjectDer.every((byte, i) => byte === issuerDer[i]);
}

export interface Enabled {
  // Base64 DER: the "Root" store, then the "CA" one.
  roots: string[];
  intermediates: string[];
}

// What sites see: the enabled certificates of the enabled stores; a self-signed one added from a file is a root,
// any other an intermediate. Read only, so content scripts can call it.
export async function enabledCertificates(api: Api = chrome): Promise<Enabled> {
  const { roots, extra } = await saved(api);
  const stores = settle(roots, extra);
  const on = (store: RootStore) => (store.enabled ? store.certificates.filter((root) => root.enabled) : []);
  const result: Enabled = { roots: on(stores.roots).map((root) => root.der), intermediates: [] };
  for (const root of on(stores.extra)) (isSelfSigned(certificateOf(root)) ? result.roots : result.intermediates).push(root.der);
  return result;
}

async function update(tab: Tab, change: (store: RootStore) => RootStore, api: Api): Promise<RootStore> {
  const stores = await certificateStores(api);
  const store = change(stores[tab]);
  await api.storage.local.set({ [keyOf(tab)]: store });
  return store;
}

export function base64ToDer(base64: string): Uint8Array {
  return Uint8Array.from(atob(base64), (char) => char.charCodeAt(0));
}

export function certificateOf(root: StoredRoot): X509 {
  return parseCertificate(base64ToDer(root.der));
}

const thumbprintOf = (root: StoredRoot) => certificateOf(root).thumbprint;

let builtinThumbprints: Set<string> | undefined;

export function isBuiltin(thumbprint: string): boolean {
  builtinThumbprints ??= new Set(BUILTIN_ROOTS.map((der) => parseCertificate(base64ToDer(der)).thumbprint));
  return builtinThumbprints.has(thumbprint);
}

export function setStoreEnabled(tab: Tab, enabled: boolean, api: Api = chrome): Promise<RootStore> {
  return update(tab, (store) => ({ ...store, enabled }), api);
}

export function setCertificateEnabled(tab: Tab, thumbprint: string, enabled: boolean, api: Api = chrome): Promise<RootStore> {
  return update(
    tab,
    (store) => ({ ...store, certificates: store.certificates.map((root) => (thumbprintOf(root) === thumbprint ? { ...root, enabled } : root)) }),
    api,
  );
}

export function setAllEnabled(tab: Tab, enabled: boolean, api: Api = chrome): Promise<RootStore> {
  return update(tab, (store) => ({ ...store, certificates: store.certificates.map((root) => ({ ...root, enabled })) }), api);
}

export function removeCertificate(tab: Tab, thumbprint: string, api: Api = chrome): Promise<RootStore> {
  return update(tab, (store) => ({ ...store, certificates: store.certificates.filter((root) => thumbprintOf(root) !== thumbprint) }), api);
}

// The certificates in a file: DER, PEM with one or more certificates, or base64 without the PEM lines, as
// .cer files are sometimes saved. Throws when the file, or any certificate in it, is not X.509.
export function certificatesInFile(bytes: Uint8Array): Uint8Array[] {
  const notCertificate = new Error("файл не похож на сертификат X.509: нужен DER или PEM");
  let ders: Uint8Array[];
  try {
    if (bytes[0] === 0x30) {
      ders = [bytes];
    } else {
      const text = new TextDecoder("latin1").decode(bytes);
      const blocks = text.match(/-----BEGIN (?:X509 |TRUSTED )?CERTIFICATE-----[\s\S]*?-----END (?:X509 |TRUSTED )?CERTIFICATE-----/g);
      if (blocks) ders = blocks.map(pemToDer);
      else if (/^[\sA-Za-z0-9+/=]+$/.test(text) && text.trim()) ders = [pemToDer(text)];
      else throw notCertificate;
    }
    for (const der of ders) {
      // Bytes after the certificate mean this is some other file.
      if (read(der).der.length !== der.length) throw notCertificate;
      parseCertificate(der);
    }
  } catch {
    throw notCertificate;
  }
  return ders;
}

export interface Added {
  added: X509[];
  // Built-in roots removed earlier, back in the built-in roots' store.
  restored: X509[];
  // Already in a store, by SHA-1 thumbprint; not added again.
  present: X509[];
}

// Adds the certificates from a file, enabled, to the second store; a built-in root goes back to its own store.
// Throws, adding nothing, when the file is not a certificate.
export async function addCertificates(bytes: Uint8Array, api: Api = chrome): Promise<Added> {
  const certificates = certificatesInFile(bytes).map(parseCertificate);
  const result: Added = { added: [], restored: [], present: [] };
  const stores = await certificateStores(api);
  const known = new Set([...stores.roots.certificates, ...stores.extra.certificates].map(thumbprintOf));
  const roots = [...stores.roots.certificates];
  const extra = [...stores.extra.certificates];
  for (const certificate of certificates) {
    if (known.has(certificate.thumbprint)) {
      result.present.push(certificate);
      continue;
    }
    known.add(certificate.thumbprint);
    const stored = { der: derToBase64(certificate.der), enabled: true };
    if (isBuiltin(certificate.thumbprint)) {
      roots.push(stored);
      result.restored.push(certificate);
    } else {
      extra.push(stored);
      result.added.push(certificate);
    }
  }
  await api.storage.local.set({ [ROOTS_KEY]: { ...stores.roots, certificates: roots }, [EXTRA_KEY]: { ...stores.extra, certificates: extra } });
  return result;
}
