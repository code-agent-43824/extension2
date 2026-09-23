// The extension's own root certificate store, kept in chrome.storage.local and edited on the options page.
// It starts with the root certificates CryptoPro CSP installs (builtin-roots.ts). Nothing reads it yet: sites
// and the Rutoken Plugin do not see it (docs/PLAN.md of stage 5, action 12).
import { read } from "../page/asn1.ts";
import { derToBase64, parseCertificate, pemToDer, type X509 } from "../page/x509.ts";
import { BUILTIN_ROOTS } from "./builtin-roots.ts";

export const ROOTS_KEY = "roots";

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

function isStore(value: unknown): value is RootStore {
  const store = value as RootStore | undefined;
  return (
    typeof store?.enabled === "boolean" &&
    Array.isArray(store.certificates) &&
    store.certificates.every((item) => typeof item?.der === "string" && typeof item.enabled === "boolean")
  );
}

// The store as saved; the first time, the built-in one, which is saved then.
export async function rootStore(api: Api = chrome): Promise<RootStore> {
  const stored = (await api.storage.local.get(ROOTS_KEY))[ROOTS_KEY];
  if (isStore(stored)) return stored;
  const store = builtinStore();
  await api.storage.local.set({ [ROOTS_KEY]: store });
  return store;
}

async function update(change: (store: RootStore) => RootStore, api: Api): Promise<RootStore> {
  const store = change(await rootStore(api));
  await api.storage.local.set({ [ROOTS_KEY]: store });
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

export function setStoreEnabled(enabled: boolean, api: Api = chrome): Promise<RootStore> {
  return update((store) => ({ ...store, enabled }), api);
}

export function setRootEnabled(thumbprint: string, enabled: boolean, api: Api = chrome): Promise<RootStore> {
  return update(
    (store) => ({ ...store, certificates: store.certificates.map((root) => (thumbprintOf(root) === thumbprint ? { ...root, enabled } : root)) }),
    api,
  );
}

export function setAllRootsEnabled(enabled: boolean, api: Api = chrome): Promise<RootStore> {
  return update((store) => ({ ...store, certificates: store.certificates.map((root) => ({ ...root, enabled })) }), api);
}

export function removeRoot(thumbprint: string, api: Api = chrome): Promise<RootStore> {
  return update((store) => ({ ...store, certificates: store.certificates.filter((root) => thumbprintOf(root) !== thumbprint) }), api);
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
  // Already in the store, by SHA-1 thumbprint; not added again.
  present: X509[];
}

// Adds the certificates from a file, enabled. Throws, adding nothing, when the file is not a certificate.
export async function addRoots(bytes: Uint8Array, api: Api = chrome): Promise<Added> {
  const certificates = certificatesInFile(bytes).map(parseCertificate);
  const result: Added = { added: [], present: [] };
  await update((store) => {
    const known = new Set(store.certificates.map(thumbprintOf));
    const added: StoredRoot[] = [];
    for (const certificate of certificates) {
      if (known.has(certificate.thumbprint)) {
        result.present.push(certificate);
        continue;
      }
      known.add(certificate.thumbprint);
      result.added.push(certificate);
      added.push({ der: derToBase64(certificate.der), enabled: true });
    }
    return { ...store, certificates: [...store.certificates, ...added] };
  }, api);
  return result;
}
