// The certificates a site sees in the "Root" and "CA" stores: the enabled roots and intermediates of the
// extension's certificate stores, edited on the options page, with the options page's switch for the extended
// validity check. page.js runs in the page's world, without chrome.storage, so it asks the extension's
// isolated-world script (src/extension/roots-bridge.ts) through postMessage. The certificates are public; a
// page that answers its own request only fools itself. Store.Add goes the same way; a root is added only after
// the user confirms it in the extension's own window, which the page cannot reach (src/extension/confirm.ts).
import type { Clock } from "./rutoken.ts";
import { CadesError } from "./errors.ts";
import { derToBase64, parseCertificate, type X509 } from "./x509.ts";

export const ROOTS_REQUEST = "cryptopro-via-rutoken:roots-request";
export const ROOTS_RESPONSE = "cryptopro-via-rutoken:roots";

export interface RootsRequest {
  type: typeof ROOTS_REQUEST;
  id: string;
}

export const ADD_REQUEST = "cryptopro-via-rutoken:add-request";
export const ADD_RESPONSE = "cryptopro-via-rutoken:added";

export interface RootsResponse {
  type: typeof ROOTS_RESPONSE;
  id: string;
  // Base64 DER: the roots, and the intermediate CAs (absent from builds before 1.1.0).
  certificates: string[];
  intermediates?: string[];
  // The extended validity check (1.2.0 on).
  extendedValidity?: boolean;
}

// The store a site adds to: CryptoPro's "Root" or "CA".
export type AddStore = "root" | "ca";

export interface AddRequest {
  type: typeof ADD_REQUEST;
  id: string;
  store: AddStore;
  // Base64 DER.
  certificate: string;
}

export interface AddResponse {
  type: typeof ADD_RESPONSE;
  id: string;
  // Absent when the certificate was added.
  error?: { message: string; code: number };
}

export interface StoreCertificates {
  roots: X509[];
  intermediates: X509[];
  extendedValidity: boolean;
}

// The bridge answers from chrome.storage at once; no answer means it is not there (an older build).
export const ROOTS_WAIT_MS = 2000;

let requests = 0;

function parsed(certificates: unknown[]): X509[] {
  const result: X509[] = [];
  for (const der of certificates) {
    if (typeof der !== "string") continue;
    try {
      result.push(parseCertificate(Uint8Array.from(atob(der), (char) => char.charCodeAt(0))));
    } catch {
      // A certificate that does not parse is left out rather than hiding the others.
    }
  }
  return result;
}

export function storeCertificates(win: Window, clock: Clock, waitMs = ROOTS_WAIT_MS): Promise<StoreCertificates> {
  const id = `${clock.now()}-${++requests}`;
  return new Promise((resolve) => {
    let done = false;
    const finish = (roots: unknown[], intermediates: unknown[], extendedValidity: boolean) => {
      if (done) return;
      done = true;
      win.removeEventListener("message", listener);
      resolve({ roots: parsed(roots), intermediates: parsed(intermediates), extendedValidity });
    };
    const listener = (event: MessageEvent) => {
      const data = event.data as Partial<RootsResponse> | null;
      if (event.source !== win || data?.type !== ROOTS_RESPONSE || data.id !== id || !Array.isArray(data.certificates)) return;
      finish(data.certificates, Array.isArray(data.intermediates) ? data.intermediates : [], data.extendedValidity === true);
    };
    win.addEventListener("message", listener);
    clock.setTimeout(() => finish([], [], false), waitMs);
    win.postMessage({ type: ROOTS_REQUEST, id } satisfies RootsRequest, "*");
  });
}

// Resolves once the extension has added the certificate, rejects with the extension's error otherwise. No
// timeout: adding a root waits for the user's answer in the extension's window.
export function addCertificate(win: Window, clock: Clock, store: AddStore, certificate: X509): Promise<void> {
  const id = `${clock.now()}-${++requests}`;
  return new Promise((resolve, reject) => {
    const listener = (event: MessageEvent) => {
      const data = event.data as Partial<AddResponse> | null;
      if (event.source !== win || data?.type !== ADD_RESPONSE || data.id !== id) return;
      win.removeEventListener("message", listener);
      if (data.error) reject(new CadesError(String(data.error.message), Number(data.error.code)));
      else resolve();
    };
    win.addEventListener("message", listener);
    win.postMessage({ type: ADD_REQUEST, id, store, certificate: derToBase64(certificate.der) } satisfies AddRequest, "*");
  });
}
