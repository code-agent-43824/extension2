// The root certificates a site sees in the "Root" store: the enabled ones of the extension's root store,
// edited on the options page. page.js runs in the page's world, without chrome.storage, so it asks the
// extension's isolated-world script (src/extension/roots-bridge.ts) through postMessage. The certificates
// are public; a page that answers its own request only fools itself.
import type { Clock } from "./rutoken.ts";
import { parseCertificate, type X509 } from "./x509.ts";

export const ROOTS_REQUEST = "cryptopro-via-rutoken:roots-request";
export const ROOTS_RESPONSE = "cryptopro-via-rutoken:roots";

export interface RootsRequest {
  type: typeof ROOTS_REQUEST;
  id: string;
}

export interface RootsResponse {
  type: typeof ROOTS_RESPONSE;
  id: string;
  // Base64 DER.
  certificates: string[];
}

// The bridge answers from chrome.storage at once; no answer means it is not there (an older build).
export const ROOTS_WAIT_MS = 2000;

let requests = 0;

export function rootCertificates(win: Window, clock: Clock, waitMs = ROOTS_WAIT_MS): Promise<X509[]> {
  const id = `${clock.now()}-${++requests}`;
  return new Promise((resolve) => {
    let done = false;
    const finish = (certificates: string[]) => {
      if (done) return;
      done = true;
      win.removeEventListener("message", listener);
      const parsed: X509[] = [];
      for (const der of certificates) {
        try {
          parsed.push(parseCertificate(Uint8Array.from(atob(der), (char) => char.charCodeAt(0))));
        } catch {
          // A certificate that does not parse is left out rather than hiding the others.
        }
      }
      resolve(parsed);
    };
    const listener = (event: MessageEvent) => {
      const data = event.data as Partial<RootsResponse> | null;
      if (event.source !== win || data?.type !== ROOTS_RESPONSE || data.id !== id || !Array.isArray(data.certificates)) return;
      finish(data.certificates.filter((der): der is string => typeof der === "string"));
    };
    win.addEventListener("message", listener);
    clock.setTimeout(() => finish([]), waitMs);
    win.postMessage({ type: ROOTS_REQUEST, id } satisfies RootsRequest, "*");
  });
}
