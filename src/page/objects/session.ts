import type { PinDialog, PinRequest } from "../pin-dialog.ts";
import type { RootOffer } from "../root-links.ts";
import type { AddStore, StoreCertificates } from "../roots.ts";
import type { RutokenPlugin } from "../rutoken.ts";
import type { X509 } from "../x509.ts";

// What emulated objects share: the loaded Rutoken Plugin and the page they serve.
export interface Session {
  plugin: RutokenPlugin;
  // The page's origin, shown in the PIN window.
  origin: string;
  pinDialog(request: PinRequest): PinDialog;
  // The certificates of the "Root" and "CA" stores (src/page/roots.ts).
  storeCertificates(): Promise<StoreCertificates>;
  // Store.Add into them, through the extension (src/page/roots.ts).
  addCertificate(store: AddStore, certificate: X509): Promise<void>;
  // Lets the page's link to this root install it (src/page/root-links.ts).
  offerRootByLink(offer: RootOffer): void;
  // XAdES-T: access to a timestamp service, which the user grants once per service in the extension's window, and the
  // service's answer to a TimeStampReq (src/page/timestamps.ts).
  timestampAccess(url: string): Promise<void>;
  timestamp(url: string, request: Uint8Array): Promise<Uint8Array>;
}
