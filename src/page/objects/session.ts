import type { PinDialog, PinRequest } from "../pin-dialog.ts";
import type { RutokenPlugin } from "../rutoken.ts";
import type { X509 } from "../x509.ts";

// What emulated objects share: the loaded Rutoken Plugin and the page they serve.
export interface Session {
  plugin: RutokenPlugin;
  // The page's origin, shown in the PIN window.
  origin: string;
  pinDialog(request: PinRequest): PinDialog;
  // The certificates of the "Root" store (src/page/roots.ts).
  rootCertificates(): Promise<X509[]>;
}
