// The Rutoken Plugin and what goes with it on a page, loaded once and shared by every plug-in page.js plays there
// (CryptoPro's, IFCPlugin, Gosplugin): one plugin, one queue of logins, one memory of PINs (token-login.ts).
import { showCertificateDialog } from "./certificate-dialog.ts";
import type { Session } from "./objects/session.ts";
import { openPinDialog } from "./pin-dialog.ts";
import { offerRootByLink } from "./root-links.ts";
import { addCertificate, storeCertificates } from "./roots.ts";
import { loadRutokenPlugin, type Clock } from "./rutoken.ts";
import { timestampAccess, timestampResponse } from "./timestamps.ts";

// The adapter's page script is injected at document_start, so by DOMContentLoaded it is either there
// or about to be. Waiting the full load timeout for an adapter that is not installed would only delay
// the "unavailable" answer.
export const ADAPTER_WAIT_MS = 3000;

const sessions = new WeakMap<object, Promise<Session>>();

export function pageSession(win: Window & Record<string, unknown>, clock: Clock): Promise<Session> {
  let session = sessions.get(win);
  if (!session) {
    session = loadRutokenPlugin(win, ADAPTER_WAIT_MS, clock).then((plugin): Session => ({
      plugin,
      origin: win.location?.origin ?? "",
      pinDialog: (request, remember) => openPinDialog(win.document, request, remember),
      showCertificate: (fields) => showCertificateDialog(win.document, fields),
      storeCertificates: () => storeCertificates(win, clock),
      addCertificate: (store, certificate) => addCertificate(win, clock, store, certificate),
      offerRootByLink(offer) {
        offerRootByLink(win, offer, this.addCertificate);
      },
      timestampAccess: (url) => timestampAccess(win, clock, url),
      timestamp: (url, request) => timestampResponse(win, clock, url, request),
    }));
    sessions.set(win, session);
  }
  return session;
}
