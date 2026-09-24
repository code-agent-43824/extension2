// Runs on the enabled sites in the extension's isolated world, next to page.js: answers page.js's request
// for the certificate stores (src/page/roots.ts) with the enabled roots and intermediates.
import { ROOTS_REQUEST, ROOTS_RESPONSE, type RootsRequest, type RootsResponse } from "../page/roots.ts";
import { enabledCertificates } from "./roots.ts";

window.addEventListener("message", (event: MessageEvent) => {
  const data = event.data as Partial<RootsRequest> | null;
  if (event.source !== window || data?.type !== ROOTS_REQUEST || typeof data.id !== "string") return;
  const id = data.id;
  void enabledCertificates().then(({ roots, intermediates }) => {
    window.postMessage({ type: ROOTS_RESPONSE, id, certificates: roots, intermediates } satisfies RootsResponse, "*");
  });
});
