// Runs on the enabled sites in the extension's isolated world, next to page.js: answers page.js's request
// for the certificate stores (src/page/roots.ts) with the enabled roots and intermediates and the extended
// validity and root offer switches, and passes its Store.Add on to the service worker (install.ts).
import { ADD_REQUEST, ADD_RESPONSE, ROOTS_REQUEST, ROOTS_RESPONSE, type AddRequest, type AddResponse, type RootsRequest, type RootsResponse } from "../page/roots.ts";
import { ADD_MESSAGE, type AddMessage, type AddResult } from "./install.ts";
import { enabledCertificates, extendedValidity, offerRoot } from "./roots.ts";

const E_FAIL = 0x80004005;

window.addEventListener("message", (event: MessageEvent) => {
  const data = event.data as Partial<RootsRequest | AddRequest> | null;
  if (event.source !== window || typeof data?.id !== "string") return;
  const id = data.id;
  if (data.type === ROOTS_REQUEST) {
    void Promise.all([enabledCertificates(), extendedValidity(), offerRoot()]).then(([{ roots, intermediates }, extended, offer]) => {
      const response: RootsResponse = { type: ROOTS_RESPONSE, id, certificates: roots, intermediates, extendedValidity: extended, offerRoot: offer };
      window.postMessage(response, "*");
    });
  } else if (data.type === ADD_REQUEST) {
    const { store, certificate } = data as Partial<AddRequest>;
    const answer = (result: AddResult) => window.postMessage({ type: ADD_RESPONSE, id, error: result?.error } satisfies AddResponse, "*");
    chrome.runtime.sendMessage({ type: ADD_MESSAGE, store, certificate } as AddMessage).then(
      (result: AddResult) => answer(result ?? {}),
      (error: unknown) => answer({ error: { message: error instanceof Error ? error.message : String(error), code: E_FAIL } }),
    );
  }
});
