// Runs on the enabled sites in the extension's isolated world, next to page.js: answers page.js's request
// for the root certificates (src/page/roots.ts) with the enabled ones of the root store.
import { ROOTS_REQUEST, ROOTS_RESPONSE, type RootsRequest, type RootsResponse } from "../page/roots.ts";
import { enabledRoots } from "./roots.ts";

window.addEventListener("message", (event: MessageEvent) => {
  const data = event.data as Partial<RootsRequest> | null;
  if (event.source !== window || data?.type !== ROOTS_REQUEST || typeof data.id !== "string") return;
  const id = data.id;
  void enabledRoots().then((certificates) => {
    window.postMessage({ type: ROOTS_RESPONSE, id, certificates } satisfies RootsResponse, "*");
  });
});
