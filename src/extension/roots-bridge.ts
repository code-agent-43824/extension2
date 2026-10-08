// Runs on the enabled sites in the extension's isolated world, next to page.js: answers page.js's request
// for the certificate stores (src/page/roots.ts) with the enabled roots and intermediates and the extended
// validity and root offer switches, and passes its Store.Add (install.ts) and XAdES-T's timestamp requests
// (src/page/timestamps.ts, timestamps.ts) on to the service worker.
import { ADD_REQUEST, ADD_RESPONSE, ROOTS_REQUEST, ROOTS_RESPONSE, type AddRequest, type AddResponse, type RootsRequest, type RootsResponse } from "../page/roots.ts";
import { TSA_ACCESS_REQUEST, TSA_ACCESS_RESPONSE, TSA_REQUEST, TSA_RESPONSE, type TsaAccessRequest, type TsaAccessResponse, type TsaRequest, type TsaResponse } from "../page/timestamps.ts";
import { ADD_MESSAGE, type AddMessage, type AddResult } from "./install.ts";
import { enabledCertificates, extendedValidity, offerRoot } from "./roots.ts";
import { TSA_ACCESS_MESSAGE, TSA_FETCH_MESSAGE, type TsaAccessMessage, type TsaFetchMessage, type TsaResult } from "./timestamps.ts";

const E_FAIL = 0x80004005;

// The service worker's answer, or the error of reaching it.
function forward(message: object): Promise<TsaResult> {
  return chrome.runtime.sendMessage(message).then(
    (result: TsaResult | undefined) => result ?? {},
    (error: unknown): TsaResult => ({ error: { message: error instanceof Error ? error.message : String(error), code: E_FAIL } }),
  );
}

window.addEventListener("message", (event: MessageEvent) => {
  const data = event.data as Partial<RootsRequest | AddRequest | TsaAccessRequest | TsaRequest> | null;
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
  } else if (data.type === TSA_ACCESS_REQUEST) {
    const { url } = data as Partial<TsaAccessRequest>;
    void forward({ type: TSA_ACCESS_MESSAGE, url } satisfies Partial<TsaAccessMessage>).then((result) =>
      window.postMessage({ type: TSA_ACCESS_RESPONSE, id, error: result.error } satisfies TsaAccessResponse, "*"),
    );
  } else if (data.type === TSA_REQUEST) {
    const { url, request } = data as Partial<TsaRequest>;
    void forward({ type: TSA_FETCH_MESSAGE, url, request } satisfies Partial<TsaFetchMessage>).then((result) =>
      window.postMessage({ type: TSA_RESPONSE, id, response: result.response, error: result.error } satisfies TsaResponse, "*"),
    );
  }
});
