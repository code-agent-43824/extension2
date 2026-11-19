// Runs on the enabled sites in the extension's isolated world, next to page.js: answers page.js's request
// for the certificate stores (src/page/roots.ts) with the enabled roots and intermediates and the extended
// validity and root offer switches, and for the other settings (src/page/settings.ts) and Gosplugin's made-up identity
// (src/page/identity.ts), and passes its Store.Add
// (install.ts) and XAdES-T's timestamp requests (src/page/timestamps.ts, timestamps.ts) on to the service worker.
import { ADD_REQUEST, ADD_RESPONSE, ROOTS_REQUEST, ROOTS_RESPONSE, type AddRequest, type AddResponse, type RootsRequest, type RootsResponse } from "../page/roots.ts";
import { TSA_ACCESS_REQUEST, TSA_ACCESS_RESPONSE, TSA_REQUEST, TSA_RESPONSE, type TsaAccessRequest, type TsaAccessResponse, type TsaRequest, type TsaResponse } from "../page/timestamps.ts";
import { ADD_MESSAGE, type AddMessage, type AddResult } from "./install.ts";
import { enabledCertificates, extendedValidity, offerRoot } from "./roots.ts";
import { TSA_ACCESS_MESSAGE, TSA_FETCH_MESSAGE, type TsaAccessMessage, type TsaFetchMessage, type TsaResult } from "./timestamps.ts";
import { SETTINGS_REQUEST, SETTINGS_RESPONSE, type SettingsRequest, type SettingsResponse } from "../page/settings.ts";
import { IDENTITY_REQUEST, IDENTITY_RESPONSE, type IdentityRequest, type IdentityResponse } from "../page/identity.ts";
import { IDENTITY_MESSAGE } from "./identity.ts";
import { BRIDGE_MARKER, ifcPinWindow, KONTUR_CLIENT_ID_KEY } from "./sites.ts";

const E_FAIL = 0x80004005;

// Kontur.Plugin's client id: a UUID made the first time a site asks, then kept, as the real host keeps its own.
async function konturClientId(): Promise<string> {
  const stored = (await chrome.storage.local.get(KONTUR_CLIENT_ID_KEY))[KONTUR_CLIENT_ID_KEY];
  if (typeof stored === "string") return stored;
  const made = crypto.randomUUID();
  await chrome.storage.local.set({ [KONTUR_CLIENT_ID_KEY]: made });
  return made;
}

// For the service worker's check after the browser starts (sites.ts, reloadTabsWithoutScript).
(globalThis as Record<string, unknown>)[BRIDGE_MARKER] = true;

// The service worker's answer, or the error of reaching it.
function forward(message: object): Promise<TsaResult> {
  return chrome.runtime.sendMessage(message).then(
    (result: TsaResult | undefined) => result ?? {},
    (error: unknown): TsaResult => ({ error: { message: error instanceof Error ? error.message : String(error), code: E_FAIL } }),
  );
}

window.addEventListener("message", (event: MessageEvent) => {
  const data = event.data as Partial<RootsRequest | AddRequest | TsaAccessRequest | TsaRequest | SettingsRequest | IdentityRequest> | null;
  if (event.source !== window || typeof data?.id !== "string") return;
  const id = data.id;
  if (data.type === ROOTS_REQUEST) {
    void Promise.all([enabledCertificates(), extendedValidity(), offerRoot()]).then(([{ roots, intermediates }, extended, offer]) => {
      const response: RootsResponse = { type: ROOTS_RESPONSE, id, certificates: roots, intermediates, extendedValidity: extended, offerRoot: offer };
      window.postMessage(response, "*");
    });
  } else if (data.type === IDENTITY_REQUEST) {
    // The service worker keeps it, and asks the generator the first time (src/extension/identity.ts).
    const answer = (identity: unknown) => {
      const { user, computer, ip, mac } = (identity ?? {}) as Partial<IdentityResponse["identity"] & object>;
      window.postMessage({ type: IDENTITY_RESPONSE, id, ...(user ? { identity: { user, computer: computer!, ip: ip!, mac: mac! } } : {}) } satisfies IdentityResponse, "*");
    };
    chrome.runtime.sendMessage({ type: IDENTITY_MESSAGE }).then(answer, () => answer(undefined));
  } else if (data.type === SETTINGS_REQUEST) {
    void Promise.all([ifcPinWindow(), konturClientId()]).then(([asked, clientId]) =>
      window.postMessage({ type: SETTINGS_RESPONSE, id, ifcPinWindow: asked, konturClientId: clientId } satisfies SettingsResponse, "*"),
    );
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
