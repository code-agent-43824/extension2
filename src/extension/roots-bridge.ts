// Runs on the enabled sites in the extension's isolated world, next to page.js: answers page.js's request
// for the certificate stores (src/page/roots.ts) with the enabled roots and intermediates and the extended
// validity and root offer switches, and for the other settings (src/page/settings.ts), keeps the keys' ids page.js
// learns at its logins (src/page/key-ids.ts) and gives them back, and passes its Store.Add
// (install.ts) and XAdES-T's timestamp requests (src/page/timestamps.ts, timestamps.ts) on to the service worker.
import { ADD_REQUEST, ADD_RESPONSE, ROOTS_REQUEST, ROOTS_RESPONSE, type AddRequest, type AddResponse, type RootsRequest, type RootsResponse } from "../page/roots.ts";
import { TSA_ACCESS_REQUEST, TSA_ACCESS_RESPONSE, TSA_REQUEST, TSA_RESPONSE, type TsaAccessRequest, type TsaAccessResponse, type TsaRequest, type TsaResponse } from "../page/timestamps.ts";
import { ADD_MESSAGE, type AddMessage, type AddResult } from "./install.ts";
import { enabledCertificates, extendedValidity, offerRoot } from "./roots.ts";
import { TSA_ACCESS_MESSAGE, TSA_FETCH_MESSAGE, type TsaAccessMessage, type TsaFetchMessage, type TsaResult } from "./timestamps.ts";
import { SETTINGS_REQUEST, SETTINGS_RESPONSE, type SettingsRequest, type SettingsResponse } from "../page/settings.ts";
import { IDENTITY_REQUEST, IDENTITY_RESPONSE, type IdentityRequest, type IdentityResponse } from "../page/identity.ts";
import { IDENTITY_MESSAGE } from "./identity.ts";
import { KEY_IDS_REQUEST, KEY_IDS_RESPONSE, KEY_IDS_SAVE, validKeyIds, validTokenKeyIds, type KeyIdsRequest, type KeyIdsResponse, type KeyIdsSave } from "../page/key-ids.ts";
import { BRIDGE_MARKER, ifcPinWindow } from "./sites.ts";

const E_FAIL = 0x80004005;

// For the service worker's check after the browser starts (sites.ts, reloadTabsWithoutScript).
(globalThis as Record<string, unknown>)[BRIDGE_MARKER] = true;

// The service worker's answer, or the error of reaching it.
function forward(message: object): Promise<TsaResult> {
  return chrome.runtime.sendMessage(message).then(
    (result: TsaResult | undefined) => result ?? {},
    (error: unknown): TsaResult => ({ error: { message: error instanceof Error ? error.message : String(error), code: E_FAIL } }),
  );
}

// The keys' ids, by token serial (src/page/key-ids.ts).
const KEY_IDS_KEY = "keyIds";

window.addEventListener("message", (event: MessageEvent) => {
  const save = event.data as Partial<KeyIdsSave> | null;
  if (event.source === window && save?.type === KEY_IDS_SAVE && typeof save.serial === "string") {
    const ids = validTokenKeyIds(save.keyIds);
    if (ids) {
      const serial = save.serial;
      void chrome.storage.local.get(KEY_IDS_KEY).then((stored) => chrome.storage.local.set({ [KEY_IDS_KEY]: { ...validKeyIds(stored[KEY_IDS_KEY]), [serial]: ids } }));
    }
    return;
  }
  const data = event.data as Partial<RootsRequest | AddRequest | TsaAccessRequest | TsaRequest | SettingsRequest | KeyIdsRequest | IdentityRequest> | null;
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
  } else if (data.type === KEY_IDS_REQUEST) {
    void chrome.storage.local.get(KEY_IDS_KEY).then((stored) =>
      window.postMessage({ type: KEY_IDS_RESPONSE, id, keyIds: validKeyIds(stored[KEY_IDS_KEY]) } satisfies KeyIdsResponse, "*"),
    );
  } else if (data.type === SETTINGS_REQUEST) {
    void ifcPinWindow().then((asked) => window.postMessage({ type: SETTINGS_RESPONSE, id, ifcPinWindow: asked } satisfies SettingsResponse, "*"));
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
