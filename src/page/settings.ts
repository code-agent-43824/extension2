// The extension's settings page.js needs besides the certificate stores, asked from the bridge (src/extension/roots-bridge.ts)
// like them: IFCPlugin's PIN switch (src/extension/sites.ts, IFC_PIN_WINDOW_KEY) and Kontur.Plugin's client id
// (KONTUR_CLIENT_ID_KEY), made once by the bridge.
import type { Clock } from "./rutoken.ts";

export const SETTINGS_REQUEST = "cryptopro-via-rutoken:settings-request";
export const SETTINGS_RESPONSE = "cryptopro-via-rutoken:settings";

export interface SettingsRequest {
  type: typeof SETTINGS_REQUEST;
  id: string;
}

export interface SettingsResponse {
  type: typeof SETTINGS_RESPONSE;
  id: string;
  // Ask IFCPlugin's PIN in the extension's window instead of using the site's.
  ifcPinWindow: boolean;
  konturClientId?: string;
}

export interface Settings {
  ifcPinWindow: boolean;
  // A UUID; one made for the page when the bridge does not answer.
  konturClientId: string;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const SETTINGS_WAIT_MS = 2000;
let requests = 0;

// The defaults when the bridge does not answer.
export function pageSettings(win: Window, clock: Clock, waitMs = SETTINGS_WAIT_MS): Promise<Settings> {
  const id = `settings-${clock.now()}-${++requests}`;
  return new Promise((resolve) => {
    let done = false;
    const finish = (settings: Settings) => {
      if (done) return;
      done = true;
      win.removeEventListener("message", listener);
      resolve(settings);
    };
    const listener = (event: MessageEvent) => {
      const data = event.data as Partial<SettingsResponse> | null;
      if (event.source !== win || data?.type !== SETTINGS_RESPONSE || data.id !== id) return;
      finish({ ifcPinWindow: data.ifcPinWindow === true, konturClientId: typeof data.konturClientId === "string" && UUID.test(data.konturClientId) ? data.konturClientId : crypto.randomUUID() });
    };
    win.addEventListener("message", listener);
    clock.setTimeout(() => finish({ ifcPinWindow: false, konturClientId: crypto.randomUUID() }), waitMs);
    win.postMessage({ type: SETTINGS_REQUEST, id } satisfies SettingsRequest, "*");
  });
}
