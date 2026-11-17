// The extension's settings page.js needs besides the certificate stores, asked from the bridge (src/extension/roots-bridge.ts)
// like them: IFCPlugin's PIN switch (src/extension/sites.ts, IFC_PIN_WINDOW_KEY).
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
}

export interface Settings {
  ifcPinWindow: boolean;
}

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
      finish({ ifcPinWindow: data.ifcPinWindow === true });
    };
    win.addEventListener("message", listener);
    clock.setTimeout(() => finish({ ifcPinWindow: false }), waitMs);
    win.postMessage({ type: SETTINGS_REQUEST, id } satisfies SettingsRequest, "*");
  });
}
