// The CKA_IDs of the tokens' keys, which the Gosuslugi plug-ins show as certificate ids and container names. The
// Rutoken Plugin gives them only after a login: getKeyByCertificate and enumerateKeys answer 19 without one, before
// touching the token (docs/JOURNAL.md, 2026-11-17). So page.js learns them at each login (token-login.ts) and keeps them
// in the extension's storage through the bridge (src/extension/roots-bridge.ts), for the lists asked without a PIN.
import type { Clock } from "./rutoken.ts";

export const KEY_IDS_REQUEST = "cryptopro-via-rutoken:key-ids-request";
export const KEY_IDS_RESPONSE = "cryptopro-via-rutoken:key-ids";
export const KEY_IDS_SAVE = "cryptopro-via-rutoken:key-ids-save";

// One token's: each certificate's key (by the certificate's thumbprint), and every key's id, as the Rutoken Plugin
// writes them (colon-separated hex).
export interface TokenKeyIds {
  certificates: Record<string, string>;
  keys: string[];
}

// By the token's serial number (the Rutoken Plugin's).
export type KeyIds = Record<string, TokenKeyIds>;

export interface KeyIdsRequest {
  type: typeof KEY_IDS_REQUEST;
  id: string;
}

export interface KeyIdsResponse {
  type: typeof KEY_IDS_RESPONSE;
  id: string;
  keyIds: KeyIds;
}

export interface KeyIdsSave {
  type: typeof KEY_IDS_SAVE;
  serial: string;
  keyIds: TokenKeyIds;
}

const WAIT_MS = 2000;
let requests = 0;

// What the extension keeps; nothing when the bridge does not answer.
export function loadKeyIds(win: Window, clock: Clock, waitMs = WAIT_MS): Promise<KeyIds> {
  const id = `key-ids-${clock.now()}-${++requests}`;
  return new Promise((resolve) => {
    let done = false;
    const finish = (keyIds: KeyIds) => {
      if (done) return;
      done = true;
      win.removeEventListener("message", listener);
      resolve(keyIds);
    };
    const listener = (event: MessageEvent) => {
      const data = event.data as Partial<KeyIdsResponse> | null;
      if (event.source !== win || data?.type !== KEY_IDS_RESPONSE || data.id !== id) return;
      finish(validKeyIds(data.keyIds));
    };
    win.addEventListener("message", listener);
    clock.setTimeout(() => finish({}), waitMs);
    win.postMessage({ type: KEY_IDS_REQUEST, id } satisfies KeyIdsRequest, "*");
  });
}

export function saveKeyIds(win: Window, serial: string, keyIds: TokenKeyIds): void {
  win.postMessage({ type: KEY_IDS_SAVE, serial, keyIds } satisfies KeyIdsSave, "*");
}

const HEX_ID = /^[0-9a-f]{2}(:[0-9a-f]{2})*$/;

// Only well-formed entries: the page can post to the bridge as well.
export function validTokenKeyIds(value: unknown): TokenKeyIds | undefined {
  const candidate = value as Partial<TokenKeyIds> | null;
  if (!candidate || typeof candidate !== "object" || !candidate.certificates || typeof candidate.certificates !== "object" || !Array.isArray(candidate.keys)) return undefined;
  const certificates = Object.fromEntries(Object.entries(candidate.certificates).filter(([thumbprint, keyId]) => /^[0-9A-F]{40}$/.test(thumbprint) && typeof keyId === "string" && HEX_ID.test(keyId)));
  return { certificates, keys: candidate.keys.filter((keyId): keyId is string => typeof keyId === "string" && HEX_ID.test(keyId)) };
}

export function validKeyIds(value: unknown): KeyIds {
  if (!value || typeof value !== "object") return {};
  const result: KeyIds = {};
  for (const [serial, ids] of Object.entries(value)) {
    const valid = validTokenKeyIds(ids);
    if (valid) result[serial] = valid;
  }
  return result;
}

// A key id's bytes.
export const keyIdBytes = (keyId: string) => Uint8Array.from(keyId.split(":"), (pair) => parseInt(pair, 16));

// The certificate id the Rutoken Plugin uses (its SHA-1, colon-separated) as a thumbprint.
export const thumbprintOfCertId = (certId: string) => certId.replace(/:/g, "").toUpperCase();
