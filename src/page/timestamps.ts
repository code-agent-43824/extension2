// The timestamp service of XAdES-T, reached through the extension (docs/PLAN.md, action 26). The Rutoken Plugin calls
// a service only inside a CMS signature, and page.js cannot call one itself: services send no CORS headers, and an
// https: page cannot reach an http: address. So page.js asks the extension's isolated-world script
// (src/extension/roots-bridge.ts), which asks the service worker (src/extension/timestamps.ts): first for access to the
// service's address, which the user grants once per service in the extension's own window, then for the service's
// answer to a request. A page that answers its own request only fools itself: the answer is checked like any other.
import { CadesError } from "./errors.ts";
import type { Clock } from "./rutoken.ts";

export const TSA_ACCESS_REQUEST = "cryptopro-via-rutoken:tsa-access-request";
export const TSA_ACCESS_RESPONSE = "cryptopro-via-rutoken:tsa-access";
export const TSA_REQUEST = "cryptopro-via-rutoken:tsa-request";
export const TSA_RESPONSE = "cryptopro-via-rutoken:tsa-response";

export interface TsaError {
  message: string;
  code: number;
}

export interface TsaAccessRequest {
  type: typeof TSA_ACCESS_REQUEST;
  id: string;
  url: string;
}

export interface TsaAccessResponse {
  type: typeof TSA_ACCESS_RESPONSE;
  id: string;
  // Absent when the extension may reach the service.
  error?: TsaError;
}

export interface TsaRequest {
  type: typeof TSA_REQUEST;
  id: string;
  url: string;
  // Base64 of the TimeStampReq.
  request: string;
}

export interface TsaResponse {
  type: typeof TSA_RESPONSE;
  id: string;
  // Base64 of the service's answer, or the error.
  response?: string;
  error?: TsaError;
}

let requests = 0;

// No timeout: access waits for the user's answer in the extension's window, and the service worker bounds the request.
function ask<T extends { type: string; id: string; error?: TsaError }>(win: Window, clock: Clock, message: { type: string; url: string; request?: string }, responseType: string): Promise<T> {
  const id = `${clock.now()}-tsa-${++requests}`;
  return new Promise((resolve, reject) => {
    const listener = (event: MessageEvent) => {
      const data = event.data as Partial<T> | null;
      if (event.source !== win || data?.type !== responseType || data.id !== id) return;
      win.removeEventListener("message", listener);
      if (data.error) reject(new CadesError(String(data.error.message), Number(data.error.code)));
      else resolve(data as T);
    };
    win.addEventListener("message", listener);
    win.postMessage({ ...message, id }, "*");
  });
}

// Resolves once the extension may reach the service at `url`; rejects when the user refuses.
export async function timestampAccess(win: Window, clock: Clock, url: string): Promise<void> {
  await ask<TsaAccessResponse>(win, clock, { type: TSA_ACCESS_REQUEST, url } satisfies Omit<TsaAccessRequest, "id">, TSA_ACCESS_RESPONSE);
}

// The service's answer to a TimeStampReq, as it came.
export async function timestampResponse(win: Window, clock: Clock, url: string, request: Uint8Array): Promise<Uint8Array> {
  const message = { type: TSA_REQUEST, url, request: btoa(String.fromCharCode(...request)) } satisfies Omit<TsaRequest, "id">;
  const answer = await ask<TsaResponse>(win, clock, message, TSA_RESPONSE);
  return Uint8Array.from(atob(answer.response ?? ""), (char) => char.charCodeAt(0));
}
