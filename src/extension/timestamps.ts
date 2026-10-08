// XAdES-T's timestamp requests from the enabled sites (docs/PLAN.md, action 26): page.js asks roots-bridge.ts, which
// asks the service worker, which runs this. The service worker reaches the service without CORS once Chrome has given
// the extension access to the service's address, an optional host permission; the user grants it in the extension's
// own window (tsa-access.html), whose button makes Chrome's own request, once per service. What goes to the service is
// a TimeStampReq: the hash of the signature and a nonce. Chrome lists the access under the extension's site access,
// where the user can take it back. Only an address the user said yes to as a timestamp service is posted to: access
// alone is not enough, since the enabled sites have it too, and a site must not read another one's answers through us.
import { PromptWindows } from "./prompt-windows.ts";
import { enabledSites, matchPattern, siteOf } from "./sites.ts";

export const TSA_ACCESS_MESSAGE = "cryptopro-via-rutoken:tsa-access-check";
export const TSA_FETCH_MESSAGE = "cryptopro-via-rutoken:tsa-fetch";
export const TSA_DETAILS = "cryptopro-via-rutoken:tsa-details";
export const TSA_ANSWER = "cryptopro-via-rutoken:tsa-answer";

const E_INVALIDARG = 0x80070057;
const E_ACCESSDENIED = 0x80070005;
const E_FAIL = 0x80004005;
// The user's no, as for a root certificate (install.ts).
const ERROR_CANCELLED = 0x800704c7;
// The origins of the services the user let the extension reach, in chrome.storage.local.
export const TSA_KEY = "tsaServices";
// A TimeStampReq is a few hundred bytes; an answer with the service's chain a few kilobytes.
const MAX_REQUEST = 4096;
const MAX_RESPONSE = 1 << 20;
export const TSA_TIMEOUT_MS = 60_000;

export interface TsaAccessMessage {
  type: typeof TSA_ACCESS_MESSAGE;
  url: string;
}

export interface TsaFetchMessage {
  type: typeof TSA_FETCH_MESSAGE;
  url: string;
  // Base64 of the TimeStampReq.
  request: string;
}

export interface TsaResult {
  // Base64 of the service's answer.
  response?: string;
  error?: { message: string; code: number };
}

// What the window shows.
export interface TsaAccessDetails {
  origin: string;
  url: string;
}

type Api = typeof chrome;
type Fetch = typeof fetch;

const failure = (message: string, code: number): TsaResult => ({ error: { message, code } });

interface Service {
  url: string;
  origin: string;
  // The origin's match pattern, as Chrome's permission takes it.
  pattern: string;
}

// An http: or https: address.
function serviceOf(url: unknown): Service | undefined {
  const origin = siteOf(typeof url === "string" ? url : undefined);
  return origin ? { url: String(url), origin, pattern: matchPattern(origin) } : undefined;
}

export async function tsaServices(api: Api = chrome): Promise<string[]> {
  const stored = (await api.storage.local.get(TSA_KEY))[TSA_KEY];
  return Array.isArray(stored) ? stored.filter((origin): origin is string => typeof origin === "string") : [];
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}

export class Timestamps {
  readonly #api: Api;
  readonly #fetch: Fetch;
  readonly #windows: PromptWindows<TsaAccessDetails>;

  constructor(api: Api = chrome, fetcher: Fetch = (input, init) => fetch(input, init)) {
    this.#api = api;
    this.#fetch = fetcher;
    this.#windows = new PromptWindows("tsa-access.html", { width: 520, height: 420 }, api);
  }

  async #site(url: string | undefined): Promise<string | undefined> {
    const origin = siteOf(url);
    return origin && (await enabledSites(this.#api)).includes(origin) ? origin : undefined;
  }

  // The user said yes to the service, and Chrome still gives access to it.
  async #allowed(service: Service): Promise<boolean> {
    return (await tsaServices(this.#api)).includes(service.origin) && (await this.#api.permissions.contains({ origins: [service.pattern] }));
  }

  // Access to the service for the page at `senderUrl`: at once when the extension has it, otherwise after the user's
  // yes in the window and Chrome's own question.
  async access(message: Partial<TsaAccessMessage>, senderUrl: string | undefined): Promise<TsaResult> {
    const origin = await this.#site(senderUrl);
    if (!origin) return failure("Сайт не включён в расширении.", E_ACCESSDENIED);
    const service = serviceOf(message.url);
    if (!service) return failure(`Неверный адрес службы штампов времени: ${String(message.url)}`, E_INVALIDARG);
    if (await this.#allowed(service)) return {};
    // The window asks Chrome for the permission itself: only a click in an extension page may.
    if (!(await this.#windows.ask({ origin, url: service.url })) || !(await this.#api.permissions.contains({ origins: [service.pattern] }))) {
      return failure("Пользователь не разрешил обращаться к службе штампов времени.", ERROR_CANCELLED);
    }
    const services = await tsaServices(this.#api);
    if (!services.includes(service.origin)) await this.#api.storage.local.set({ [TSA_KEY]: [...services, service.origin].sort() });
    return {};
  }

  // The service's answer to a TimeStampReq, posted as RFC 3161's HTTP transport says.
  async request(message: Partial<TsaFetchMessage>, senderUrl: string | undefined): Promise<TsaResult> {
    if (!(await this.#site(senderUrl))) return failure("Сайт не включён в расширении.", E_ACCESSDENIED);
    const service = serviceOf(message.url);
    let body: Uint8Array;
    try {
      body = Uint8Array.from(atob(String(message.request)), (char) => char.charCodeAt(0));
      if (!service || body.length === 0 || body.length > MAX_REQUEST) throw new Error();
    } catch {
      return failure("The parameter is incorrect.", E_INVALIDARG);
    }
    if (!(await this.#allowed(service))) return failure("Нет доступа к службе штампов времени.", E_ACCESSDENIED);
    let response: Response;
    try {
      response = await this.#fetch(service.url, {
        method: "POST",
        headers: { "Content-Type": "application/timestamp-query" },
        body: body as BodyInit,
        credentials: "omit",
        signal: AbortSignal.timeout(TSA_TIMEOUT_MS),
      });
    } catch (error) {
      return failure(`служба не ответила (${error instanceof Error ? error.message : String(error)})`, E_FAIL);
    }
    if (!response.ok) return failure(`служба ответила HTTP ${response.status}`, E_FAIL);
    const answer = new Uint8Array(await response.arrayBuffer());
    if (answer.length === 0 || answer.length > MAX_RESPONSE) return failure("ответ службы пустой или слишком большой", E_FAIL);
    return { response: toBase64(answer) };
  }

  details(id: unknown): TsaAccessDetails | undefined {
    return this.#windows.details(id);
  }

  answer(id: unknown, granted: boolean): void {
    this.#windows.answer(id, granted);
  }

  windowClosed(windowId: number): void {
    this.#windows.windowClosed(windowId);
  }
}
