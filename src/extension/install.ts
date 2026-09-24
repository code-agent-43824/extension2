// Store.Add from the enabled sites (docs/PLAN.md, action 20): page.js asks roots-bridge.ts, which asks the
// service worker, which runs this. A certificate that becomes a root, added to "Root" or self-signed, needs the
// user's yes in the extension's own window (confirm.html), which the page cannot see or click; CryptoPro's
// plug-in also waits for the user before adding to Root. An intermediate is added at once, as the plug-in adds
// to "CA" (docs/JOURNAL.md, 2026-09-24). Either lands on the options page's second tab, where the user can turn
// it off or remove it.
import type { AddStore } from "../page/roots.ts";
import { parseCertificate, type X509 } from "../page/x509.ts";
import { base64ToDer, certificatesInFile, installCertificate, isSelfSigned } from "./roots.ts";
import { enabledSites, siteOf } from "./sites.ts";

export const ADD_MESSAGE = "cryptopro-via-rutoken:add-certificate";
export const CONFIRM_DETAILS = "cryptopro-via-rutoken:confirm-details";
export const CONFIRM_ANSWER = "cryptopro-via-rutoken:confirm-answer";
// The window pings while open: the service worker holding the site's request would otherwise be stopped when idle.
export const CONFIRM_PING = "cryptopro-via-rutoken:confirm-ping";
export const CONFIRM_PING_MS = 20_000;

const E_INVALIDARG = 0x80070057;
const E_ACCESSDENIED = 0x80070005;
// What certfnsh.asp of CryptoPro's test CA expects when the user refuses; the plug-in's own answer could not be
// seen, its window needs a screen (docs/JOURNAL.md, 2026-09-24).
export const ERROR_CANCELLED = 0x800704c7;

export interface AddMessage {
  type: typeof ADD_MESSAGE;
  store: AddStore;
  // Base64 DER.
  certificate: string;
}

export interface AddResult {
  error?: { message: string; code: number };
}

// What the window shows.
export interface ConfirmDetails {
  origin: string;
  store: AddStore;
  certificate: string;
}

type Api = typeof chrome;

const failure = (message: string, code: number): AddResult => ({ error: { message, code } });

export function needsConfirmation(store: AddStore, certificate: X509): boolean {
  return store === "root" || isSelfSigned(certificate);
}

export class Installer {
  readonly #api: Api;
  readonly #pending = new Map<string, { details: ConfirmDetails; windowId?: number; resolve: (install: boolean) => void }>();

  constructor(api: Api = chrome) {
    this.#api = api;
  }

  // A request from the content script of the page at `url`.
  async add(message: Partial<AddMessage>, url: string | undefined): Promise<AddResult> {
    const origin = siteOf(url);
    if (!origin || !(await enabledSites(this.#api)).includes(origin)) return failure("Сайт не включён в расширении.", E_ACCESSDENIED);
    const { store, certificate } = message;
    let der: Uint8Array;
    try {
      if (store !== "root" && store !== "ca") throw new Error();
      const ders = certificatesInFile(base64ToDer(String(certificate)));
      if (ders.length !== 1) throw new Error();
      der = ders[0]!;
    } catch {
      return failure("The parameter is incorrect.", E_INVALIDARG);
    }
    if (needsConfirmation(store, parseCertificate(der)) && !(await this.#confirm({ origin, store, certificate: String(certificate) }))) {
      return failure("Пользователь не разрешил добавить сертификат.", ERROR_CANCELLED);
    }
    await installCertificate(der, this.#api);
    return {};
  }

  #confirm(details: ConfirmDetails): Promise<boolean> {
    const id = crypto.randomUUID();
    return new Promise((resolve) => {
      const request: { details: ConfirmDetails; windowId?: number; resolve: (install: boolean) => void } = {
        details,
        resolve: (install) => {
          this.#pending.delete(id);
          resolve(install);
        },
      };
      this.#pending.set(id, request);
      this.#api.windows.create({ url: this.#api.runtime.getURL(`confirm.html?id=${id}`), type: "popup", width: 520, height: 600 }).then(
        (window) => {
          request.windowId = window?.id;
        },
        () => request.resolve(false),
      );
    });
  }

  details(id: unknown): ConfirmDetails | undefined {
    return this.#pending.get(String(id))?.details;
  }

  answer(id: unknown, install: boolean): void {
    this.#pending.get(String(id))?.resolve(install);
  }

  // A window closed without an answer is a no.
  windowClosed(windowId: number): void {
    for (const request of [...this.#pending.values()]) if (request.windowId === windowId) request.resolve(false);
  }
}
