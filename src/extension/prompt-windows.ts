// A question the service worker asks the user in a window of the extension's own, which the page cannot see or click:
// the root certificate a site adds (confirm.html, install.ts) and access to a timestamp service (tsa-access.html,
// timestamps.ts). The window reads what to show by its id and sends the answer back; closing it is a no.
type Api = typeof chrome;

interface Pending<T> {
  details: T;
  windowId?: number;
  resolve: (yes: boolean) => void;
}

export class PromptWindows<T> {
  readonly #api: Api;
  readonly #page: string;
  readonly #size: { width: number; height: number };
  readonly #pending = new Map<string, Pending<T>>();

  constructor(page: string, size: { width: number; height: number }, api: Api = chrome) {
    this.#api = api;
    this.#page = page;
    this.#size = size;
  }

  ask(details: T): Promise<boolean> {
    const id = crypto.randomUUID();
    return new Promise((resolve) => {
      const request: Pending<T> = {
        details,
        resolve: (yes) => {
          this.#pending.delete(id);
          resolve(yes);
        },
      };
      this.#pending.set(id, request);
      this.#api.windows.create({ url: this.#api.runtime.getURL(`${this.#page}?id=${id}`), type: "popup", ...this.#size }).then(
        (window) => {
          request.windowId = window?.id;
        },
        () => request.resolve(false),
      );
    });
  }

  details(id: unknown): T | undefined {
    return this.#pending.get(String(id))?.details;
  }

  answer(id: unknown, yes: boolean): void {
    this.#pending.get(String(id))?.resolve(yes);
  }

  windowClosed(windowId: number): void {
    for (const request of [...this.#pending.values()]) if (request.windowId === windowId) request.resolve(false);
  }
}
