// Access to the Rutoken Plugin through the object the "Адаптер Рутокен Плагин" extension puts on
// every page. The adapter's own page script runs at document_start like ours, in no fixed order,
// so we wait for its object instead of expecting it.

export const ADAPTER_KEY = "C3B7563B-BF85-45B7-88FC-7CFF1BD3C2DB";

// The part of the Rutoken Plugin API 4.12 the shim uses. Every member is asynchronous, constants
// included: plugin.CERT_CATEGORY_USER is a thenable, so it is awaited before use.
export interface RutokenPlugin {
  readonly version: PromiseLike<string>;
  readonly CERT_CATEGORY_USER: PromiseLike<number>;
  readonly TOKEN_INFO_SERIAL: PromiseLike<number>;
  enumerateDevices(): Promise<number[]>;
  enumerateCertificates(deviceId: number, category: number): Promise<string[]>;
  getCertificate(deviceId: number, certId: string): Promise<string>;
  getDeviceInfo(deviceId: number, option: number): Promise<unknown>;
}

interface Adapter {
  initialize?: () => Promise<void>;
  initializePromise?: unknown;
  isPluginInstalled?: () => Promise<boolean>;
  loadPlugin?: () => Promise<RutokenPlugin>;
}

export interface Clock {
  setTimeout(callback: () => void, ms: number): unknown;
  now(): number;
}

export class RutokenUnavailable extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RutokenUnavailable";
  }
}

const POLL_MS = 50;

async function waitFor<T>(probe: () => T | undefined, deadline: number, clock: Clock, what: string): Promise<T> {
  for (;;) {
    const value = probe();
    if (value !== undefined) return value;
    if (clock.now() >= deadline) throw new RutokenUnavailable(what);
    await new Promise<void>((resolve) => clock.setTimeout(resolve, POLL_MS));
  }
}

// Loads the Rutoken Plugin. `adapterWaitMs` bounds how long we wait for the adapter to appear
// and to finish initialising; the plugin load itself is bounded by the caller's timeout.
export async function loadRutokenPlugin(
  win: Record<string, unknown>,
  adapterWaitMs: number,
  clock: Clock,
): Promise<RutokenPlugin> {
  const deadline = clock.now() + adapterWaitMs;
  const adapter = await waitFor(
    () => win[ADAPTER_KEY] as Adapter | undefined,
    deadline,
    clock,
    "расширение «Адаптер Рутокен Плагин» не найдено на странице",
  );
  // initialize() may be called only once per page; if the site already called it, wait for it to finish.
  if (typeof adapter.loadPlugin !== "function" && adapter.initialize && adapter.initializePromise === undefined) {
    await adapter.initialize();
  }
  const ready = await waitFor(
    () => (typeof adapter.loadPlugin === "function" ? adapter : undefined),
    deadline,
    clock,
    "Адаптер Рутокен Плагин не завершил инициализацию",
  );
  if (!(await ready.isPluginInstalled?.())) throw new RutokenUnavailable("Рутокен Плагин не установлен");
  return ready.loadPlugin!();
}
