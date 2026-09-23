// Access to the Rutoken Plugin through the object the "Адаптер Рутокен Плагин" extension puts on
// every page. The adapter's own page script runs at document_start like ours, in no fixed order,
// so we wait for its object instead of expecting it.

export const ADAPTER_KEY = "C3B7563B-BF85-45B7-88FC-7CFF1BD3C2DB";

// The part of the Rutoken Plugin API 4.12 the shim uses. Every member is asynchronous, constants
// included: plugin.CERT_CATEGORY_USER is a thenable, so it is awaited before use. Methods return
// thenables too, not Promises: no .catch() or .finally() on them.
export interface RutokenPlugin {
  readonly version: PromiseLike<string>;
  readonly CERT_CATEGORY_USER: PromiseLike<number>;
  readonly TOKEN_INFO_SERIAL: PromiseLike<number>;
  readonly DATA_FORMAT_BASE64: PromiseLike<number>;
  readonly PUBLIC_KEY_ALGORITHM_GOST3410_2012_256: PromiseLike<number>;
  readonly PUBLIC_KEY_ALGORITHM_GOST3410_2012_512: PromiseLike<number>;
  readonly HASH_TYPE_GOST3411_12_256: PromiseLike<number>;
  readonly HASH_TYPE_GOST3411_12_512: PromiseLike<number>;
  readonly KEY_SPEC_SIGN: PromiseLike<number>;
  readonly KEY_SPEC_SIGN_AND_EXCHANGE: PromiseLike<number>;
  enumerateDevices(): PromiseLike<number[]>;
  enumerateCertificates(deviceId: number, category: number): PromiseLike<string[]>;
  getCertificate(deviceId: number, certId: string): PromiseLike<string>;
  getDeviceInfo(deviceId: number, option: number): PromiseLike<unknown>;
  login(deviceId: number, pin: string): PromiseLike<void>;
  logout(deviceId: number): PromiseLike<void>;
  sign(deviceId: number, certId: string, data: string, dataFormat: number, options: SignOptions): PromiseLike<string>;
  // Returns the key id (hex). `reserved` must be undefined.
  generateKeyPair(deviceId: number, reserved: undefined, marker: string, options: KeyPairOptions): PromiseLike<string>;
  deleteKeyPair(deviceId: number, keyId: string): PromiseLike<void>;
  // Returns the request as PEM ("-----BEGIN CERTIFICATE REQUEST-----").
  createPkcs10(deviceId: number, keyId: string, subject: SubjectAttribute[], extensions: RequestExtensions, options: RequestOptions): PromiseLike<string>;
  // Takes PEM; returns the new certificate id.
  importCertificate(deviceId: number, certificate: string, category: number): PromiseLike<string>;
  getKeyByCertificate(deviceId: number, certId: string): PromiseLike<string>;
  deleteCertificate(deviceId: number, certId: string): PromiseLike<void>;
}

export interface KeyPairOptions {
  publicKeyAlgorithm: number;
  signatureSize: number;
  keySpec: number;
}

// `rdn` is a name from the plugin's list (commonName, organizationalUnitName, …) or a dotted OID;
// both were checked on the stand (docs/JOURNAL.md).
export interface SubjectAttribute {
  rdn: string;
  value: string;
}

export interface RequestExtensions {
  keyUsage?: string[];
  // Dotted OIDs.
  extKeyUsage?: string[];
}

export interface RequestOptions {
  hashAlgorithm: number;
}

export interface SignOptions {
  detached: boolean;
  addUserCertificate: boolean;
  addEssCert: boolean;
  addSignTime: boolean;
}

// Error codes the plugin rejects with (as the error message), from the Rutoken Plugin 4.12 documentation.
export const RutokenError = {
  PIN_LENGTH_INVALID: 16,
  PIN_INCORRECT: 17,
  PIN_LOCKED: 18,
  CERTIFICATE_EXISTS: 6,
  KEY_NOT_FOUND: 20,
  ALREADY_LOGGED_IN: 93,
} as const;

export function rutokenErrorCode(error: unknown): number | undefined {
  const code = Number((error as { message?: unknown } | null)?.message);
  return Number.isInteger(code) ? code : undefined;
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
