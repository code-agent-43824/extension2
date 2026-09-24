// window.cadesplugin as cadesplugin_api.js 2.4.5 builds it for Chrome: a Promise that settles when
// the plug-in is ready, carrying the constants and helper functions sites call. Behind it is the
// Rutoken Plugin instead of CryptoPro's native messaging host.
import { JS_MODULE_VERSION } from "./compat.ts";
import { constants } from "./constants.ts";
import { getLastError } from "./errors.ts";
import { createObject } from "./objects/index.ts";
import type { Session } from "./objects/session.ts";
import { openPinDialog } from "./pin-dialog.ts";
import { offerRootByLink } from "./root-links.ts";
import { addCertificate, storeCertificates } from "./roots.ts";
import { loadRutokenPlugin, type Clock } from "./rutoken.ts";
import { asyncSpawn } from "./spawn.ts";

// Texts and timeout from cadesplugin_api.js 2.4.5; sites show the texts to users as they are.
export const PLUGIN_UNAVAILABLE = "Плагин недоступен";
export const LOAD_TIMEOUT = "Истекло время ожидания загрузки плагина";
const DEFAULT_LOAD_TIMEOUT_MS = 20000;

// The adapter's page script is injected at document_start, so by DOMContentLoaded it is either there
// or about to be. Waiting the full load timeout for an adapter that is not installed would only delay
// the "unavailable" answer.
export const ADAPTER_WAIT_MS = 3000;

const EXTENSION_VERSION_REQUEST = "cadesplugin_extension_version_request";
const EXTENSION_VERSION_RESPONSE = "cadesplugin_extension_version_response:";
const EXTENSION_ID_REQUEST = "cadesplugin_extension_id_request";
const EXTENSION_ID_RESPONSE = "cadesplugin_extension_id_response:";

type PageWindow = Window & Record<string, unknown>;
type Callback = (() => void) | undefined;

export type Cadesplugin = Promise<void> & Record<string, unknown>;

export function createCadesplugin(win: PageWindow, clock: Clock): Cadesplugin {
  let settled = false;
  let resolvePlugin!: () => void;
  let rejectPlugin!: (reason: string) => void;
  const cadesplugin = new Promise<void>((resolve, reject) => {
    resolvePlugin = resolve;
    rejectPlugin = reject;
  }) as Cadesplugin;
  // Mark the promise as handled: a site that never calls .then() must not get an unhandled-rejection report.
  cadesplugin.catch(() => {});

  let resolveSession!: (session: Session) => void;
  let rejectSession!: (reason: Error) => void;
  const session = new Promise<Session>((resolve, reject) => {
    resolveSession = resolve;
    rejectSession = reject;
  });
  session.catch(() => {});

  function log(level: number, message: string): void {
    if (level > (cadesplugin.current_log_level as number)) return;
    if (level === constants.LOG_LEVEL_ERROR) console.error(`ERROR: ${message}`);
    else if (level === constants.LOG_LEVEL_INFO) console.info(`INFO: ${message}`);
    else console.log(`DEBUG: ${message}`);
  }

  function fail(reason: string, cause: string, callback?: Callback): void {
    if (settled) return;
    settled = true;
    log(constants.LOG_LEVEL_ERROR, `Рутокен вместо КриптоПро: ${cause}`);
    callback?.();
    rejectSession(new Error(reason));
    rejectPlugin(reason);
  }

  function start(): void {
    (win.cadesplugin_extension_loaded_callback as Callback)?.();
    const timeout = Number(win.cadesplugin_load_timeout) || DEFAULT_LOAD_TIMEOUT_MS;
    clock.setTimeout(
      () => fail(LOAD_TIMEOUT, "истекло время ожидания", win.cadesplugin_timeout_failed_callback as Callback),
      timeout,
    );
    loadRutokenPlugin(win, ADAPTER_WAIT_MS, clock).then(
      (plugin) => {
        if (settled) return;
        settled = true;
        resolveSession({
          plugin,
          origin: win.location?.origin ?? "",
          pinDialog: (request) => openPinDialog(win.document, request),
          storeCertificates: () => storeCertificates(win, clock),
          addCertificate: (store, certificate) => addCertificate(win, clock, store, certificate),
          offerRootByLink(offer) {
            offerRootByLink(win, offer, this.addCertificate);
          },
        });
        (win.cadesplugin_plugin_loaded_callback as Callback)?.();
        resolvePlugin();
      },
      (error: unknown) => fail(PLUGIN_UNAVAILABLE, error instanceof Error ? error.message : String(error)),
    );
  }

  function answer(prefix: string, callback: (value: string) => void): (event: MessageEvent) => void {
    return (event) => {
      if (typeof event.data === "string" && event.data.startsWith(prefix)) callback(event.data.slice(prefix.length));
    };
  }

  Object.assign(cadesplugin, constants, {
    JSModuleVersion: JS_MODULE_VERSION,
    current_log_level: constants.LOG_LEVEL_ERROR,
    async_spawn: asyncSpawn,
    getLastError,
    set: () => {},
    is_capilite_enabled: () => typeof cadesplugin.EnableInternalCSP !== "undefined" && !!cadesplugin.EnableInternalCSP,
    set_log_level(level: unknown) {
      const valid = [constants.LOG_LEVEL_DEBUG, constants.LOG_LEVEL_INFO, constants.LOG_LEVEL_ERROR];
      if (!valid.includes(level as never)) {
        log(constants.LOG_LEVEL_ERROR, `cadesplugin_api.js: Incorrect log_level: ${String(level)}`);
        return;
      }
      cadesplugin.current_log_level = level;
    },
    // The request/response pair goes through postMessage, as with CryptoPro's extension: sites
    // may listen for the responses themselves.
    get_extension_version(callback: (version: string) => void) {
      win.postMessage(EXTENSION_VERSION_REQUEST, "*");
      win.addEventListener("message", answer(EXTENSION_VERSION_RESPONSE, callback), false);
    },
    get_extension_id(callback: (id: string) => void) {
      win.postMessage(EXTENSION_ID_REQUEST, "*");
      win.addEventListener("message", answer(EXTENSION_ID_RESPONSE, callback), false);
    },
    async CreateObjectAsync(name: string) {
      return createObject(name, await session);
    },
    ReleasePluginObjects: () => Promise.resolve(),
  });

  win.addEventListener("message", (event: MessageEvent) => {
    if (event.source !== win) return;
    if (event.data === EXTENSION_VERSION_REQUEST) win.postMessage(EXTENSION_VERSION_RESPONSE + __EXTENSION_VERSION__, "*");
    // Our id is not visible from the page world, and claiming CryptoPro's would mislead the site.
    else if (event.data === EXTENSION_ID_REQUEST) win.postMessage(EXTENSION_ID_RESPONSE, "*");
  });

  // Sites define their callbacks before including cadesplugin_api.js, and it calls them
  // asynchronously; starting after the document is parsed gives the same order.
  if (win.document.readyState === "loading") {
    win.document.addEventListener("DOMContentLoaded", start, { once: true });
  } else {
    clock.setTimeout(start, 0);
  }
  return cadesplugin;
}
