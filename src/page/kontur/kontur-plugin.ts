// Kontur.Plugin over the Rutoken Plugin (docs/PLAN.md, stage 9): the page side of the real extension 3.1.11 and the
// answers of its native host 4.15.1, as recorded on the stand (docs/JOURNAL.md, 2026-11-19). The page posts
// {type: "kontur-toolbox-request", request} and gets {type: "kontur-toolbox-response", response}; extension.info,
// extension.close and extension.uninstall are the extension's own, everything else the host's (commands.ts). No code
// of the plug-in is in this file.
import { pageSession } from "../page-session.ts";
import type { Clock } from "../rutoken.ts";
import { pageSettings } from "../settings.ts";
import { answerCommand, newKonturContext, sortKeys, type KonturContext } from "./commands.ts";
import { KonturError } from "./errors.ts";
import { pageDownload, pageFileDialogs } from "./file-dialog.ts";
import { pageIdentity } from "../identity.ts";

export const REQUEST_TYPE = "kontur-toolbox-request";
export const RESPONSE_TYPE = "kontur-toolbox-response";
// The <meta> attribute the extension puts on Kontur's own pages; the client waits longer for the plug-in when it is there.
export const INSTALLATION_FLAG = "kontur-toolbox-installed";
const KONTUR_HOSTS = [".kontur.ru", ".kontur-ca.ru", ".kontur-extern.ru", ".kontur", ".testkontur.ru"];

// What the real extension tells about itself: its Chrome Web Store id, or in Firefox its add-on id from the host's
// manifest; the version is the Chrome Web Store's (Firefox's was not seen).
export function extensionInfo(userAgent: string): { id: string; type: string; version: string } {
  const firefox = userAgent.toLowerCase().includes("firefox/");
  return { id: firefox ? "kontur.extension@kontur.ru" : "hnhppcgejeffnbnioloohhmndpmclaga", type: firefox ? "firefox" : "chrome", version: "3.1.11" };
}

export function isKonturHost(hostname: string): boolean {
  return KONTUR_HOSTS.some((suffix) => hostname.endsWith(suffix));
}

interface Request {
  sessionId?: unknown;
  commandId?: unknown;
  type?: unknown;
  extensionId?: unknown;
  [key: string]: unknown;
}

type Win = Window & Record<string, unknown>;

export function startKonturPlugin(win: Win, clock: Clock): void {
  const konturHost = isKonturHost(win.location.hostname);
  const info = extensionInfo(win.navigator.userAgent);
  const post = (response: Record<string, unknown>) => win.postMessage({ type: RESPONSE_TYPE, response }, "*");
  let context: Promise<KonturContext> | undefined;
  const getContext = () =>
    (context ??= pageSession(win, clock).then((session) =>
      newKonturContext(session, pageSettings(win, clock), win.navigator.platform, {
        dialogs: pageFileDialogs(win.document),
        download: pageDownload(win.document),
        identity: () => pageIdentity(win, clock),
        navigator: win.navigator,
      }),
    ));
  // The host does one command at a time.
  let queue: Promise<unknown> = Promise.resolve();

  if (konturHost) {
    const mark = () => {
      const head = win.document.head;
      if (!head) return;
      const meta = win.document.createElement("meta");
      meta.setAttribute(INSTALLATION_FLAG, "true");
      head.appendChild(meta);
    };
    if (win.document.readyState === "loading") win.document.addEventListener("DOMContentLoaded", mark, { once: true });
    else mark();
  }

  const handleMessage = (event: MessageEvent) => {
    if (!event.isTrusted || event.origin === "null" || event.source !== win || !event.data) return;
    const data = event.data as { type?: unknown; request?: Request };
    if (data.type !== REQUEST_TYPE) return;
    const request = data.request;
    if (!request || !request.sessionId) return;
    const { sessionId, commandId } = request;
    switch (request.type) {
      case "extension.info":
        if (!request.extensionId || request.extensionId === info.id) post({ sessionId, commandId, result: info });
        return;
      // The real one closes its port to the host; here the session's cache goes with it.
      case "extension.close":
        void context?.then((ready) => ready.caches.delete(String(sessionId)));
        return;
      // The real one uninstalls itself when Kontur's page asks with its id; this one is not Kontur's to remove, so it
      // answers as the real one answers any other site.
      case "extension.uninstall":
        if (!konturHost || request.extensionId === info.id) post({ sessionId, commandId, error: { type: "extension", message: "bad request" } });
        return;
    }
    queue = queue.then(async () => {
      let ready: KonturContext;
      try {
        ready = await getContext();
      } catch {
        // As the real extension without its host.
        post({ sessionId, error: { type: "connect", message: "Specified native messaging host not found." } });
        return;
      }
      // The host's envelope: its keys in order, no result key when there is nothing to answer.
      try {
        const result = await answerCommand(ready, { ...request, hostUri: event.origin });
        post(result === undefined ? { commandId, sessionId } : { commandId, result, sessionId });
      } catch (error) {
        post({ commandId, error: sortKeys(KonturError.of(error).answer), sessionId });
      }
    });
  };
  win.addEventListener("message", handleMessage, false);
}
