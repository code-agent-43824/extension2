// Gosplugin (docs/PLAN.md, action 46) over the Rutoken Plugin: what its extension's content script does on a page, and
// what its core answers. Once the document is parsed, the meta tag gosuslugi.plugin.extension.content marks the page,
// unless another Gosplugin extension marked it first (then this one stands aside, as the plug-in's own does); the
// page's messages (category "gosuslugi.plugin", node "") are answered by the "extension" (registered, loadScripts,
// chunkSize, cancelChunks, protocol, exists) or by the "core" (src/page/gos/core.ts).
import { pageSession } from "../page-session.ts";
import type { Clock } from "../rutoken.ts";
import { loadScripts, register, registered, SCRIPTS } from "./api.ts";
import { callCore, newCoreContext, type CoreContext, type Files } from "./core.ts";
import { CATEGORY, CONTENT_NODE, coreAnswer, GosError, localAnswer, type PageMessage } from "./messages.ts";
import { pageIdentity, type FakeIdentity } from "../identity.ts";

type Win = Window & Record<string, unknown>;

const base64Of = (bytes: Uint8Array) => btoa(Array.from(bytes, (byte) => String.fromCharCode(byte)).join(""));

// A Blob or File as the core's file: its bytes in Base64.
async function fromBlob(blob: Blob, info: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
  return { ...info, content: base64Of(new Uint8Array(await blob.arrayBuffer())), contentEncoding: "base64", name: (blob as File).name ?? "" };
}

// The files the user picks, as the plug-in's extension asks for them when a signature names none.
function pickFiles(win: Win): Promise<File[]> {
  return new Promise((resolve) => {
    const input = win.document.createElement("input");
    input.type = "file";
    input.multiple = true;
    input.style.display = "none";
    input.addEventListener("change", () => {
      resolve(Array.from(input.files ?? []));
      input.remove();
    });
    input.addEventListener("cancel", () => {
      resolve([]);
      input.remove();
    });
    win.document.body?.appendChild(input);
    input.click();
  });
}

// What the page's request carries as files, File objects read; for a signature with none, the user's choice.
function filesOf(win: Win, fromObject: boolean, picking: boolean): Files {
  return async (request) => {
    const list = Array.isArray(request.files) ? request.files : request.file ? [request.file] : [];
    if (!list.length && fromObject && picking) return Promise.all((await pickFiles(win)).map((file) => fromBlob(file)));
    return Promise.all(list.map((file) => (file instanceof Blob ? fromBlob(file) : (file as Record<string, unknown>))));
  };
}

export function startGosplugin(win: Win, clock: Clock): void {
  const doc = win.document;
  let active = false;
  let chunkSize = 524288;
  let context: Promise<CoreContext> | undefined;
  const coreContext = () => (context ??= pageSession(win, clock).then((session) => newCoreContext(session, pageIdentity(win, clock), win.navigator?.platform ?? "")));
  const post = (answer: unknown) => win.postMessage(answer, "*");

  const handle = async (message: PageMessage) => {
    const module = String(message.module?.type ?? "");
    const type = String(message.method?.type ?? "");
    const data = message.method?.data;
    switch (type) {
      case "registered":
        return post(localAnswer(message, JSON.stringify(registered(doc, typeof data === "string" && data ? data : undefined))));
      case "loadScripts":
      case "loadAllScripts":
        try {
          return post(localAnswer(message, JSON.stringify(loadScripts(win, type === "loadAllScripts" ? [] : data))));
        } catch (error) {
          const answer = localAnswer(message, "");
          answer.method = { ...answer.method, error: error instanceof Error ? error.message : String(error) };
          return post(answer);
        }
      case "cancelChunks":
        return post(localAnswer(message, "true"));
      case "chunkSize":
        if (data) chunkSize = Number(data);
        return post(localAnswer(message, String(chunkSize)));
      case "protocol":
        return post(
          localAnswer(message, JSON.stringify({ type: "nmh", host: "chrome.gosuslugi.plugin", state: "OPEN" }), {
            protocol: { category: "protocol", type: "nmh", description: "chrome.gosuslugi.plugin", version: "" },
          }),
        );
      case "exists": {
        const name = typeof data === "string" && data ? data : undefined;
        const result = name
          ? SCRIPTS.some((script) => script.value === name) && win[name] !== undefined
          : SCRIPTS.filter((script) => win[script.value] !== undefined).map((script) => ({ module: script.key, id: script.id, path: script.path, caller: "web-page" }));
        return post(localAnswer(message, JSON.stringify(result)));
      }
      case "disconnect":
        return;
    }
    let ready: CoreContext;
    let who: FakeIdentity;
    try {
      ready = await coreContext();
      who = await ready.identity;
    } catch {
      return post(coreAnswer(message, "", new GosError(20001)));
    }
    try {
      const fromObject = data !== null && typeof data === "object";
      const request = fromObject && (data as { certificate?: unknown }).certificate instanceof Blob ? { ...(data as object), certificate: await fromBlob((data as { certificate: Blob }).certificate) } : data;
      const result = await callCore(ready, module, type, request, filesOf(win, fromObject, type === "signature" || type === "signatureV2"));
      post(coreAnswer(message, result, undefined, who));
    } catch (error) {
      const gosError = error instanceof GosError ? error : new GosError(20001);
      if (!(error instanceof GosError)) console.warn("Рутокен вместо Госплагина:", error);
      ready.lastError = gosError.errorMessage;
      post(coreAnswer(message, "", gosError, who));
    }
  };

  win.addEventListener("message", (event: MessageEvent) => {
    if (!active || event.source !== win) return;
    const message = event.data as PageMessage | null;
    if (!message || typeof message !== "object" || message.meta?.format?.category !== CATEGORY || message.node !== "") return;
    void handle(message);
  });

  const init = () => {
    if (registered(doc, CONTENT_NODE)) return;
    register(doc, CONTENT_NODE);
    active = true;
  };
  if (doc.readyState === "loading") doc.addEventListener("DOMContentLoaded", init, { once: true });
  else init();
}
