// Gosplugin's messages as a page sees them (docs/JOURNAL.md, 2026-11-17): the page posts an object with
// meta.format.category "gosuslugi.plugin" and node ""; the extension answers some itself (content.js: the page's own
// message with node set to the page's first route, data null, a result and its route added) and passes the rest to
// the core, whose answer has its own shape (code, errorMessage, the core's meta). Both are rebuilt here from the
// recorded ones; no code of the plug-in is in this file.

export const CATEGORY = "gosuslugi.plugin";
export const CONTENT_NODE = "gosuslugi.plugin.extension.content";
export const CORE_VERSION = "1.3.42.0";

export interface PageRoute {
  node?: unknown;
  time?: unknown;
  transfer?: unknown;
}

export interface PageMessage {
  id?: unknown;
  node?: unknown;
  error?: unknown;
  mode?: unknown;
  module?: { type?: unknown; version?: unknown };
  method?: { type?: unknown; data?: unknown; result?: unknown; error?: unknown };
  meta?: { format?: { category?: unknown }; routes?: PageRoute[]; data?: Record<string, unknown>; [key: string]: unknown };
  [key: string]: unknown;
}

// The core's error catalog, the codes it answers here: category and text.
const ERRORS: Record<number, [string, string]> = {
  20001: ["Application", "Общая ошибка"],
  20003: ["Application", "Операция отменена пользователем"],
  20005: ["Application", "Не найден метод"],
  20006: ["Application", "Данные не найдены"],
  20009: ["Application", "Файл не найден"],
  30005: ["Crypto", "Не найден контейнер"],
  30008: ["Crypto", "Не найден алгоритм"],
  30009: ["Crypto", "Не найден тип"],
  30013: ["Crypto", "Не задано хранилище сертификатов"],
  30015: ["Crypto", "Не задан алгоритм"],
  30019: ["Crypto", "Сертификат отсутствует в хранилище"],
  30022: ["Crypto", "Тип подписи не поддерживается"],
  30031: ["Crypto", "Сертификат уже содержится в контейнере на токене"],
  30045: ["Crypto", "Ошибка контекста сертификата"],
  31013: ["Xml", "Ожидается namespace"],
};

export class GosError extends Error {
  readonly code: number;
  readonly text: string;
  // "<code> <category> '<text>'", and ": <detail>" when the core names what it did not find.
  readonly errorMessage: string;

  constructor(code: number, detail?: string) {
    const [category, text] = ERRORS[code] ?? ERRORS[20001]!;
    const errorMessage = `${code} ${category} '${text}'${detail ? `: ${detail}` : ""}`;
    super(errorMessage);
    this.name = "GosError";
    this.code = code;
    this.text = text;
    this.errorMessage = errorMessage;
  }
}

export const SUCCESS_MESSAGE = "0 Application 'Успешное выполнение операции'";

const firstRoute = (message: PageMessage): PageRoute => (Array.isArray(message.meta?.routes) ? (message.meta!.routes[0] ?? {}) : {});

export const pageNode = (message: PageMessage) => String(firstRoute(message).node ?? "");

const contentRoute = () => ({ node: CONTENT_NODE, time: new Date().toLocaleString(), transfer: "" });

// An answer of the extension itself: the page's message, answered.
export function localAnswer(message: PageMessage, result: string, extraMeta: Record<string, unknown> = {}): PageMessage {
  const answer = structuredClone(message);
  answer.node = pageNode(message);
  answer.method = { ...(answer.method ?? {}), data: null, result };
  answer.meta = { ...(answer.meta ?? {}), ...extraMeta, routes: [...(answer.meta?.routes ?? []), contentRoute()] };
  return answer;
}

// The core's time in its route: "17.11.2026, 13:39:57".
const coreTime = () => new Date().toLocaleString("ru-RU");

// An answer of the core: its result, or its error.
export function coreAnswer(message: PageMessage, result: string, error?: GosError): Record<string, unknown> {
  const route = firstRoute(message);
  return {
    id: message.id,
    module: { type: String(message.module?.type ?? ""), version: "0.0.0.0" },
    method: { type: String(message.method?.type ?? ""), data: null, result: error ? "" : result },
    error: error ? error.text : "",
    code: error ? String(error.code) : "0",
    errorMessage: error ? error.errorMessage : "",
    node: pageNode(message),
    mode: String(message.mode ?? ""),
    meta: {
      format: { type: "", version: "", category: "", description: "" },
      protocol: { type: "nmh", version: CORE_VERSION, category: "plugin", description: "provides communication plugin-plugin.extension via google native messaging protocol" },
      content: { type: "", charset: "", transferEncoding: error ? "" : "binary" },
      routes: [{ node: route.node, time: route.time }, { node: "plugin", time: coreTime() }, contentRoute()],
      data: {},
      // The core names the user and the computer here; the extension does not tell them.
      userAgent: JSON.stringify({ user: "(none)", pc: "(none)", process: "gosuslugi_plugin" }),
    },
  };
}
