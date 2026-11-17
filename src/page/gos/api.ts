// What Gosplugin's scripts put on a page when it asks for them with loadScripts (docs/JOURNAL.md, 2026-11-17): the
// message classes of formats.js, gosuslugiPluginSystem and gosuslugiPluginCrypto (each method posts a message and calls
// back with the answer of the same id), bootstrap, each also under its _<name>_0db7… alias, and a meta tag per script.
// The interface is the plug-in's; the code is this extension's own. The real scripts declare the classes as global
// constants, which a bundled script cannot; here they are non-enumerable properties of the window, so a page sees them
// by name all the same.
import { CATEGORY } from "./messages.ts";

const SUFFIX = "0db7d9ec48754f9080a77e237238453b";

export interface PluginScript {
  key: string;
  id: string;
  value: string;
  path: string;
  dependencies: string[];
}

// In the order the plug-in's bootstrap lists them; crypto_wrapper.js is listed but not shipped, so it fails to load.
export const SCRIPTS: PluginScript[] = [
  { key: "system", id: "gosuslugi.plugin.extension.system", value: `_system_${SUFFIX}`, path: "system.js", dependencies: ["formats"] },
  { key: "crypto", id: "gosuslugi.plugin.extension.crypto", value: `_crypto_${SUFFIX}`, path: "crypto.js", dependencies: ["formats"] },
  { key: "crypto_wrapper", id: "gosuslugi.plugin.extension.crypto_wrapper", value: `_crypto_wrapper_${SUFFIX}`, path: "crypto_wrapper.js", dependencies: ["crypto"] },
  { key: "bootstrap", id: "gosuslugi.plugin.extension.bootstrap", value: `_bootstrap_${SUFFIX}`, path: "bootstrap.js", dependencies: [] },
  { key: "formats", id: "gosuslugi.plugin.extension.formats", value: `_formats_${SUFFIX}`, path: "formats.js", dependencies: [] },
];

type Win = Window & Record<string, unknown>;
type Callback = (message: unknown) => void;

// The meta tags of "gosuslugi.plugin.extension.*" in the head: whether `id` is one, or all of them.
export function registered(doc: Document, id?: string): boolean | string[] {
  const properties = Array.from(doc.head?.querySelectorAll('meta[content="extension"]') ?? [])
    .map((meta) => meta.getAttribute("property") ?? "")
    .filter((property) => property.startsWith("gosuslugi.plugin.extension."));
  return id ? properties.includes(id) : properties;
}

export function register(doc: Document, id: string): void {
  const meta = doc.createElement("meta");
  meta.setAttribute("content", "extension");
  meta.setAttribute("property", id);
  doc.head?.appendChild(meta);
}

function uuid(): string {
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (char) => {
    const random = (Math.random() * 16) | 0;
    return (char === "x" ? random : (random & 0x3) | 0x8).toString(16);
  });
}

function formatClasses(win: Win) {
  class GosuslugiPluginModule {
    type: unknown;
    version: unknown;
    constructor(type: unknown, version: unknown) {
      this.type = type;
      this.version = version;
    }
  }
  class GosuslugiPluginFileInfo {
    content: unknown;
    path: unknown;
    id: unknown;
    name: unknown;
    contentEncoding: unknown;
    contentFormat: unknown;
    constructor(content: unknown, path: unknown, contentEncoding?: unknown, id?: unknown, name?: unknown, contentFormat?: unknown) {
      this.content = content;
      this.path = path;
      this.id = id || "";
      this.name = name || "";
      this.contentEncoding = contentEncoding || "";
      this.contentFormat = contentFormat || "";
    }
  }
  class GosuslugiPluginMethod {
    type: unknown;
    data: unknown;
    result: unknown;
    constructor(type: unknown, data: unknown, result?: unknown) {
      this.type = type;
      this.data = data;
      this.result = result || "";
    }
  }
  class GosuslugiPluginFormat {
    type: unknown;
    version: unknown;
    category: unknown;
    constructor(type: unknown, version: unknown, category: unknown) {
      this.type = type;
      this.version = version;
      this.category = category;
    }
  }
  class GosuslugiPluginContent {
    type: unknown;
    charset: unknown;
    transferEncoding: unknown;
    constructor(type: unknown, charset: unknown, transferEncoding: unknown) {
      this.type = type;
      this.charset = charset;
      this.transferEncoding = transferEncoding;
    }
  }
  class GosuslugiPluginRoute {
    node: unknown;
    time: unknown;
    transfer: unknown;
    constructor(node: unknown, time: unknown, transfer: unknown = "") {
      this.node = node;
      this.time = time;
      this.transfer = transfer;
    }
  }
  class GosuslugiPluginMeta {
    format: unknown;
    content: unknown;
    routes: unknown[] = [];
    data: Record<string, unknown> = {};
    userAgent: string;
    constructor(format: unknown, content: unknown) {
      this.format = format;
      this.content = content;
      this.userAgent = win.navigator?.userAgent || "Unknown";
    }
  }
  class GosuslugiPluginDependency {
    type: unknown;
    version: unknown;
    constructor(type: unknown, version: unknown) {
      this.type = type;
      this.version = version;
    }
  }
  class GosuslugiPluginConfig {
    type = "";
    description = "";
    state = "";
    format = new GosuslugiPluginFormat("", "", "");
    dependencies: unknown[] = [];
    methods: unknown[] = [];
  }
  class GosuslugiPluginNameInfo {
    name = "";
    lastName = "";
    firstAndMiddleName = "";
    email = "";
    snils = "";
    companyName = "";
    organizationName = "";
    inn = "";
    kpp = "";
    ogrn = "";
    ogrnip = "";
    post = "";
    street = "";
    region = "";
    city = "";
    country = "";
  }
  class GosuslugiPluginMessage {
    id = uuid();
    node = "";
    error = "";
    mode: unknown;
    module: GosuslugiPluginModule;
    method: GosuslugiPluginMethod;
    meta: GosuslugiPluginMeta;
    constructor(owner: unknown, module: unknown, func: unknown, data: unknown = "", result: unknown = "", mode: unknown = "") {
      this.mode = mode || "";
      this.module = new GosuslugiPluginModule(module, "0.0.0.0");
      this.method = new GosuslugiPluginMethod(func, data, result);
      this.meta = new GosuslugiPluginMeta(new GosuslugiPluginFormat("message", "0.0.0.0", CATEGORY), new GosuslugiPluginContent("application/json", "utf8", ""));
      this.meta.routes.push(new GosuslugiPluginRoute(owner, new Date().toLocaleString()));
    }
  }
  return {
    GosuslugiPluginModule,
    GosuslugiPluginFileInfo,
    GosuslugiPluginMethod,
    GosuslugiPluginFormat,
    GosuslugiPluginContent,
    GosuslugiPluginRoute,
    GosuslugiPluginMeta,
    GosuslugiPluginDependency,
    GosuslugiPluginConfig,
    GosuslugiPluginNameInfo,
    GosuslugiPluginMessage,
  };
}

type Classes = ReturnType<typeof formatClasses>;

// The object of one script (`id`, the owner of its messages): posts them and calls back with the answers.
function client(win: Win, id: string, classes: Classes, original: unknown) {
  const callbacks = new Map<unknown, Callback>();
  win.addEventListener("message", (event: MessageEvent) => {
    const message = event.data as { node?: unknown; id?: unknown } | null;
    if (!message?.node || !message.id) return;
    const callback = callbacks.get(message.id);
    if (callback) {
      callbacks.delete(message.id);
      callback(message);
    }
  });
  return {
    caller: () => "web-page",
    original: () => original,
    post(message: { id: unknown }, callback?: Callback) {
      if (callback) callbacks.set(message.id, callback);
      win.postMessage(message, "*");
    },
    send(module: string, method: string, data: unknown, callback?: Callback) {
      const message = new classes.GosuslugiPluginMessage(id, module, method, data);
      this.post(message, callback);
      return message;
    },
  };
}

function systemObject(win: Win, classes: Classes) {
  const base = client(win, "gosuslugi.plugin.extension.system", classes, win.gosuslugiPluginSystem);
  const call = (method: string) => (callback?: Callback) => void base.send("system", method, "", callback);
  return {
    caller: base.caller,
    original: base.original,
    post: base.post.bind(base),
    handshake: call("handshake"),
    echo: (value: unknown, callback?: Callback) => void base.send("system", "echo", value, callback),
    cache: (value: unknown, callback?: Callback) => void base.send("system", "cache", value, callback),
    lastError: call("lastError"),
    config: call("config"),
    ipConfig: call("ipConfig"),
    close: call("close"),
    protocol: call("protocol"),
  };
}

function cryptoObject(win: Win, classes: Classes) {
  const base = client(win, "gosuslugi.plugin.extension.crypto", classes, win.gosuslugiPluginCrypto);
  // providers, tokens, certificates and certificateRequest send the request as JSON; the others as it is.
  const json = (method: string) => (request: unknown, callback?: Callback) => void base.send("crypto", method, JSON.stringify(request), callback);
  const asIs = (method: string) => (request: unknown, callback?: Callback) => void base.send("crypto", method, request, callback);
  // A signature can carry its own message id (request.meta.data.message), for the chunks of a big file.
  const signature = (method: string) => (request: unknown, callback?: Callback) => {
    const message = new classes.GosuslugiPluginMessage("gosuslugi.plugin.extension.crypto", "crypto", method, request);
    const id = (request as { meta?: { data?: { message?: unknown } } } | null)?.meta?.data?.message;
    if (id) message.id = String(id);
    base.post(message, callback);
  };
  return {
    caller: base.caller,
    original: base.original,
    profile: () => undefined,
    post: base.post.bind(base),
    providers: json("providers"),
    tokens: json("tokens"),
    certificates: json("certificates"),
    certificateRequest: json("certificateRequest"),
    certificateFields: asIs("certificateFields"),
    addCertificate: asIs("addCertificate"),
    deleteCertificate: asIs("deleteCertificate"),
    signature: signature("signature"),
    signatureV2: signature("signatureV2"),
    cancelChunks: (callback?: Callback) => void base.send("crypto", "cancelChunks", "", callback),
    chunkSize: (_value: unknown, callback?: Callback) => void base.send("crypto", "chunkSize", "", callback),
    normalize: asIs("normalize"),
    hash: asIs("hash"),
  };
}

const define = (win: Win, name: string, value: unknown, enumerable = true) =>
  Object.defineProperty(win, name, { value, writable: true, configurable: true, enumerable });

const time = () => new Date().toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit", second: "2-digit" });

export interface LoadResult {
  script: string;
  status: "success" | "exists" | "error";
  time: string;
  error?: Record<string, never>;
}

// Defines the requested scripts' objects, their dependencies first, as the plug-in's bootstrap loads them.
export function loadScripts(win: Win, list: unknown): LoadResult[] {
  const names = Array.isArray(list) && list.length ? list.map((name) => String(name).replace(".js", "")) : SCRIPTS.map((script) => script.key);
  const order: PluginScript[] = [];
  const visit = (key: string) => {
    const script = SCRIPTS.find((candidate) => candidate.key === key);
    if (!script) throw new Error(`gosuslugi.plugin.extension.bootstrap: script not found: ${key}`);
    if (order.includes(script)) return;
    script.dependencies.forEach(visit);
    order.push(script);
  };
  names.forEach(visit);
  const doc = win.document;
  return order.map((script) => {
    if (registered(doc, script.id)) return { script: script.path, status: "exists", time: time() };
    if (script.key === "crypto_wrapper") return { script: script.path, status: "error", time: time(), error: {} };
    install(win, script.key);
    register(doc, script.id);
    return { script: script.path, status: "success", time: time() };
  });
}

let classes: Classes | undefined;

function install(win: Win, key: string): void {
  classes ??= formatClasses(win);
  const script = SCRIPTS.find((candidate) => candidate.key === key)!;
  // The alias first, then the name sites use, in the order the plug-in's scripts set them.
  const set = (name: string, value: unknown) => {
    define(win, script.value, value);
    define(win, name, value);
  };
  if (key === "formats") {
    for (const [name, constructor] of Object.entries(classes)) define(win, name, constructor, false);
    set("formats", { caller: () => "web-page", original: () => win.formats, ...classes });
  } else if (key === "system") {
    set("gosuslugiPluginSystem", systemObject(win, classes));
  } else if (key === "crypto") {
    set("gosuslugiPluginCrypto", cryptoObject(win, classes));
  } else if (key === "bootstrap") {
    set("bootstrap", bootstrapObject(win));
  }
}

function bootstrapObject(win: Win) {
  return {
    caller: () => "web-page",
    context: () => win,
    document: () => win.document,
    original: () => undefined,
    exists: (name?: string) =>
      name
        ? SCRIPTS.some((script) => script.value === name) && win[name] !== undefined
        : SCRIPTS.filter((script) => win[script.value] !== undefined).map((script) => ({ module: script.key, id: script.id, path: script.path, caller: "web-page" })),
    registered: (id?: string) => registered(win.document, id),
    register: (id: string) => register(win.document, id),
    init: (id: string) => {
      if (!registered(win.document, id)) register(win.document, id);
    },
    loadScripts: async (list: unknown) => loadScripts(win, list),
    loadAllScripts: async () => loadScripts(win, []),
  };
}
