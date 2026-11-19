// Kontur.Plugin's http.request (docs/JOURNAL.md, 2026-11-19): {uri, query?, method, header?, body?, timeout?,
// responseContent?, verifySslCertificate?, properties?}, answered {content, header, properties, statusCode,
// statusLine}. The host makes the request itself, past the browser's rules (a GET carries a body there, not in a
// browser); here the page's fetch makes it, so the site reaches no more than its own scripts can: another origin
// without CORS, or http: from an https: page, fails as the host's failed connection does. No cookies go, as none go
// from the host. The response's headers are those fetch shows (lower case; across origins only the exposed ones), and
// its HTTP version is not known to a page: "HTTP/1.1".
import { KonturError, invalidStructure } from "./errors.ts";
import { checkSink, readStream, writeStream, type Cache } from "./streams.ts";

const isObject = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
const METHODS = new Set(["GET", "DELETE", "HEAD", "POST", "PUT"]);

const curl = (code: number, text: string) =>
  new KonturError({ type: "libcurl", code, context: "curl_easy_perform", message: `LIBCURL[0x${code.toString(16).toUpperCase().padStart(8, "0")}]curl_easy_perform ${text}` });

function pairs(value: unknown): [string, string][] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || !value.every((item) => isObject(item) && typeof item.name === "string" && typeof item.value === "string")) throw invalidStructure();
  return value.map((item) => [item.name as string, item.value as string]);
}

// "compression": "gzip" says the source is gzip; the host inflates it and sends what is inside.
async function gunzip(bytes: Uint8Array): Promise<Uint8Array> {
  try {
    const stream = new Blob([bytes as BlobPart]).stream().pipeThrough(new DecompressionStream("gzip"));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  } catch {
    throw new KonturError({ type: "zlib", code: -3, context: "inflate", message: "ZLIB[0xFFFFFFFD]inflate incorrect header check" });
  }
}

// A form's name or value as the host writes it: spaces as "+", other bytes outside letters, digits and "!()*-._" as
// lower-case %xx (all of ASCII checked on the host).
function formEscape(text: string): string {
  return Array.from(new TextEncoder().encode(text), (byte) => {
    const char = String.fromCharCode(byte);
    if (/[A-Za-z0-9!()*\-._]/.test(char)) return char;
    return byte === 0x20 ? "+" : `%${byte.toString(16).padStart(2, "0")}`;
  }).join("");
}

// The request's body and its content type: plain bytes from a source (application/octet-stream unless a header says
// otherwise), a URL-encoded form, or multipart form data.
async function requestBody(cache: Cache, body: unknown, headers: Headers): Promise<BodyInit | undefined> {
  if (body === undefined) return undefined;
  if (!isObject(body)) throw invalidStructure();
  switch (body.type) {
    case "plain": {
      let bytes = readStream(cache, body.data);
      if (body.compression === "gzip") bytes = await gunzip(bytes);
      else if (body.compression !== undefined) throw invalidStructure();
      if (!headers.has("Content-Type")) headers.set("Content-Type", "application/octet-stream");
      return bytes as BodyInit;
    }
    case "form":
      if (!headers.has("Content-Type")) headers.set("Content-Type", "application/x-www-form-urlencoded");
      return pairs(body.data)
        .map(([name, value]) => `${formEscape(name)}=${formEscape(value)}`)
        .join("&");
    case "form-data": {
      if (!Array.isArray(body.data)) throw invalidStructure();
      const form = new FormData();
      for (const field of body.data) {
        if (!isObject(field) || typeof field.name !== "string") throw invalidStructure();
        if (typeof field.value === "string") form.append(field.name, field.value);
        else {
          const bytes = readStream(cache, field.source);
          const type = typeof field.contentType === "string" ? field.contentType : "application/octet-stream";
          form.append(field.name, new Blob([bytes as BlobPart], { type }), typeof field.filename === "string" ? field.filename : field.name);
        }
      }
      return form;
    }
  }
  // Another type, or none: no body, as the host sends none.
  return undefined;
}

export async function httpRequest(request: Record<string, unknown>, cache: Cache, fetcher: typeof fetch = fetch): Promise<unknown> {
  const uri = request.uri;
  const method = request.method;
  if (typeof uri !== "string" || typeof method !== "string" || !METHODS.has(method)) throw invalidStructure();
  if (request.timeout !== undefined && typeof request.timeout !== "number") throw invalidStructure();
  if (request.verifySslCertificate !== undefined && typeof request.verifySslCertificate !== "boolean") throw invalidStructure();
  const sink = request.responseContent ?? { type: "base64" };
  checkSink(sink);
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    throw new KonturError({ type: "libhttp", code: 25, context: "", message: "LIBHTTP[0x00000019] can create request use relative uri only" });
  }
  // The query given takes the place of the URI's own, escaped as the host escapes it: spaces and other bytes as %XX,
  // URI punctuation ("&", "=", "?"…) as it is.
  if (request.query !== undefined) url.search = pairs(request.query).map(([name, value]) => `${encodeURI(name)}=${encodeURI(value)}`).join("&");
  const headers = new Headers();
  for (const [name, value] of pairs(request.header)) headers.append(name, value);
  let body = await requestBody(cache, request.body, headers);
  // A POST without a body goes as the host's curl sends it: empty, as a URL-encoded form (a PUT without a type).
  if (body === undefined && method === "POST") {
    body = "";
    if (!headers.has("Content-Type")) headers.set("Content-Type", "application/x-www-form-urlencoded");
  }
  const abort = new AbortController();
  // In seconds.
  const timer = typeof request.timeout === "number" && request.timeout > 0 ? setTimeout(() => abort.abort(), request.timeout * 1000) : undefined;
  let response: Response;
  let content: Uint8Array;
  try {
    response = await fetcher(url, { method, headers, body: method === "GET" || method === "HEAD" ? undefined : body, signal: abort.signal, credentials: "omit", redirect: "follow" });
    content = new Uint8Array(await response.arrayBuffer());
  } catch {
    if (abort.signal.aborted) throw curl(28, "Timeout was reached");
    throw curl(7, "Could not connect to server");
  } finally {
    clearTimeout(timer);
  }
  return {
    content: writeStream(cache, sink, content),
    header: Array.from(response.headers, ([name, value]) => ({ name, value })),
    properties: {},
    statusCode: response.status,
    statusLine: { httpVersion: "HTTP/1.1", reasonPhrase: response.statusText, statusCode: response.status },
  };
}
