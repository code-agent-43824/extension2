// Kontur.Plugin's data streams (docs/JOURNAL.md, 2026-11-19): a source or a sink is {type, data | name | path}, of type
// "base64", "hex", "cache" (bytes the host keeps by name for the connection) or "file" (a path on disk). A sink
// answers {data, size, type} or, for the cache, {name, size, type}.
import { cryptoError, invalidStructure, pluginError } from "./errors.ts";

export interface Stream {
  type?: unknown;
  data?: unknown;
  name?: unknown;
  path?: unknown;
}

export interface StreamAnswer {
  data?: string;
  name?: string;
  size: number;
  type: string;
}

// The streams a page session keeps (KonturContext.caches, by session id).
export type Cache = Map<string, Uint8Array>;

const isObject = (value: unknown): value is Stream => typeof value === "object" && value !== null && !Array.isArray(value);

// The host takes Base64 leniently: "@@@" signed as empty data on the stand. Characters outside the alphabet are
// dropped here and the rest decoded.
export function fromBase64(text: string): Uint8Array {
  const clean = text.replace(/[^A-Za-z0-9+/]/g, "");
  const usable = clean.slice(0, clean.length - (clean.length % 4 === 1 ? 1 : 0));
  const padded = usable + "=".repeat((4 - (usable.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
}

export function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}

export function fromHex(text: string): Uint8Array {
  const clean = text.replace(/[^0-9a-fA-F]/g, "");
  return Uint8Array.from(clean.match(/../g) ?? [], (pair) => parseInt(pair, 16));
}

export const toHex = (bytes: Uint8Array) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

// Files are the host's own business: a path the page names is refused, as the host refuses one it did not hand out.
const accessDenied = () => pluginError(16, "access denied");

export function readStream(cache: Cache, stream: unknown): Uint8Array {
  if (!isObject(stream)) throw invalidStructure();
  switch (stream.type) {
    case "base64":
      if (typeof stream.data !== "string") throw invalidStructure();
      return fromBase64(stream.data);
    case "hex":
      if (typeof stream.data !== "string") throw invalidStructure();
      return fromHex(stream.data);
    case "cache": {
      if (typeof stream.name !== "string") throw invalidStructure();
      const bytes = cache.get(stream.name);
      if (!bytes) throw pluginError(101, "the stream with the specified name is not in the cache");
      return bytes;
    }
    case "file":
      throw accessDenied();
  }
  throw invalidStructure();
}

// Checks a sink before the work it receives, as the host refuses a bad one before signing.
export function checkSink(sink: unknown): void {
  if (!isObject(sink)) throw invalidStructure();
  if (sink.type === "cache" && typeof sink.name !== "string") throw invalidStructure();
  if (!["base64", "hex", "cache", "file"].includes(String(sink.type))) throw invalidStructure();
}

export function writeStream(cache: Cache, sink: unknown, bytes: Uint8Array): StreamAnswer {
  checkSink(sink);
  const target = sink as Stream;
  switch (target.type) {
    case "base64":
      return { data: toBase64(bytes), size: bytes.length, type: "base64" };
    case "hex":
      return { data: toHex(bytes), size: bytes.length, type: "hex" };
    case "cache":
      cache.set(String(target.name), bytes);
      return { name: String(target.name), size: bytes.length, type: "cache" };
  }
  throw accessDenied();
}

// The host's answer for a hash of the wrong length (crypto.signHash).
export const wrongHashSize = () => cryptoError(35, "wrong hash value size");
