// Kontur.Plugin's hash.md5, hash.sha256, hash.crc32, io.getInfo, io.transfer and io.delete (docs/JOURNAL.md,
// 2026-11-19), as its host answers them on the stand.
import { md5 } from "@noble/hashes/legacy.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { KonturError, invalidStructure, pluginError } from "./errors.ts";
import { accessDenied } from "./files.ts";
import { checkSink, readStream, writeStream, type Cache } from "./streams.ts";

const isObject = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);

let crcTable: Uint32Array | undefined;

// CRC-32 of zip and gzip (IEEE 802.3, reflected).
export function crc32(bytes: Uint8Array): number {
  if (!crcTable) {
    crcTable = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      crcTable[n] = c >>> 0;
    }
  }
  let crc = 0xffffffff;
  for (const byte of bytes) crc = crcTable[(crc ^ byte) & 0xff]! ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

// hash.md5 and hash.sha256 {source, sink}: the digest into the sink; hash.crc32 {source}: the number itself.
export function hashCommand(type: string, request: Record<string, unknown>, cache: Cache): unknown {
  if (type === "hash.crc32") return crc32(readStream(cache, request.source));
  checkSink(request.sink);
  const bytes = readStream(cache, request.source);
  return writeStream(cache, request.sink, type === "hash.md5" ? md5(bytes) : sha256(bytes));
}

const tooFar = () => new KonturError({ type: "iostreams", code: 6, context: "", message: "IOSTREAMS[0x00000006] offset is larger than the data size" });

function offset(value: unknown): number {
  if (value === undefined) return 0;
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) throw invalidStructure();
  return value;
}

// io.getInfo {source}: its type and size; a cache stream's name; a file's path, opened for reading.
export function streamInfo(request: Record<string, unknown>, cache: Cache): Record<string, unknown> {
  const source = request.source;
  if (!isObject(source)) throw invalidStructure();
  const size = readStream(cache, source).length;
  if (source.type === "cache") return { name: source.name, size, type: "cache" };
  if (source.type === "file") return { access: "read", mode: "open", path: source.path, size, type: "file" };
  return { size, type: source.type };
}

// io.transfer {source, sink, sourceOffset?, count?, sinkOffset?}: count bytes of the source from its offset (all to
// its end, a count past it cut) written into the sink at its offset: over a cache stream's bytes, zeros before the
// rest; the sink's answer for all it holds.
export function transfer(request: Record<string, unknown>, cache: Cache): unknown {
  checkSink(request.sink);
  const bytes = readStream(cache, request.source);
  const from = offset(request.sourceOffset);
  const at = offset(request.sinkOffset);
  if (request.count !== undefined) offset(request.count);
  if (from > bytes.length) throw tooFar();
  const part = bytes.subarray(from, request.count === undefined ? undefined : from + (request.count as number));
  const sink = request.sink as Record<string, unknown>;
  const before = sink.type === "cache" ? (cache.get(String(sink.name)) ?? new Uint8Array()) : new Uint8Array();
  const result = new Uint8Array(Math.max(before.length, at + part.length));
  result.set(before);
  result.set(part, at);
  return writeStream(cache, sink, result);
}

// io.delete {source}: true when there was something to delete (a cache stream, a file chosen or saved, which the page
// forgets: a download stays in the browser's downloads), false otherwise; data in the request itself, true.
export function deleteStream(request: Record<string, unknown>, cache: Cache): boolean {
  const source = request.source;
  if (!isObject(source)) throw pluginError(2, "unknown command");
  if (source.type === "cache") {
    if (typeof source.name !== "string") throw invalidStructure();
    return cache.delete(source.name);
  }
  if (source.type === "file") {
    if (typeof source.path !== "string") throw invalidStructure();
    if (!cache.files) throw accessDenied();
    return cache.files.remove(source.path);
  }
  if (source.type !== "base64" && source.type !== "hex") throw invalidStructure();
  return true;
}
