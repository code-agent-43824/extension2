// Kontur.Plugin's archive.gzip, archive.ungzip, archive.zip, archive.unzip and archive.zip.* (docs/JOURNAL.md,
// 2026-11-19), as its host answers them on the stand: gzip and zip made and read in the page with the browser's
// (de)compression streams. A zip here is what the host's minizip writes and reads: deflated or stored entries, names
// in UTF-8, no ZIP64, no encryption.
import { crc32 } from "./io.ts";
import { KonturError, invalidStructure, pluginError } from "./errors.ts";
import { accessDenied } from "./files.ts";
import { checkSink, readStream, writeStream, type Cache } from "./streams.ts";

const zlib = (code: number, context: string) =>
  new KonturError({ type: "zlib", code, context, message: `ZLIB[0x${(code >>> 0).toString(16).toUpperCase().padStart(8, "0")}]${context === "inflate" ? "inflate incorrect header check" : context}` });
const badHeader = () => zlib(-3, "inflate");
const notZip = () => new KonturError({ type: "iostreams", code: 6, context: "", message: "IOSTREAMS[0x00000006] offset is larger than the data size" });

async function through(bytes: Uint8Array, stream: CompressionStream | DecompressionStream): Promise<Uint8Array> {
  const piped = new Blob([bytes as BlobPart]).stream().pipeThrough(stream);
  return new Uint8Array(await new Response(piped).arrayBuffer());
}

// compressionLevel: "best", "fast" or "normal"; another word is the host's "invalid enumeration value".
function checkLevel(level: unknown): void {
  if (level === undefined || level === "best" || level === "fast" || level === "normal") return;
  if (typeof level !== "string") throw invalidStructure();
  throw new KonturError({ message: "invalid enumeration value" } as never);
}

// archive.gzip {source, sink, compressionLevel?}, archive.ungzip {source, sink}.
export async function gzip(request: Record<string, unknown>, cache: Cache, unpack: boolean): Promise<unknown> {
  checkSink(request.sink);
  if (!unpack) checkLevel(request.compressionLevel);
  const bytes = readStream(cache, request.source);
  let result: Uint8Array;
  if (unpack) {
    try {
      result = await through(bytes, new DecompressionStream("gzip"));
    } catch {
      throw badHeader();
    }
  } else result = await through(bytes, new CompressionStream("gzip"));
  return writeStream(cache, request.sink, result);
}

interface Entry {
  name: string;
  method: number;
  flags: number;
  crc: number;
  size: number;
  // The entry's data as stored.
  stored: Uint8Array;
}

const utf8 = new TextEncoder();

function readZip(bytes: Uint8Array): Entry[] {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let end = -1;
  for (let at = bytes.length - 22; at >= Math.max(0, bytes.length - 22 - 0xffff); at--) {
    if (view.getUint32(at, true) === 0x06054b50) {
      end = at;
      break;
    }
  }
  if (end < 0) throw notZip();
  const count = view.getUint16(end + 10, true);
  let at = view.getUint32(end + 16, true);
  const entries: Entry[] = [];
  try {
    for (let i = 0; i < count; i++) {
      if (view.getUint32(at, true) !== 0x02014b50) throw notZip();
      const flags = view.getUint16(at + 8, true);
      const method = view.getUint16(at + 10, true);
      const crc = view.getUint32(at + 16, true);
      const compressed = view.getUint32(at + 20, true);
      const size = view.getUint32(at + 24, true);
      const nameLength = view.getUint16(at + 28, true);
      const extraLength = view.getUint16(at + 30, true);
      const commentLength = view.getUint16(at + 32, true);
      const local = view.getUint32(at + 42, true);
      const name = new TextDecoder().decode(bytes.subarray(at + 46, at + 46 + nameLength));
      if (view.getUint32(local, true) !== 0x04034b50) throw notZip();
      const data = local + 30 + view.getUint16(local + 26, true) + view.getUint16(local + 28, true);
      if (data + compressed > bytes.length) throw notZip();
      entries.push({ name, method, flags, crc, size, stored: bytes.subarray(data, data + compressed) });
      at += 46 + nameLength + extraLength + commentLength;
    }
  } catch (error) {
    if (error instanceof KonturError) throw error;
    throw notZip();
  }
  return entries;
}

function writeZip(entries: Entry[]): Uint8Array {
  const parts: Uint8Array[] = [];
  const central: Uint8Array[] = [];
  let offset = 0;
  for (const entry of entries) {
    const name = utf8.encode(entry.name);
    const local = new Uint8Array(30 + name.length);
    const view = new DataView(local.buffer);
    view.setUint32(0, 0x04034b50, true);
    view.setUint16(4, 20, true);
    view.setUint16(6, entry.flags, true);
    view.setUint16(8, entry.method, true);
    view.setUint32(14, entry.crc, true);
    view.setUint32(18, entry.stored.length, true);
    view.setUint32(22, entry.size, true);
    view.setUint16(26, name.length, true);
    local.set(name, 30);
    const record = new Uint8Array(46 + name.length);
    const header = new DataView(record.buffer);
    header.setUint32(0, 0x02014b50, true);
    header.setUint16(6, 20, true);
    header.setUint16(8, entry.flags, true);
    header.setUint16(10, entry.method, true);
    header.setUint32(16, entry.crc, true);
    header.setUint32(20, entry.stored.length, true);
    header.setUint32(24, entry.size, true);
    header.setUint16(28, name.length, true);
    header.setUint32(42, offset, true);
    record.set(name, 46);
    parts.push(local, entry.stored);
    central.push(record);
    offset += local.length + entry.stored.length;
  }
  const directory = central.reduce((sum, record) => sum + record.length, 0);
  const end = new Uint8Array(22);
  const view = new DataView(end.buffer);
  view.setUint32(0, 0x06054b50, true);
  view.setUint16(8, entries.length, true);
  view.setUint16(10, entries.length, true);
  view.setUint32(12, directory, true);
  view.setUint32(16, offset, true);
  const all = [...parts, ...central, end];
  const result = new Uint8Array(all.reduce((sum, part) => sum + part.length, 0));
  let at = 0;
  for (const part of all) {
    result.set(part, at);
    at += part.length;
  }
  return result;
}

async function newEntry(name: string, bytes: Uint8Array, level: unknown): Promise<Entry> {
  // General purpose flag bit 1: "maximum compression", as minizip marks it.
  return { name, method: 8, flags: level === "best" ? 2 : 0, crc: crc32(bytes), size: bytes.length, stored: await through(bytes, new CompressionStream("deflate-raw")) };
}

async function content(entry: Entry): Promise<Uint8Array> {
  if (entry.method === 0) return entry.stored;
  try {
    return await through(entry.stored, new DecompressionStream("deflate-raw"));
  } catch {
    throw badHeader();
  }
}

// The entry a request names, by name or by index.
function chosen(entries: Entry[], request: Record<string, unknown>): Entry {
  if (typeof request.name === "string") {
    const entry = entries.find((each) => each.name === request.name);
    if (!entry) throw zlib(-100, "unzLocateFile");
    return entry;
  }
  if (typeof request.index === "number") {
    const entry = entries[request.index];
    if (!entry) throw zlib(-100, "unzGoToNextFile");
    return entry;
  }
  throw invalidStructure();
}

// archive.zip.getEntries {source}.
export function zipEntries(request: Record<string, unknown>, cache: Cache): unknown[] {
  return readZip(readStream(cache, request.source)).map((entry, index) => ({
    compressionSize: entry.stored.length,
    index,
    isDirectory: entry.name.endsWith("/"),
    name: entry.name,
    size: entry.size,
  }));
}

// archive.zip.getEntry {source, sink, name | index}; archive.unzip {source, sink}: the first entry.
export async function zipEntry(request: Record<string, unknown>, cache: Cache, first: boolean): Promise<unknown> {
  checkSink(request.sink);
  const entries = readZip(readStream(cache, request.source));
  const entry = first ? entries[0] : chosen(entries, request);
  if (!entry) throw zlib(-100, "unzGoToFirstFile");
  return writeStream(cache, request.sink, await content(entry));
}

// archive.zip.addEntry {source, sink, name, compressionLevel?}: the entry added to the archive a cache stream (or a
// file) holds, or a new archive; archive.zip {source, sink}: a new archive of one entry, "file".
export async function zipAdd(request: Record<string, unknown>, cache: Cache, single: boolean): Promise<unknown> {
  checkSink(request.sink);
  checkLevel(request.compressionLevel);
  const name = single ? "file" : request.name;
  if (typeof name !== "string" || !name) throw invalidStructure();
  const bytes = readStream(cache, request.source);
  const sink = request.sink as Record<string, unknown>;
  let entries: Entry[] = [];
  if (!single && sink.type === "cache" && cache.has(String(sink.name))) entries = readZip(cache.get(String(sink.name))!);
  if (entries.some((entry) => entry.name === name)) throw pluginError(103, "zip archive already contains an entry with the same name");
  entries.push(await newEntry(name, bytes, request.compressionLevel));
  return writeStream(cache, sink, writeZip(entries));
}

// archive.zip.extract {source, destination, name | index?}: the entries (or the one named) into a folder the user chose
// in ui.selectFolder, that is to the browser's downloads; any other folder is refused. Nothing is answered.
export async function zipExtract(request: Record<string, unknown>, cache: Cache): Promise<undefined> {
  const destination = request.destination;
  if (typeof destination !== "string") throw invalidStructure();
  const entries = readZip(readStream(cache, request.source));
  const files = cache.files;
  if (!files) throw accessDenied();
  const wanted = request.name === undefined && request.index === undefined ? entries : [chosen(entries, request)];
  for (const entry of wanted) {
    if (entry.name.endsWith("/")) continue;
    files.write(files.join(destination, entry.name.split("/").pop()!), await content(entry));
  }
  return undefined;
}
