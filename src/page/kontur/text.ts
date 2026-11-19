// Kontur.Plugin's io.decode and io.encode (docs/JOURNAL.md, 2026-11-19): text in a Windows code page, by its number,
// as the host's converter answers. The code pages are the browser's (WHATWG encodings) with the holes the host
// refuses in them (0x98 of 1251; 1252's after Microsoft's table) and only those numbers whose answers were seen on
// the host or follow from them; any other number is its "unknown codepage".
import { KonturError, invalidStructure, pluginError } from "./errors.ts";
import { checkSink, readStream, writeStream, type Cache } from "./streams.ts";

const babel = (code: number, text: string) =>
  new KonturError({ type: "babel", code, context: "", message: `BABEL[0x${code.toString(16).toUpperCase().padStart(8, "0")}] ${text}` });
const invalidSequence = () => babel(2, "invalid multibyte sequence has been encountered in the input");

interface CodePage {
  label: string;
  holes?: number[];
}

const CODE_PAGES: Record<number, CodePage> = {
  65001: { label: "utf-8" },
  1200: { label: "utf-16le" },
  1201: { label: "utf-16be" },
  1251: { label: "windows-1251", holes: [0x98] },
  1252: { label: "windows-1252", holes: [0x81, 0x8d, 0x8f, 0x90, 0x9d] },
  866: { label: "ibm866" },
  20866: { label: "koi8-r" },
  21866: { label: "koi8-u" },
  28591: { label: "iso-8859-1" },
  28595: { label: "iso-8859-5" },
};
// Known to the host's converter by number, but not convertible there (Mac Cyrillic).
const UNSUPPORTED = new Set([10007]);

function codePage(number: unknown): CodePage {
  if (typeof number !== "number" || !Number.isInteger(number)) throw invalidStructure();
  if (UNSUPPORTED.has(number)) throw babel(5, "conversion is not supported by the implementation");
  const found = CODE_PAGES[number];
  if (!found) throw babel(1, "unknown codepage");
  return found;
}

function decodeAs(page: CodePage, bytes: Uint8Array): string {
  if (page.holes?.some((hole) => bytes.includes(hole))) throw invalidSequence();
  try {
    return new TextDecoder(page.label, { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw invalidSequence();
  }
}

// Without a code page the host guesses with a statistical detector: it takes UTF-8 and UTF-16 with a BOM and
// Cyrillic text in single-byte pages, takes long cp1251 text for an unsupported page, and cannot tell plain ASCII
// (seen on the stand). Here only the certain part is done: no bytes, a BOM, or UTF-8 with more than ASCII; the rest is
// its 105. Kontur's client always gives a code page (1251 unless asked otherwise).
function detected(bytes: Uint8Array): string {
  if (bytes.length === 0) return "";
  if (bytes[0] === 0xff && bytes[1] === 0xfe) return new TextDecoder("utf-16le").decode(bytes.subarray(2));
  if (bytes[0] === 0xfe && bytes[1] === 0xff) return new TextDecoder("utf-16be").decode(bytes.subarray(2));
  if (bytes.some((byte) => byte >= 0x80)) {
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      // Not UTF-8: undetermined here.
    }
  }
  throw pluginError(105, "unable to determine the encoding");
}

// The single-byte pages' reverse tables, made from the browser's decoder.
const reverse = new Map<string, Map<string, number>>();

function singleByteTable(page: CodePage): Map<string, number> {
  let table = reverse.get(page.label);
  if (!table) {
    table = new Map();
    const decoder = new TextDecoder(page.label);
    for (let byte = 0; byte < 256; byte++) {
      if (page.holes?.includes(byte)) continue;
      table.set(decoder.decode(Uint8Array.of(byte)), byte);
    }
    reverse.set(page.label, table);
  }
  return table;
}

function encodeAs(page: CodePage, text: string): Uint8Array {
  if (page.label === "utf-8") return new TextEncoder().encode(text);
  if (page.label === "utf-16le" || page.label === "utf-16be") {
    const bytes = new Uint8Array(text.length * 2);
    const view = new DataView(bytes.buffer);
    for (let i = 0; i < text.length; i++) view.setUint16(i * 2, text.charCodeAt(i), page.label === "utf-16le");
    return bytes;
  }
  const table = singleByteTable(page);
  return Uint8Array.from(Array.from(text), (char) => {
    const byte = table.get(char);
    if (byte === undefined) throw invalidSequence();
    return byte;
  });
}

// io.decode {source, codePage?}: the text.
export function decodeText(request: Record<string, unknown>, cache: Cache): string {
  if (request.codePage !== undefined) codePage(request.codePage);
  const bytes = readStream(cache, request.source);
  return request.codePage === undefined ? detected(bytes) : decodeAs(codePage(request.codePage), bytes);
}

// io.encode {value, codePage?, sink}: the bytes, into the sink; UTF-8 without a code page.
export function encodeText(request: Record<string, unknown>, cache: Cache): unknown {
  if (typeof request.value !== "string") throw invalidStructure();
  checkSink(request.sink);
  const page = request.codePage === undefined ? CODE_PAGES[65001]! : codePage(request.codePage);
  return writeStream(cache, request.sink, encodeAs(page, request.value));
}
