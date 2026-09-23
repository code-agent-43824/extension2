// Minimal CRX3 reader: splits the signed header from the ZIP payload and finds
// the public key that defines the extension id. Chromium derives an unpacked
// extension's id from manifest "key", so writing this key there lets the stand
// load the Rutoken adapter under its store id, which the Rutoken native host
// requires (allowed_origins).
import { createHash } from "node:crypto";

export interface Crx {
  publicKeys: Buffer[];
  crxId: Buffer | undefined;
  zip: Buffer;
}

function readVarint(buf: Buffer, pos: number): [number, number] {
  let value = 0;
  let shift = 0;
  for (;;) {
    if (pos >= buf.length) throw new Error("truncated varint");
    const byte = buf[pos++]!;
    value += (byte & 0x7f) * 2 ** shift;
    if ((byte & 0x80) === 0) return [value, pos];
    shift += 7;
  }
}

// Yields the length-delimited fields of a protobuf message; other wire types are skipped.
function* fields(buf: Buffer): Generator<[number, Buffer]> {
  let pos = 0;
  while (pos < buf.length) {
    const [tag, afterTag] = readVarint(buf, pos);
    const field = Math.floor(tag / 8);
    const wire = tag & 7;
    pos = afterTag;
    if (wire === 2) {
      const [len, afterLen] = readVarint(buf, pos);
      yield [field, buf.subarray(afterLen, afterLen + len)];
      pos = afterLen + len;
    } else if (wire === 0) {
      pos = readVarint(buf, pos)[1];
    } else if (wire === 5) {
      pos += 4;
    } else if (wire === 1) {
      pos += 8;
    } else {
      throw new Error(`unsupported protobuf wire type ${wire}`);
    }
  }
}

export function parseCrx(file: Buffer): Crx {
  if (file.subarray(0, 4).toString("latin1") !== "Cr24") throw new Error("not a CRX file");
  const version = file.readUInt32LE(4);
  if (version !== 3) throw new Error(`unsupported CRX version ${version}`);
  const headerSize = file.readUInt32LE(8);
  const header = file.subarray(12, 12 + headerSize);
  const publicKeys: Buffer[] = [];
  let crxId: Buffer | undefined;
  for (const [field, value] of fields(header)) {
    // CrxFileHeader: 2 = sha256_with_rsa, 3 = sha256_with_ecdsa (AsymmetricKeyProof), 10000 = signed_header_data.
    if (field === 2 || field === 3) {
      for (const [f, v] of fields(value)) if (f === 1) publicKeys.push(v);
    } else if (field === 10000) {
      for (const [f, v] of fields(value)) if (f === 1) crxId = v;
    }
  }
  return { publicKeys, crxId, zip: file.subarray(12 + headerSize) };
}

// Chromium extension id: first 16 bytes of SHA-256 of the key, each nibble mapped 0..15 -> 'a'..'p'.
export function extensionIdFromKey(publicKey: Buffer): string {
  const digest = createHash("sha256").update(publicKey).digest().subarray(0, 16);
  return [...digest.toString("hex")].map((c) => String.fromCharCode(97 + parseInt(c, 16))).join("");
}

export function extensionIdFromBytes(id: Buffer): string {
  return [...id.toString("hex")].map((c) => String.fromCharCode(97 + parseInt(c, 16))).join("");
}

// The key whose hash matches the id the store signed; falls back to the only key if the id is absent.
export function developerKey(crx: Crx): Buffer {
  if (crx.crxId) {
    const want = extensionIdFromBytes(crx.crxId);
    const key = crx.publicKeys.find((k) => extensionIdFromKey(k) === want);
    if (!key) throw new Error(`no public key in the CRX header matches id ${want}`);
    return key;
  }
  if (crx.publicKeys.length === 1) return crx.publicKeys[0]!;
  throw new Error("CRX has no signed id and several keys");
}
