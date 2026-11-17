// IFCPlugin's req_gen: a PKCS#10 request built in the page, as the core builds it (docs/JOURNAL.md, 2026-11-17): the
// subject with the string types the site names, an extension request with the fixed key usage, the site's extended
// key usages, policies, signing tool and its own extensions, signed by the token's rawSign. The Rutoken Plugin's
// createPkcs10 cannot add the signing tool or other extensions, so it only lends the request its public key.
import { children, encode, encodeOid, read } from "../asn1.ts";

export interface SubjectEntry {
  oid: string;
  // The ASN.1 string tag: 12 UTF8String, 19 PrintableString, 22 IA5String, 18 NumericString, 30 BMPString.
  type: number;
  value: string;
}

const seq = (...parts: Uint8Array[]) => encode(0x30, ...parts);
const oid = (dotted: string) => encode(0x06, encodeOid(dotted));
const utf8 = (text: string) => new TextEncoder().encode(text);
const ascii = (text: string) => Uint8Array.from(Array.from(text, (char) => char.charCodeAt(0) & 0xff));

function stringValue(type: number, value: string): Uint8Array {
  switch (type) {
    case 19:
    case 22:
    case 18:
    case 26:
      return encode(type, ascii(value));
    case 30:
      return encode(0x1e, Uint8Array.from(Array.from(value).flatMap((char) => [char.charCodeAt(0) >> 8, char.charCodeAt(0) & 0xff])));
    default:
      return encode(0x0c, utf8(value));
  }
}

export function encodeSubject(entries: SubjectEntry[]): Uint8Array {
  return seq(...entries.map((entry) => encode(0x31, seq(oid(entry.oid), stringValue(entry.type, entry.value)))));
}

export function extension(id: string, value: Uint8Array, critical = false): Uint8Array {
  return seq(oid(id), ...(critical ? [encode(0x01, Uint8Array.of(0xff))] : []), encode(0x04, value));
}

// digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment: what the core always asks for.
export const KEY_USAGE = extension("2.5.29.15", encode(0x03, Uint8Array.of(0x04, 0xf0)));

export const extendedKeyUsage = (oids: string[]) => extension("2.5.29.37", seq(...oids.map(oid)));
export const certificatePolicies = (oids: string[]) => extension("2.5.29.32", seq(...oids.map((policy) => seq(oid(policy)))));
export const signingTool = (text: string) => extension("1.2.643.100.111", encode(0x0c, utf8(text)));

// One value of OpenSSL's extension configuration syntax, as the core hands csrExtensions to X509V3_EXT_nconf; the
// common generic forms only. Undefined for what is not understood (the core answers 1 then).
export function nconfExtension(id: string, text: string): Uint8Array | undefined {
  let rest = text.trim();
  let critical = false;
  if (/^critical\s*,/.test(rest)) {
    critical = true;
    rest = rest.replace(/^critical\s*,\s*/, "");
  }
  const der = /^DER:([0-9A-Fa-f:]+)$/.exec(rest);
  if (der) {
    const hex = der[1]!.replace(/:/g, "");
    if (hex.length % 2) return undefined;
    return extension(id, Uint8Array.from(hex.match(/../g)!, (pair) => parseInt(pair, 16)), critical);
  }
  const match = /^ASN1:([A-Za-z0-9]+)(?::([\s\S]*))?$/.exec(rest);
  if (!match) return undefined;
  const kind = match[1]!.toUpperCase();
  const value = match[2] ?? "";
  let encoded: Uint8Array | undefined;
  if (kind === "UTF8" || kind === "UTF8STRING") encoded = encode(0x0c, utf8(value));
  else if (kind === "PRINTABLE" || kind === "PRINTABLESTRING") encoded = encode(0x13, ascii(value));
  else if (kind === "IA5" || kind === "IA5STRING") encoded = encode(0x16, ascii(value));
  else if (kind === "BMP" || kind === "BMPSTRING") encoded = stringValue(30, value);
  else if (kind === "NULL") encoded = encode(0x05);
  else if (kind === "BOOL" || kind === "BOOLEAN") encoded = /^(TRUE|true|Y|y|YES|yes)$/.test(value) ? encode(0x01, Uint8Array.of(0xff)) : /^(FALSE|false|N|n|NO|no)$/.test(value) ? encode(0x01, Uint8Array.of(0)) : undefined;
  else if (kind === "OID" || kind === "OBJECT") encoded = /^\d+(\.\d+)+$/.test(value) ? oid(value) : undefined;
  else if (kind === "INT" || kind === "INTEGER") {
    const number = /^0x[0-9a-f]+$/i.test(value) ? BigInt(value) : /^\d+$/.test(value) ? BigInt(value) : undefined;
    if (number !== undefined) {
      let hex = number.toString(16);
      if (hex.length % 2) hex = `0${hex}`;
      if (parseInt(hex.slice(0, 2), 16) >= 0x80) hex = `00${hex}`;
      encoded = encode(0x02, Uint8Array.from(hex.match(/../g)!, (pair) => parseInt(pair, 16)));
    }
  }
  return encoded && extension(id, encoded, critical);
}

// The SubjectPublicKeyInfo of a request (the Rutoken Plugin's, PEM or DER).
export function requestPublicKey(der: Uint8Array): Uint8Array {
  const [info] = children(read(der));
  return children(info!)[2]!.der;
}

export function requestInfo(subject: Uint8Array, publicKey: Uint8Array, extensions: Uint8Array[]): Uint8Array {
  const extensionRequest = seq(oid("1.2.840.113549.1.9.14"), encode(0x31, seq(...extensions)));
  return seq(encode(0x02, Uint8Array.of(0)), subject, publicKey, encode(0xa0, extensionRequest));
}

// The request: the info, GOST R 34.10-2012 with GOST R 34.11-2012 of the key's size, with NULL parameters as the
// core writes them, and the signature.
export function signedRequest(info: Uint8Array, signatureAlgorithm: string, signature: Uint8Array): Uint8Array {
  return seq(info, seq(oid(signatureAlgorithm), encode(0x05)), encode(0x03, Uint8Array.of(0), signature));
}
