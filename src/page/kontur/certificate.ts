// A certificate as Kontur.Plugin's host answers it in cert.search, cert.parse and the containers (docs/JOURNAL.md,
// 2026-11-19): only the properties asked for, the hash always; names as arrays of {short name: value}; dates in ISO
// 8601; the extensions it decodes by name, the rest by OID as the extnValue in Base64.
import { children, decodeOid, read } from "../asn1.ts";
import type { Name } from "../dn.ts";
import { certificateKey } from "../objects/certificate.ts";
import type { X509 } from "../x509.ts";
import { isQualified } from "./qualified.ts";
import { toBase64 } from "./streams.ts";

// The host's short names; any other attribute goes by its OID (checked on the host with every one of these and seven
// others).
const SHORT_NAMES: Record<string, string> = {
  "2.5.4.6": "C",
  "2.5.4.8": "S",
  "2.5.4.7": "L",
  "2.5.4.9": "STREET",
  "2.5.4.10": "O",
  "2.5.4.11": "OU",
  "2.5.4.12": "T",
  "2.5.4.4": "SN",
  "2.5.4.42": "G",
  "2.5.4.43": "I",
  "2.5.4.3": "CN",
  "1.2.840.113549.1.9.1": "E",
  "1.2.643.100.1": "ОГРН",
  "1.2.643.100.3": "СНИЛС",
  "1.2.643.100.4": "ИННЮЛ",
  "1.2.643.100.5": "ОГРНИП",
  "1.2.643.3.131.1.1": "ИНН",
};

export function names(name: Name): Record<string, string>[] {
  return name.flat().map((attribute) => ({ [SHORT_NAMES[attribute.oid] ?? attribute.oid]: attribute.value }));
}

// ISO 8601 as the host writes it: seconds, and milliseconds only when the time has them.
export function isoTime(date: Date): string {
  return date.toISOString().replace(/\.000Z$/, "Z");
}

const KEY_USAGES = ["digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment", "keyAgreement", "keyCertSign", "crlSign", "encipherOnly", "decipherOnly"];

// The host's reading of the key usage bits, kept as it is: the bits counted from the first one set, which it calls
// digitalSignature, the next one nonRepudiation and so on. It agrees with RFC 5280 whenever digitalSignature is set,
// as in end-entity and most CA certificates, and not otherwise: keyCertSign with cRLSign reads as digitalSignature
// with nonRepudiation (fourteen bit sets checked on the host, docs/JOURNAL.md, 2026-11-19).
export function keyUsages(value: Uint8Array): Record<string, true> {
  const bits = read(value).value.subarray(1);
  const set: number[] = [];
  bits.forEach((byte, index) => {
    for (let bit = 0; bit < 8; bit++) if (byte & (0x80 >> bit)) set.push(index * 8 + bit);
  });
  const result: Record<string, true> = {};
  const first = set[0] ?? 0;
  for (const position of set) if (position - first < KEY_USAGES.length) result[KEY_USAGES[position - first]!] = true;
  return result;
}

function extendedKeyUsages(value: Uint8Array): Record<string, true> {
  return Object.fromEntries(children(read(value)).map((node) => [decodeOid(node.value), true as const]));
}

function policies(value: Uint8Array): Record<string, Record<string, never>> {
  return Object.fromEntries(children(read(value)).map((policy) => [decodeOid(children(policy)[0]!.value), {}]));
}

function privateKeyUsagePeriod(x509: X509): Record<string, string> {
  const period: Record<string, string> = {};
  if (x509.privateKeyNotAfter) period.notAfter = isoTime(x509.privateKeyNotAfter);
  if (x509.privateKeyNotBefore) period.notBefore = isoTime(x509.privateKeyNotBefore);
  return period;
}

function integer(value: Uint8Array): number {
  return read(value).value.reduce((sum, byte) => sum * 256 + byte, 0);
}

export function extensions(x509: X509): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const extension of x509.extensions) {
    try {
      switch (extension.oid) {
        case "2.5.29.15":
          result.keyUsages = keyUsages(extension.value);
          continue;
        case "2.5.29.37":
          result.extendedKeyUsages = extendedKeyUsages(extension.value);
          continue;
        case "2.5.29.16":
          result.privateKeyUsagePeriod = privateKeyUsagePeriod(x509);
          continue;
        case "2.5.29.32":
          result.policies = policies(extension.value);
          continue;
        case "1.2.643.100.114":
          result.identificationKind = integer(extension.value);
          continue;
      }
    } catch {
      // A malformed one goes by its OID, as an unknown one.
    }
    result[extension.oid] = { data: toBase64(extension.value), size: extension.value.length, type: "base64" };
  }
  return result;
}

// Where a certificate on a token is: its slot (the reader) and the token's model, as the host names them.
export interface TokenPlace {
  slot: string;
  token: string;
  // Seen through CryptoAPI instead (cryptopro.ts): the emulated CryptoPro provider and container.
  cryptoApi?: { provider: Record<string, unknown>; containerName: string };
}

// The properties a request asks for: those set to true.
export function wanted(properties: unknown): Set<string> {
  if (typeof properties !== "object" || properties === null || Array.isArray(properties)) return new Set();
  return new Set(Object.entries(properties).filter(([, on]) => on === true).map(([name]) => name));
}

const hexOf = (text: string) => text.toLowerCase();

export function certificateFields(x509: X509, asked: Set<string>, place?: TokenPlace): Record<string, unknown> {
  const fields: Record<string, unknown> = { hash: { data: hexOf(x509.thumbprint), size: 20, type: "hex" } };
  const provider = place ? (place.cryptoApi?.provider ?? { slot: place.slot, token: place.token, type: "pkcs11" }) : undefined;
  for (const name of asked) {
    switch (name) {
      case "content":
        fields.content = { data: toBase64(x509.der), size: x509.der.length, type: "base64" };
        break;
      case "serialNumber":
        fields.serialNumber = { data: hexOf(x509.serialNumber), size: x509.serialNumber.length / 2, type: "hex" };
        break;
      case "subject":
        fields.subject = names(x509.subject);
        break;
      case "issuer":
        fields.issuer = names(x509.issuer);
        break;
      case "validFrom":
        fields.validFrom = isoTime(x509.notBefore);
        break;
      case "validTo":
        fields.validTo = isoTime(x509.notAfter);
        break;
      case "hasPrivateKey":
        fields.hasPrivateKey = place !== undefined;
        break;
      case "qualified":
        fields.qualified = isQualified(x509);
        break;
      case "extensions":
        fields.extensions = extensions(x509);
        break;
      case "cryptoProvider":
        fields.cryptoProvider = provider ?? {};
        break;
      case "containerInfo":
        fields.containerInfo = provider ? { containerName: place?.cryptoApi?.containerName ?? containerName(x509), provider } : {};
        break;
      case "publicKeyLength":
        fields.publicKeyLength = certificateKey(x509).length;
        break;
      case "publicKeyAlgorithm":
        fields.publicKeyAlgorithm = x509.publicKeyAlgorithm;
        break;
    }
  }
  return fields;
}

// The host names a container "_HEX__" and its key's CKA_ID, which the Rutoken Plugin gives only after a login; here
// the certificate's thumbprint stands for it, as for the other plug-ins (CLAUDE.md).
export function containerName(x509: X509): string {
  return `_HEX__${hexOf(x509.thumbprint)}`;
}
