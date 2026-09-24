// The parts of an X.509 certificate the emulated CAdESCOM.Certificate reports.
import { children, decodeOid, decodeTime, expectTag, hex, read } from "./asn1.ts";
import { parseName, type Name } from "./dn.ts";
import { sha1 } from "./sha1.ts";

export interface X509 {
  der: Uint8Array;
  version: number;
  // Hex, upper case, as the DER integer is written (leading zero byte kept if present).
  serialNumber: string;
  issuer: Name;
  subject: Name;
  notBefore: Date;
  notAfter: Date;
  publicKeyAlgorithm: string;
  // From the private key usage period extension (2.5.29.16); null when absent.
  privateKeyNotBefore: Date | null;
  privateKeyNotAfter: Date | null;
  // The key usage extension (2.5.29.15) as CAPICOM's flags: the bit string's first byte, then its second byte
  // shifted left by 8 (CAPICOM_DIGITAL_SIGNATURE_KEY_USAGE is 128, decipherOnly 0x8000); null when absent.
  keyUsage: number | null;
  thumbprint: string;
  // For checking signatures and chains: the signed part with its algorithm and signature (the BIT STRING's
  // bits), the names as encoded, the key's parameter set (the first OID of its parameters, null without
  // one) and the subjectPublicKey BIT STRING's bits.
  tbs: Uint8Array;
  signatureAlgorithm: string;
  signature: Uint8Array;
  issuerDer: Uint8Array;
  subjectDer: Uint8Array;
  publicKeyParameters: string | null;
  publicKey: Uint8Array;
}

// Friendly names CryptoPro gives the GOST public key algorithms; other algorithms show their OID.
const algorithmNames = new Map<string, string>([
  ["1.2.643.2.2.19", "ГОСТ Р 34.10-2001"],
  ["1.2.643.7.1.1.1.1", "ГОСТ Р 34.10-2012 256 бит"],
  ["1.2.643.7.1.1.1.2", "ГОСТ Р 34.10-2012 512 бит"],
]);

export function algorithmName(oid: string): string {
  return algorithmNames.get(oid) ?? oid;
}

export function pemToDer(pem: string): Uint8Array {
  const body = pem.replace(/-----(BEGIN|END) [A-Z ]+-----/g, "").replace(/\s+/g, "");
  return Uint8Array.from(atob(body), (char) => char.charCodeAt(0));
}

export function derToBase64(der: Uint8Array): string {
  let binary = "";
  for (const byte of der) binary += String.fromCharCode(byte);
  return btoa(binary);
}

// The value (the OCTET STRING's content) of the extension with this OID, if the certificate has it.
function extensionValue(extensions: ReturnType<typeof read> | undefined, oid: string): Uint8Array | undefined {
  if (!extensions) return undefined;
  for (const extension of children(expectTag(children(extensions)[0], 0x30, "Extensions"))) {
    const parts = children(extension);
    if (decodeOid(expectTag(parts[0], 0x06, "extension id").value) !== oid) continue;
    return expectTag(parts[parts.length - 1], 0x04, "extension value").value;
  }
  return undefined;
}

function privateKeyUsagePeriod(extensions: ReturnType<typeof read> | undefined): [Date | null, Date | null] {
  const value = extensionValue(extensions, "2.5.29.16");
  if (!value) return [null, null];
  let from: Date | null = null;
  let to: Date | null = null;
  for (const field of children(expectTag(read(value), 0x30, "PrivateKeyUsagePeriod"))) {
    if (field.tag === 0x80) from = decodeTime(field);
    else if (field.tag === 0x81) to = decodeTime(field);
  }
  return [from, to];
}

function keyUsage(extensions: ReturnType<typeof read> | undefined): number | null {
  const value = extensionValue(extensions, "2.5.29.15");
  if (!value) return null;
  // BIT STRING content: the count of unused bits, then the bits.
  const bits = expectTag(read(value), 0x03, "KeyUsage").value;
  return (bits[1] ?? 0) | ((bits[2] ?? 0) << 8);
}

export function parseCertificate(der: Uint8Array): X509 {
  const certificate = expectTag(read(der), 0x30, "Certificate");
  const [tbsNode, signatureAlgorithm, signature] = children(certificate);
  const tbs = children(expectTag(tbsNode, 0x30, "TBSCertificate"));
  // version [0] EXPLICIT is optional (v1 certificates omit it); the rest is positional.
  const hasVersion = tbs[0]?.tag === 0xa0;
  const version = hasVersion ? children(tbs[0]!)[0]!.value[0]! + 1 : 1;
  const [serial, , issuer, validity, subject, spki, ...rest] = hasVersion ? tbs.slice(1) : tbs;
  const [notBefore, notAfter] = children(expectTag(validity, 0x30, "Validity"));
  const [keyAlgorithm, keyBits] = children(expectTag(spki, 0x30, "SubjectPublicKeyInfo"));
  const [algorithm, parameters] = children(expectTag(keyAlgorithm, 0x30, "AlgorithmIdentifier"));
  const parameterSet = parameters?.tag === 0x30 ? children(parameters)[0] : undefined;
  const extensions = rest.find((node) => node.tag === 0xa3);
  const [privateKeyNotBefore, privateKeyNotAfter] = privateKeyUsagePeriod(extensions);
  return {
    der,
    version,
    serialNumber: hex(expectTag(serial, 0x02, "serialNumber").value),
    issuer: parseName(issuer!),
    subject: parseName(subject!),
    notBefore: decodeTime(notBefore!),
    notAfter: decodeTime(notAfter!),
    publicKeyAlgorithm: decodeOid(expectTag(algorithm, 0x06, "algorithm").value),
    privateKeyNotBefore,
    privateKeyNotAfter,
    keyUsage: keyUsage(extensions),
    thumbprint: hex(sha1(der)),
    tbs: tbsNode!.der,
    signatureAlgorithm: decodeOid(expectTag(children(expectTag(signatureAlgorithm, 0x30, "signatureAlgorithm"))[0], 0x06, "algorithm").value),
    signature: expectTag(signature, 0x03, "signatureValue").value.subarray(1),
    issuerDer: issuer!.der,
    subjectDer: subject!.der,
    publicKeyParameters: parameterSet?.tag === 0x06 ? decodeOid(parameterSet.value) : null,
    publicKey: expectTag(keyBits, 0x03, "subjectPublicKey").value.subarray(1),
  };
}
