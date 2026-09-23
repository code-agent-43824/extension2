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
  thumbprint: string;
}

export function pemToDer(pem: string): Uint8Array {
  const body = pem.replace(/-----(BEGIN|END) [A-Z ]+-----/g, "").replace(/\s+/g, "");
  return Uint8Array.from(atob(body), (char) => char.charCodeAt(0));
}

function privateKeyUsagePeriod(extensions: ReturnType<typeof read> | undefined): [Date | null, Date | null] {
  if (!extensions) return [null, null];
  for (const extension of children(expectTag(children(extensions)[0], 0x30, "Extensions"))) {
    const parts = children(extension);
    if (decodeOid(expectTag(parts[0], 0x06, "extension id").value) !== "2.5.29.16") continue;
    const value = expectTag(parts[parts.length - 1], 0x04, "extension value").value;
    let from: Date | null = null;
    let to: Date | null = null;
    for (const field of children(expectTag(read(value), 0x30, "PrivateKeyUsagePeriod"))) {
      if (field.tag === 0x80) from = decodeTime(field);
      else if (field.tag === 0x81) to = decodeTime(field);
    }
    return [from, to];
  }
  return [null, null];
}

export function parseCertificate(der: Uint8Array): X509 {
  const certificate = expectTag(read(der), 0x30, "Certificate");
  const tbs = children(expectTag(children(certificate)[0], 0x30, "TBSCertificate"));
  // version [0] EXPLICIT is optional (v1 certificates omit it); the rest is positional.
  const hasVersion = tbs[0]?.tag === 0xa0;
  const version = hasVersion ? children(tbs[0]!)[0]!.value[0]! + 1 : 1;
  const [serial, , issuer, validity, subject, spki, ...rest] = hasVersion ? tbs.slice(1) : tbs;
  const [notBefore, notAfter] = children(expectTag(validity, 0x30, "Validity"));
  const algorithm = children(expectTag(children(expectTag(spki, 0x30, "SubjectPublicKeyInfo"))[0], 0x30, "AlgorithmIdentifier"))[0];
  const [privateKeyNotBefore, privateKeyNotAfter] = privateKeyUsagePeriod(rest.find((node) => node.tag === 0xa3));
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
    thumbprint: hex(sha1(der)),
  };
}
