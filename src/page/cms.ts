// CMS SignedData (RFC 5652) taken apart and its signers checked in the page, for CadesSignedData's
// VerifyCades and VerifyHash. DER, and the BER indefinite lengths some producers write.
import { children, decodeOid, decodeTime, expectTag, octets, read, type Node } from "./asn1.ts";
import { digest, digestOids, verifyHash, type DigestName } from "./gost.ts";
import { parseCertificate, type X509 } from "./x509.ts";

const SIGNED_DATA = "1.2.840.113549.1.7.2";
export const ATTRIBUTE_CONTENT_TYPE = "1.2.840.113549.1.9.3";
export const ATTRIBUTE_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
export const ATTRIBUTE_SIGNING_TIME = "1.2.840.113549.1.9.5";
export const ATTRIBUTE_SIGNING_CERTIFICATE = "1.2.840.113549.1.9.16.2.12";
export const ATTRIBUTE_SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.47";
export const ATTRIBUTE_SIGNATURE_TIMESTAMP = "1.2.840.113549.1.9.16.2.14";
export const ATTRIBUTE_CERTIFICATE_REFS = "1.2.840.113549.1.9.16.2.21";
export const ATTRIBUTE_REVOCATION_REFS = "1.2.840.113549.1.9.16.2.22";

export interface SignerInfo {
  // The signer's certificate by issuer and serial number (DER of the Name, the serial number's bytes), or by key id.
  issuer?: Uint8Array;
  serial?: Uint8Array;
  keyId?: Uint8Array;
  digestAlgorithm: string;
  // DER of the signed attributes as they are signed (a SET, not the [0] of SignerInfo), and each one's values.
  signedAttributesDer?: Uint8Array;
  signedAttributes: Map<string, Node[]>;
  unsignedAttributes: Map<string, Node[]>;
  signature: Uint8Array;
}

export interface SignedData {
  contentType: string;
  // The encapsulated content; undefined for a detached signature.
  content?: Uint8Array;
  certificates: X509[];
  signers: SignerInfo[];
}

function attributes(node: Node): Map<string, Node[]> {
  const result = new Map<string, Node[]>();
  for (const attribute of children(node)) {
    const [type, values] = children(expectTag(attribute, 0x30, "Attribute"));
    result.set(decodeOid(expectTag(type, 0x06, "attrType").value), children(expectTag(values, 0x31, "attrValues")));
  }
  return result;
}

function signerInfo(node: Node): SignerInfo {
  const fields = children(expectTag(node, 0x30, "SignerInfo"));
  const [, sid, digestAlgorithm] = fields;
  let rest = fields.slice(3);
  const info: SignerInfo = {
    digestAlgorithm: decodeOid(expectTag(children(expectTag(digestAlgorithm, 0x30, "digestAlgorithm"))[0], 0x06, "algorithm").value),
    signedAttributes: new Map(),
    unsignedAttributes: new Map(),
    signature: new Uint8Array(),
  };
  if (sid?.tag === 0x30) {
    const [issuer, serial] = children(sid);
    info.issuer = expectTag(issuer, 0x30, "issuer").der;
    info.serial = expectTag(serial, 0x02, "serialNumber").value;
  } else {
    info.keyId = expectTag(sid, 0x80, "subjectKeyIdentifier").value;
  }
  if (rest[0]?.tag === 0xa0) {
    const signed = rest[0];
    info.signedAttributes = attributes(signed);
    // Signed as a SET OF: the same bytes with the universal tag in place of [0].
    info.signedAttributesDer = Uint8Array.from(signed.der);
    info.signedAttributesDer[0] = 0x31;
    rest = rest.slice(1);
  }
  info.signature = octets(rest[1]!);
  if (rest[2]?.tag === 0xa1) info.unsignedAttributes = attributes(rest[2]);
  return info;
}

// Throws on anything that is not a CMS SignedData.
export function parseSignedData(der: Uint8Array): SignedData {
  const [type, explicit] = children(expectTag(read(der), 0x30, "ContentInfo"));
  if (decodeOid(expectTag(type, 0x06, "contentType").value) !== SIGNED_DATA) throw new Error("CMS: not a SignedData");
  const fields = children(expectTag(children(expectTag(explicit, 0xa0, "content"))[0], 0x30, "SignedData"));
  const [encapsulated, ...rest] = fields.slice(2);
  const [contentType, content] = children(expectTag(encapsulated, 0x30, "EncapsulatedContentInfo"));
  const certificates: X509[] = [];
  let infos: Node | undefined;
  for (const field of rest) {
    if (field.tag === 0xa0) {
      for (const certificate of children(field)) {
        // Only X.509 certificates; attribute and other certificate choices are skipped.
        if (certificate.tag === 0x30) certificates.push(parseCertificate(Uint8Array.from(certificate.der)));
      }
    } else if (field.tag === 0x31) {
      infos = field;
    }
  }
  return {
    contentType: decodeOid(expectTag(contentType, 0x06, "eContentType").value),
    content: content && octets(children(expectTag(content, 0xa0, "eContent"))[0]!),
    certificates,
    signers: children(expectTag(infos, 0x31, "signerInfos")).map(signerInfo),
  };
}

function same(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

// The serial number as the DER integer's bytes, for comparing with a SignerInfo's.
function serialBytes(certificate: X509): Uint8Array {
  return Uint8Array.from(certificate.serialNumber.match(/../g) ?? [], (byte) => parseInt(byte, 16));
}

// The subject key identifier extension's value (2.5.29.14), if the certificate has one.
function subjectKeyId(certificate: X509): Uint8Array | undefined {
  const tbs = children(read(certificate.tbs));
  const extensions = tbs.find((node) => node.tag === 0xa3);
  if (!extensions) return undefined;
  for (const extension of children(children(extensions)[0]!)) {
    const parts = children(extension);
    if (decodeOid(parts[0]!.value) === "2.5.29.14") return read(parts[parts.length - 1]!.value).value;
  }
  return undefined;
}

// The signer's certificate among `candidates` (the signature's own, then others the caller knows).
export function findSignerCertificate(info: SignerInfo, candidates: readonly X509[]): X509 | undefined {
  return candidates.find((certificate) =>
    info.keyId ? same(subjectKeyId(certificate) ?? new Uint8Array(), info.keyId) : same(certificate.issuerDer, info.issuer!) && same(serialBytes(certificate), info.serial!),
  );
}

export function signerDigest(info: SignerInfo): DigestName | undefined {
  return digestOids.get(info.digestAlgorithm);
}

export function signingTime(info: SignerInfo): Date | undefined {
  const value = info.signedAttributes.get(ATTRIBUTE_SIGNING_TIME)?.[0];
  return value ? decodeTime(value) : undefined;
}

// What checking one signer found: the message digest attribute does not match the content's hash, or the
// signature does not verify with the certificate's key.
export type SignerCheck = "valid" | "digest-mismatch" | "bad-signature";

// Checks the signer over the content's hash (`hash`, computed with the signer's digest algorithm).
export function checkSigner(info: SignerInfo, certificate: X509, hash: Uint8Array): SignerCheck {
  const name = signerDigest(info);
  if (!name) return "bad-signature";
  if (!info.signedAttributesDer) return verifyHash(certificate, hash, info.signature) ? "valid" : "bad-signature";
  const messageDigest = info.signedAttributes.get(ATTRIBUTE_MESSAGE_DIGEST)?.[0];
  if (!messageDigest || messageDigest.tag !== 0x04 || !same(messageDigest.value, hash)) return "digest-mismatch";
  return verifyHash(certificate, digest(name, info.signedAttributesDer), info.signature) ? "valid" : "bad-signature";
}

// Whether the signing-certificate attribute (v2, or v1 with SHA-1) names this certificate by its hash; true
// without the attribute.
export function signingCertificateMatches(info: SignerInfo, certificate: X509): boolean {
  const v2 = info.signedAttributes.get(ATTRIBUTE_SIGNING_CERTIFICATE_V2)?.[0];
  const v1 = info.signedAttributes.get(ATTRIBUTE_SIGNING_CERTIFICATE)?.[0];
  const attribute = v2 ?? v1;
  if (!attribute) return true;
  const first = children(children(attribute)[0]!)[0];
  if (!first) return false;
  const parts = children(first);
  let name: DigestName | undefined = v2 ? "sha256" : "sha1";
  let hash = parts[0]!;
  if (v2 && parts[0]?.tag === 0x30) {
    name = digestOids.get(decodeOid(children(parts[0])[0]!.value));
    hash = parts[1]!;
  }
  return name !== undefined && hash?.tag === 0x04 && same(hash.value, digest(name, certificate.der));
}
