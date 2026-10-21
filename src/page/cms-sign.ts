// CMS SignedData made in the page, for what the Rutoken Plugin's sign() cannot make: a signature with the site's own
// signed attributes (CPSigner.AuthenticatedAttributes2), whose hash the token signs with rawSign; and the certificate
// chain, put into a signature either way, since the certificates field is not signed (docs/PLAN.md, action 35c). The
// layout follows CryptoPro's signatures (tests/fixtures/verify.json): SignedData and SignerInfo version 1, the signer
// by issuer and serial number, the digest algorithm without parameters, the key's algorithm as the signature
// algorithm, the CAdES-BES attributes contentType, signingTime, messageDigest and signingCertificateV2.
import { children, decodeOid, encode, encodeOid, expectTag, read } from "./asn1.ts";
import { ATTRIBUTE_CONTENT_TYPE, ATTRIBUTE_MESSAGE_DIGEST, ATTRIBUTE_SIGNATURE_TIMESTAMP, ATTRIBUTE_SIGNING_CERTIFICATE_V2, ATTRIBUTE_SIGNING_TIME } from "./cms.ts";
import { digest, type DigestName } from "./gost.ts";
import type { X509 } from "./x509.ts";

const DATA = "1.2.840.113549.1.7.1";
const SIGNED_DATA = "1.2.840.113549.1.7.2";

// The hash each GOST key signs with, as CMS names it.
const keyDigests = new Map<string, { name: DigestName; oid: string }>([
  ["1.2.643.2.2.19", { name: "gost94", oid: "1.2.643.2.2.9" }],
  ["1.2.643.7.1.1.1.1", { name: "streebog256", oid: "1.2.643.7.1.1.2.2" }],
  ["1.2.643.7.1.1.1.2", { name: "streebog512", oid: "1.2.643.7.1.1.2.3" }],
]);

export function keyDigest(signer: X509): { name: DigestName; oid: string } {
  const found = keyDigests.get(signer.publicKeyAlgorithm);
  if (!found) throw new Error(`CMS: no GOST hash for the key ${signer.publicKeyAlgorithm}`);
  return found;
}

const objectId = (oid: string) => encode(0x06, encodeOid(oid));
const algorithm = (oid: string) => encode(0x30, objectId(oid));

export function attribute(type: string, ...values: Uint8Array[]): Uint8Array {
  return encode(0x30, objectId(type), encode(0x31, ...values));
}

// RFC 5652, 11.3: UTCTime for the years 1950–2049, GeneralizedTime for the others; whole seconds.
export function encodeTime(date: Date): Uint8Array {
  const digits = date.toISOString().replace(/\.\d+Z$/, "Z").replace(/[-:T]/g, "");
  const year = date.getUTCFullYear();
  const text = year >= 1950 && year < 2050 ? digits.slice(2) : digits;
  return encode(year >= 1950 && year < 2050 ? 0x17 : 0x18, new TextEncoder().encode(text));
}

// X.690, 11.6: a SET OF's elements in the order of their encodings, the shorter padded with zeros.
function setOf(tag: number, elements: Uint8Array[]): Uint8Array {
  const sorted = [...elements].sort((a, b) => {
    for (let i = 0; i < Math.max(a.length, b.length); i++) {
      const difference = (a[i] ?? 0) - (b[i] ?? 0);
      if (difference) return difference;
    }
    return 0;
  });
  return encode(tag, ...sorted);
}

function serialInteger(certificate: X509): Uint8Array {
  return encode(0x02, Uint8Array.from(certificate.serialNumber.match(/../g) ?? [], (pair) => parseInt(pair, 16)));
}

// signingCertificateV2 (RFC 5035): the certificate's hash with the signer's hash, and its issuer and serial number.
function signingCertificateV2(signer: X509): Uint8Array {
  const { name, oid } = keyDigest(signer);
  const issuerSerial = encode(0x30, encode(0x30, encode(0xa4, signer.issuerDer)), serialInteger(signer));
  const essCertId = encode(0x30, algorithm(oid), encode(0x04, digest(name, signer.der)), issuerSerial);
  return attribute(ATTRIBUTE_SIGNING_CERTIFICATE_V2, encode(0x30, encode(0x30, essCertId)));
}

export function attributeType(element: Uint8Array): string {
  const [type] = children(expectTag(read(element), 0x30, "Attribute"));
  return decodeOid(expectTag(type, 0x06, "attrType").value);
}

export interface AttributesInput {
  signer: X509;
  // The content's hash: computed from the data, or the one the site gave (SignHash).
  messageDigest: Uint8Array;
  signingTime: Date;
  // The site's attributes, each a DER Attribute; one of type signingTime replaces the one made of `signingTime`.
  extra: Uint8Array[];
}

// The signed attributes as a DER SET: what the token signs the hash of, and, with its tag changed to [0], what goes
// into the SignerInfo.
export function signedAttributes({ signer, messageDigest, signingTime, extra }: AttributesInput): Uint8Array {
  const ownTime = !extra.some((element) => attributeType(element) === ATTRIBUTE_SIGNING_TIME);
  return setOf(0x31, [
    attribute(ATTRIBUTE_CONTENT_TYPE, objectId(DATA)),
    ...(ownTime ? [attribute(ATTRIBUTE_SIGNING_TIME, encodeTime(signingTime))] : []),
    attribute(ATTRIBUTE_MESSAGE_DIGEST, encode(0x04, messageDigest)),
    signingCertificateV2(signer),
    ...extra,
  ]);
}

export interface SignedDataInput {
  signer: X509;
  // As signedAttributes() made them.
  signedAttributes: Uint8Array;
  // s||r, as rawSign gives it and CMS has it.
  signature: Uint8Array;
  // The data, for an attached signature.
  content?: Uint8Array;
  certificates: X509[];
  // A CAdES-T signature's timestamp token (a CMS ContentInfo).
  timestamp?: Uint8Array;
}

export function signerInfo({ signer, signedAttributes, signature, timestamp }: SignedDataInput): Uint8Array {
  const { oid } = keyDigest(signer);
  const signed = Uint8Array.from(signedAttributes);
  signed[0] = 0xa0;
  return encode(
    0x30,
    encode(0x02, Uint8Array.of(1)),
    encode(0x30, signer.issuerDer, serialInteger(signer)),
    algorithm(oid),
    signed,
    algorithm(signer.publicKeyAlgorithm),
    encode(0x04, signature),
    ...(timestamp ? [encode(0xa1, attribute(ATTRIBUTE_SIGNATURE_TIMESTAMP, timestamp))] : []),
  );
}

// The ContentInfo of a SignedData with one signer.
export function signedData(input: SignedDataInput): Uint8Array {
  const { oid } = keyDigest(input.signer);
  const encapsulated = encode(0x30, objectId(DATA), ...(input.content ? [encode(0xa0, encode(0x04, input.content))] : []));
  const certificates = input.certificates.length ? [encode(0xa0, ...input.certificates.map((certificate) => certificate.der))] : [];
  const body = encode(0x30, encode(0x02, Uint8Array.of(1)), encode(0x31, algorithm(oid)), encapsulated, ...certificates, encode(0x31, signerInfo(input)));
  return encode(0x30, objectId(SIGNED_DATA), encode(0xa0, body));
}

function same(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

// A SignedData (as the Rutoken Plugin's sign() makes it) with `certificates` added to those it carries, after them;
// the rest of it byte for byte.
export function withCertificates(cms: Uint8Array, certificates: X509[]): Uint8Array {
  const [type, explicit] = children(expectTag(read(cms), 0x30, "ContentInfo"));
  const fields = children(expectTag(children(expectTag(explicit, 0xa0, "content"))[0], 0x30, "SignedData"));
  const present = fields.find((field) => field.tag === 0xa0);
  const carried = present ? children(present).map((certificate) => certificate.der) : [];
  const added = certificates.map((certificate) => certificate.der).filter((der) => !carried.some((other) => same(other, der)));
  if (!added.length) return cms;
  const field = encode(0xa0, ...carried, ...added);
  // The certificates go after the encapsulated content, the third field, when the signature had none.
  const rebuilt = present ? fields.map((node) => (node === present ? field : node.der)) : [...fields.slice(0, 3).map((node) => node.der), field, ...fields.slice(3).map((node) => node.der)];
  return encode(0x30, type!.der, encode(0xa0, encode(0x30, ...rebuilt)));
}
