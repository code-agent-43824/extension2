// XAdES-BES and XAdES-T on top of the page's XMLDSig (src/page/objects/signed-xml.ts), after ETSI TS 101 903 v1.3.2
// (docs/PLAN.md, action 26). A ds:Object holds xades:QualifyingProperties aimed at the signature; its SignedProperties
// (the signing time; the signing certificate as its digest, issuer and serial number) are covered by a Reference of
// the SignedProperties type; XAdES-T adds a SignatureTimeStamp over the canonical SignatureValue as an unsigned
// property. No signature of CryptoPro's plug-in was at hand to copy: the criterion is that it verifies (the owner,
// 2026-09-23). SigningCertificate rather than EN 319 132's SigningCertificateV2: CryptoPro's own verification takes
// either (XadesGetSigningCertId, docs.cryptopro.ru), older verifiers only the first.
import { rfc4514 } from "../dn.ts";
import type { X509 } from "../x509.ts";

export const XADES = "http://uri.etsi.org/01903/v1.3.2#";
const SIGNED_PROPERTIES_TYPE = "http://uri.etsi.org/01903#SignedProperties";
const DS = "http://www.w3.org/2000/09/xmldsig#";
const XMLNS = "http://www.w3.org/2000/xmlns/";
const EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#";

function ds(signature: Element, localName: string): Element {
  return signature.ownerDocument.createElementNS(DS, signature.prefix ? `${signature.prefix}:${localName}` : localName);
}

function dsChild(parent: Element, localName: string): Element | undefined {
  return Array.from(parent.children).find((element) => element.namespaceURI === DS && element.localName === localName);
}

function xadesChild(parent: Element, localName: string): Element | undefined {
  return Array.from(parent.children).find((element) => element.namespaceURI === parent.namespaceURI && element.localName === localName);
}

// Elements in the namespace and with the prefix of `like`.
function sibling(like: Element, localName: string): Element {
  return like.ownerDocument.createElementNS(like.namespaceURI, like.prefix ? `${like.prefix}:${localName}` : localName);
}

function withText(element: Element, text: string): Element {
  element.textContent = text;
  return element;
}

function append(parent: Element, ...nodes: Element[]): Element {
  for (const node of nodes) parent.appendChild(node);
  return parent;
}

// The serial number as XMLDSig writes it, a decimal integer; DER's two's complement, though RFC 5280 wants it positive.
function decimalSerial(certificate: X509): string {
  const hex = certificate.serialNumber;
  const value = BigInt(`0x${hex}`);
  return (parseInt(hex.slice(0, 2), 16) & 0x80 ? value - (1n << BigInt(hex.length * 4)) : value).toString();
}

// The signature's own xades:QualifyingProperties, in one of its ds:Object elements.
export function qualifyingProperties(signature: Element): Element | undefined {
  for (const object of Array.from(signature.children)) {
    if (object.namespaceURI !== DS || object.localName !== "Object") continue;
    const found = Array.from(object.children).find((element) => element.namespaceURI === XADES && element.localName === "QualifyingProperties");
    if (found) return found;
  }
  return undefined;
}

export interface XadesIds {
  // For a signature without an Id of its own (a template's).
  signature: string;
  signedProperties: string;
}

// Adds the qualifying properties and the Reference covering them, the SigningTime left empty for fillSigningTime, and
// answers the signature's Id. A template that brings its own QualifyingProperties keeps them. `certificateDigest` is
// the certificate's digest under `digestMethod`.
export function addQualifyingProperties(signature: Element, ids: XadesIds, certificate: X509, digestMethod: string, certificateDigest: string): string {
  if (!signature.getAttribute("Id")) signature.setAttribute("Id", ids.signature);
  const id = signature.getAttribute("Id")!;
  if (qualifyingProperties(signature)) return id;
  const doc = signature.ownerDocument;
  const signedInfo = dsChild(signature, "SignedInfo")!;
  const reference = ds(signature, "Reference");
  reference.setAttribute("Type", SIGNED_PROPERTIES_TYPE);
  reference.setAttribute("URI", `#${ids.signedProperties}`);
  const transform = ds(signature, "Transform");
  transform.setAttribute("Algorithm", EXC_C14N);
  const referenceDigest = ds(signature, "DigestMethod");
  referenceDigest.setAttribute("Algorithm", digestMethod);
  append(reference, append(ds(signature, "Transforms"), transform), referenceDigest, ds(signature, "DigestValue"));
  signedInfo.appendChild(reference);
  signedInfo.appendChild(doc.createTextNode("\n"));

  const properties = doc.createElementNS(XADES, "xades:QualifyingProperties");
  properties.setAttributeNS(XMLNS, "xmlns:xades", XADES);
  properties.setAttribute("Target", `#${id}`);
  const x = (localName: string) => sibling(properties, localName);
  const signed = x("SignedProperties");
  signed.setAttribute("Id", ids.signedProperties);
  const certDigest = ds(signature, "DigestMethod");
  certDigest.setAttribute("Algorithm", digestMethod);
  const cert = append(
    x("Cert"),
    append(x("CertDigest"), certDigest, withText(ds(signature, "DigestValue"), certificateDigest)),
    append(x("IssuerSerial"), withText(ds(signature, "X509IssuerName"), rfc4514(certificate.issuerDer)), withText(ds(signature, "X509SerialNumber"), decimalSerial(certificate))),
  );
  append(properties, append(signed, append(x("SignedSignatureProperties"), x("SigningTime"), append(x("SigningCertificate"), cert))));
  signature.appendChild(append(ds(signature, "Object"), properties));
  signature.appendChild(doc.createTextNode("\n"));
  return id;
}

// The signing time, in UTC to the second, into each empty SigningTime of the signature's qualifying properties.
export function fillSigningTime(signature: Element, when: Date): void {
  const properties = qualifyingProperties(signature);
  if (!properties) return;
  for (const time of Array.from(properties.getElementsByTagNameNS(XADES, "SigningTime"))) {
    if (!time.textContent?.trim()) time.textContent = when.toISOString().replace(/\.\d{3}Z$/, "Z");
  }
}

// XAdES-T: the timestamp token (base64 of a CMS ContentInfo) as a SignatureTimeStamp whose canonicalization, the one
// its imprint was computed with, is exclusive C14N.
export function addSignatureTimeStamp(signature: Element, token: string, id: string): void {
  const properties = qualifyingProperties(signature)!;
  let unsigned = xadesChild(properties, "UnsignedProperties");
  if (!unsigned) unsigned = properties.appendChild(sibling(properties, "UnsignedProperties"));
  let signatureProperties = xadesChild(unsigned, "UnsignedSignatureProperties");
  if (!signatureProperties) signatureProperties = unsigned.insertBefore(sibling(properties, "UnsignedSignatureProperties"), unsigned.firstElementChild);
  const stamp = sibling(properties, "SignatureTimeStamp");
  stamp.setAttribute("Id", id);
  const canonicalization = ds(signature, "CanonicalizationMethod");
  canonicalization.setAttribute("Algorithm", EXC_C14N);
  append(signatureProperties, append(stamp, canonicalization, withText(sibling(properties, "EncapsulatedTimeStamp"), token)));
}

// The certificate digests of the signature's SigningCertificate: each Cert's DigestMethod and DigestValue (base64).
export function signingCertificateDigests(signature: Element): { method: string; value: string }[] {
  const properties = qualifyingProperties(signature);
  if (!properties) return [];
  return Array.from(properties.getElementsByTagNameNS(XADES, "CertDigest"), (digest) => ({
    method: dsChild(digest, "DigestMethod")?.getAttribute("Algorithm") ?? "",
    value: dsChild(digest, "DigestValue")?.textContent ?? "",
  }));
}
