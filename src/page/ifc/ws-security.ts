// IFCPlugin's sign_xml and verify_xml: a WS-Security message whose signature template the site has written. The core
// finds the element with an attribute equal to the id, the Reference pointing at "#id", its SignedInfo, the
// Signature's SignatureValue and the Security header's BinarySecurityToken, as its XPaths do
// (//*[@* = "#id"]/*[local-name() = "DigestValue"] and so on), canonicalizes with exclusive C14N whatever the template
// names, fills DigestValue and SignatureValue and leaves BinarySecurityToken to the site; verify_xml takes the
// certificate from there (docs/JOURNAL.md, 2026-11-17).
import { XmlCanonicalizer } from "xmldsigjs-canonicalizer";

export class WsSecurityError extends Error {
  // IFCPlugin's code: 5 for a document or template the core cannot use, 27 for no element with the id.
  readonly code: number;

  constructor(code: number, message: string) {
    super(message);
    this.name = "WsSecurityError";
    this.code = code;
  }
}

export function parseXml(text: string): XMLDocument {
  const doc = new DOMParser().parseFromString(text, "application/xml");
  if (!text.trim() || doc.getElementsByTagNameNS("http://www.w3.org/1999/xhtml", "parsererror").length > 0) {
    throw new WsSecurityError(5, "not XML");
  }
  return doc;
}

function elements(doc: XMLDocument): Element[] {
  return Array.from(doc.getElementsByTagName("*"));
}

const hasAttributeValue = (element: Element, value: string) => Array.from(element.attributes).some((attribute) => attribute.value === value);
const child = (element: Element | null | undefined, localName: string) => (element ? Array.from(element.children).find((node) => node.localName === localName) : undefined);

export function excC14n(node: Node): Uint8Array {
  return new TextEncoder().encode(new XmlCanonicalizer(false, true).Canonicalize(node));
}

interface Template {
  target: Element;
  digestValue: Element;
  signedInfo: Element;
  signature: Element;
}

function template(doc: XMLDocument, id: string): Template {
  const target = elements(doc).find((element) => hasAttributeValue(element, id));
  if (!target) throw new WsSecurityError(27, `no element with id ${id}`);
  const reference = elements(doc).find((element) => hasAttributeValue(element, `#${id}`) && child(element, "DigestValue"));
  const signedInfo = reference?.parentElement;
  const signature = signedInfo?.parentElement;
  if (!reference || !signedInfo || !signature) throw new WsSecurityError(5, "no signature template");
  return { target, digestValue: child(reference, "DigestValue")!, signedInfo, signature };
}

const base64 = (bytes: Uint8Array) => btoa(Array.from(bytes, (byte) => String.fromCharCode(byte)).join(""));

// Fills the template; `hash` is the key's hash, `sign` signs a hash as IFCPlugin's sign type 1 does. Returns the
// document as the core serializes it: from the root element, without the XML declaration.
export async function signTemplate(doc: XMLDocument, id: string, hash: (data: Uint8Array) => Uint8Array, sign: (hash: Uint8Array) => Promise<Uint8Array>): Promise<string> {
  const { target, digestValue, signedInfo, signature } = template(doc, id);
  const signatureValue = child(signature, "SignatureValue");
  if (!signatureValue) throw new WsSecurityError(5, "no SignatureValue");
  digestValue.textContent = base64(hash(excC14n(target)));
  signatureValue.textContent = base64(await sign(hash(excC14n(signedInfo))));
  return new XMLSerializer().serializeToString(doc.documentElement);
}

// The certificate of the Security header's BinarySecurityToken, as Base64; empty when the site left it so.
export function securityToken(doc: XMLDocument, id: string): string {
  const { signature } = template(doc, id);
  return (child(signature.parentElement, "BinarySecurityToken")?.textContent ?? "").replace(/\s+/g, "");
}

// Whether the digest matches the element and the signature verifies, given the hash and the check of a signature.
export function verifyTemplate(doc: XMLDocument, id: string, hash: (data: Uint8Array) => Uint8Array, check: (hash: Uint8Array, signature: Uint8Array) => boolean): boolean {
  const { target, digestValue, signedInfo, signature } = template(doc, id);
  const bytes = (text: string | null | undefined) => {
    try {
      return Uint8Array.from(atob((text ?? "").replace(/\s+/g, "")), (char) => char.charCodeAt(0));
    } catch {
      return new Uint8Array();
    }
  };
  const expected = hash(excC14n(target));
  const written = bytes(digestValue.textContent);
  if (written.length !== expected.length || written.some((byte, index) => byte !== expected[index])) return false;
  return check(hash(excC14n(signedInfo)), bytes(child(signature, "SignatureValue")?.textContent));
}
