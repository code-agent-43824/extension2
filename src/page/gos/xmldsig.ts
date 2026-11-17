// Gosplugin's "xmldsig" signature: the document with ds:Signature added as the root's last child, exclusive C14N for
// SignedInfo, GOST R 34.10-2012 of the key's size, a Reference to the whole document (URI="") without transforms and
// without KeyInfo, and the XML declaration the core writes (docs/JOURNAL.md, 2026-11-17). What the core's DigestValue
// covers was not found; here it is the document before the signature, canonicalized by C14N as XMLDSig does for a
// reference without transforms: what a verifier treating the signature as enveloped checks.
import { XmlCanonicalizer } from "xmldsigjs-canonicalizer";
import { GOST_2012_512 } from "../gost.ts";
import { excC14n, parseXml } from "../ifc/ws-security.ts";
import type { X509 } from "../x509.ts";
import { GosError } from "./messages.ts";

const DS = "http://www.w3.org/2000/09/xmldsig#";
const CPXMLSEC = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:";
const base64 = (bytes: Uint8Array) => btoa(Array.from(bytes, (byte) => String.fromCharCode(byte)).join(""));

export async function signXml(text: string, x509: X509, hash: (data: Uint8Array) => Uint8Array, sign: (hash: Uint8Array) => Promise<Uint8Array>): Promise<string> {
  let doc: XMLDocument;
  try {
    doc = parseXml(text);
  } catch {
    throw new GosError(20001);
  }
  const root = doc.documentElement;
  const bits = x509.publicKeyAlgorithm === GOST_2012_512 ? "512" : "256";
  const documentDigest = hash(new TextEncoder().encode(new XmlCanonicalizer(false, false).Canonicalize(root)));
  const element = (parent: Element, name: string, algorithm?: string) => {
    const child = doc.createElementNS(DS, `ds:${name}`);
    if (algorithm !== undefined) child.setAttribute("Algorithm", algorithm);
    parent.appendChild(child);
    return child;
  };
  const signature = doc.createElementNS(DS, "ds:Signature");
  const signedInfo = element(signature, "SignedInfo");
  element(signedInfo, "CanonicalizationMethod", "http://www.w3.org/2001/10/xml-exc-c14n#");
  element(signedInfo, "SignatureMethod", `${CPXMLSEC}gostr34102012-gostr34112012-${bits}`);
  const reference = element(signedInfo, "Reference");
  reference.setAttribute("URI", "");
  element(reference, "DigestMethod", `${CPXMLSEC}gostr34112012-${bits}`);
  element(reference, "DigestValue").textContent = base64(documentDigest);
  root.appendChild(signature);
  element(signature, "SignatureValue").textContent = base64(await sign(hash(excC14n(signedInfo))));
  return `<?xml version="1.0" encoding="utf-8" standalone="no" ?>${new XMLSerializer().serializeToString(root)}`;
}
