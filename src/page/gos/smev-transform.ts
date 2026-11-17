// The SMEV 3 transform (urn://smev-gov-ru/xmldsig/transform), Gosplugin's only "normalize" algorithm: no XML declaration,
// processing instructions or comments; text that is only whitespace dropped; every namespace prefix renamed ns1, ns2, … in
// the order it is needed and declared where it is first used; attributes sorted by namespace, then name, the unqualified
// first; an element without a namespace is an error (31013, as the core answers). Written from the transform's published
// description and the core's answers (docs/JOURNAL.md, 2026-11-17).
import { parseXml } from "../ifc/ws-security.ts";
import { GosError } from "./messages.ts";

export const SMEV_TRANSFORM = "urn://smev-gov-ru/xmldsig/transform";

const escapeText = (text: string) => text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/\r/g, "&#xD;");
const escapeAttribute = (text: string) =>
  text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/"/g, "&quot;").replace(/\t/g, "&#x9;").replace(/\n/g, "&#xA;").replace(/\r/g, "&#xD;");

export function smevTransform(text: string): string {
  let doc: XMLDocument;
  try {
    doc = parseXml(text);
  } catch {
    throw new GosError(20001);
  }
  let counter = 0;
  const write = (element: Element, scope: Map<string, string>): string => {
    if (!element.namespaceURI) throw new GosError(31013);
    const own = new Map(scope);
    const declarations: string[] = [];
    const prefixOf = (uri: string) => {
      let prefix = own.get(uri);
      if (!prefix) {
        prefix = `ns${++counter}`;
        own.set(uri, prefix);
        declarations.push(` xmlns:${prefix}="${escapeAttribute(uri)}"`);
      }
      return prefix;
    };
    const name = `${prefixOf(element.namespaceURI)}:${element.localName}`;
    const attributes = Array.from(element.attributes)
      .filter((attribute) => attribute.namespaceURI !== "http://www.w3.org/2000/xmlns/")
      .sort((a, b) => (a.namespaceURI ?? "").localeCompare(b.namespaceURI ?? "") || a.localName.localeCompare(b.localName))
      .map((attribute) => ` ${attribute.namespaceURI ? `${prefixOf(attribute.namespaceURI)}:` : ""}${attribute.localName}="${escapeAttribute(attribute.value)}"`);
    let content = "";
    for (const node of Array.from(element.childNodes)) {
      if (node.nodeType === 1) content += write(node as Element, own);
      else if ((node.nodeType === 3 || node.nodeType === 4) && (node.nodeValue ?? "").trim()) content += escapeText(node.nodeValue ?? "");
    }
    return `<${name}${declarations.join("")}${attributes.join("")}>${content}</${name}>`;
  };
  return write(doc.documentElement, new Map());
}
