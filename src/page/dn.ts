// Distinguished names as the CryptoPro plug-in shows them in SubjectName and IssuerName: the
// CryptoAPI X.500 string (CertNameToStr with CERT_X500_NAME_STR), relative names in reverse DER
// order ("CN=…" first, "C=RU" last). Russian OIDs carry the names CryptoPro CSP registers for them.
// Sites match these strings with regular expressions. Built from public samples and CryptoAPI
// rules, not yet compared with a real CryptoPro installation: see docs/JOURNAL.md.
import { children, decodeOid, expectTag, hex, type Node } from "./asn1.ts";

const names = new Map<string, string>([
  ["2.5.4.3", "CN"],
  ["2.5.4.4", "SN"],
  ["2.5.4.5", "SERIALNUMBER"],
  ["2.5.4.6", "C"],
  ["2.5.4.7", "L"],
  ["2.5.4.8", "S"],
  ["2.5.4.9", "STREET"],
  ["2.5.4.10", "O"],
  ["2.5.4.11", "OU"],
  ["2.5.4.12", "T"],
  ["2.5.4.13", "Description"],
  ["2.5.4.17", "PostalCode"],
  ["2.5.4.18", "POBox"],
  ["2.5.4.20", "Phone"],
  ["2.5.4.24", "X21Address"],
  ["2.5.4.42", "G"],
  ["2.5.4.43", "I"],
  ["2.5.4.46", "dnQualifier"],
  ["1.2.840.113549.1.9.1", "E"],
  ["1.2.840.113549.1.9.2", "UnstructuredName"],
  ["1.2.840.113549.1.9.8", "UnstructuredAddress"],
  ["0.9.2342.19200300.100.1.25", "DC"],
  ["1.2.643.3.131.1.1", "ИНН"],
  ["1.2.643.100.1", "ОГРН"],
  ["1.2.643.100.3", "СНИЛС"],
  ["1.2.643.100.4", "ИНН ЮЛ"],
  ["1.2.643.100.5", "ОГРНИП"],
]);

export interface Attribute {
  oid: string;
  value: string;
}

// One entry per RDN, in DER order; a multi-valued RDN has several attributes.
export type Name = Attribute[][];

function decodeString(node: Node): string {
  switch (node.tag) {
    case 0x0c: // UTF8String
      return new TextDecoder("utf-8").decode(node.value);
    case 0x12: // NumericString
    case 0x13: // PrintableString
    case 0x16: // IA5String
    case 0x14: // TeletexString, treated as Latin-1
      return new TextDecoder("latin1").decode(node.value);
    case 0x1e: // BMPString
      return new TextDecoder("utf-16be").decode(node.value);
    default:
      return `#${hex(node.der)}`;
  }
}

export function parseName(node: Node): Name {
  return children(expectTag(node, 0x30, "Name")).map((rdn) =>
    children(expectTag(rdn, 0x31, "RelativeDistinguishedName")).map((pair) => {
      const [type, value] = children(expectTag(pair, 0x30, "AttributeTypeAndValue"));
      return { oid: decodeOid(expectTag(type, 0x06, "attribute type").value), value: decodeString(value!) };
    }),
  );
}

function quote(value: string): string {
  const needsQuotes = value === "" || /[,+="<>#;\r\n]/.test(value) || /^\s|\s$/.test(value);
  return needsQuotes ? `"${value.replaceAll('"', '""')}"` : value;
}

export function formatName(name: Name): string {
  return name
    .toReversed()
    .map((rdn) => rdn.map(({ oid, value }) => `${names.get(oid) ?? `OID.${oid}`}=${quote(value)}`).join(" + "))
    .join(", ");
}
