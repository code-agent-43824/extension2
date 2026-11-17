// A certificate's fields as IFCPlugin's core prints them with its OpenSSL (1.0-era printing code, an object table with
// the Russian names INN, OGRN, SNILS and the signing tools, docs/JOURNAL.md 2026-11-17): names one attribute a line
// with long names, ASN1_TIME_print's dates, the serial as hex bytes, X509V3_extensions_print's text with unknown
// extensions dumped as asn1parse does. tests/fixtures/ifc-x509-info.json holds what the core printed for public
// certificates; the unit tests compare against it.
import { children, decodeOid, read, type Node } from "../asn1.ts";
import type { Name } from "../dn.ts";
import type { X509 } from "../x509.ts";

// OpenSSL's long names of the attributes and OIDs the core's table knows.
const longNames = new Map<string, string>([
  ["2.5.4.3", "commonName"],
  ["2.5.4.4", "surname"],
  ["2.5.4.5", "serialNumber"],
  ["2.5.4.6", "countryName"],
  ["2.5.4.7", "localityName"],
  ["2.5.4.8", "stateOrProvinceName"],
  ["2.5.4.9", "streetAddress"],
  ["2.5.4.10", "organizationName"],
  ["2.5.4.11", "organizationalUnitName"],
  ["2.5.4.12", "title"],
  ["2.5.4.13", "description"],
  ["2.5.4.15", "businessCategory"],
  ["2.5.4.16", "postalAddress"],
  ["2.5.4.17", "postalCode"],
  ["2.5.4.41", "name"],
  ["2.5.4.42", "givenName"],
  ["2.5.4.43", "initials"],
  ["2.5.4.44", "generationQualifier"],
  ["2.5.4.46", "dnQualifier"],
  ["2.5.4.65", "pseudonym"],
  ["1.2.840.113549.1.9.1", "emailAddress"],
  ["1.2.840.113549.1.9.2", "unstructuredName"],
  ["0.9.2342.19200300.100.1.1", "userId"],
  ["0.9.2342.19200300.100.1.25", "domainComponent"],
  ["1.2.643.3.131.1.1", "INN"],
  ["1.2.643.100.1", "OGRN"],
  ["1.2.643.100.3", "SNILS"],
  ["2.5.29.14", "X509v3 Subject Key Identifier"],
  ["2.5.29.15", "X509v3 Key Usage"],
  ["2.5.29.16", "X509v3 Private Key Usage Period"],
  ["2.5.29.17", "X509v3 Subject Alternative Name"],
  ["2.5.29.18", "X509v3 Issuer Alternative Name"],
  ["2.5.29.19", "X509v3 Basic Constraints"],
  ["2.5.29.30", "X509v3 Name Constraints"],
  ["2.5.29.31", "X509v3 CRL Distribution Points"],
  ["2.5.29.32", "X509v3 Certificate Policies"],
  ["2.5.29.32.0", "X509v3 Any Policy"],
  ["2.5.29.35", "X509v3 Authority Key Identifier"],
  ["2.5.29.37", "X509v3 Extended Key Usage"],
  ["2.5.29.37.0", "Any Extended Key Usage"],
  ["2.5.29.46", "X509v3 Freshest CRL"],
  ["1.3.6.1.5.5.7.1.1", "Authority Information Access"],
  ["1.3.6.1.5.5.7.1.11", "Subject Information Access"],
  ["1.3.6.1.5.5.7.48.1", "OCSP"],
  ["1.3.6.1.5.5.7.48.2", "CA Issuers"],
  ["1.3.6.1.5.5.7.3.1", "TLS Web Server Authentication"],
  ["1.3.6.1.5.5.7.3.2", "TLS Web Client Authentication"],
  ["1.3.6.1.5.5.7.3.3", "Code Signing"],
  ["1.3.6.1.5.5.7.3.4", "E-mail Protection"],
  ["1.3.6.1.5.5.7.3.5", "IPSec End System"],
  ["1.3.6.1.5.5.7.3.6", "IPSec Tunnel"],
  ["1.3.6.1.5.5.7.3.7", "IPSec User"],
  ["1.3.6.1.5.5.7.3.8", "Time Stamping"],
  ["1.3.6.1.5.5.7.3.9", "OCSP Signing"],
  ["1.3.6.1.4.1.311.2.1.21", "Microsoft Individual Code Signing"],
  ["1.3.6.1.4.1.311.2.1.22", "Microsoft Commercial Code Signing"],
  ["1.3.6.1.4.1.311.10.3.1", "Microsoft Trust List Signing"],
  ["1.3.6.1.4.1.311.10.3.3", "Microsoft Server Gated Crypto"],
  ["1.3.6.1.4.1.311.10.3.4", "Microsoft Encrypted File System"],
  ["1.3.6.1.4.1.311.20.2.2", "Microsoft Smartcardlogin"],
  ["1.3.6.1.5.5.8.2.2", "ipsec Internet Key Exchange"],
  ["1.2.643.100.111", "Signing Tool of Subject"],
  ["1.2.643.100.112", "Signing Tool of Issuer"],
  ["1.2.643.7.1.1.1.1", "GOST R 34.10-2012 with 256 bit modulus"],
  ["1.2.643.7.1.1.1.2", "GOST R 34.10-2012 with 512 bit modulus"],
  ["1.2.643.7.1.1.2.2", "GOST R 34.11-2012 with 256 bit hash"],
  ["1.2.643.7.1.1.2.3", "GOST R 34.11-2012 with 512 bit hash"],
  ["1.2.840.113549.1.1.1", "rsaEncryption"],
]);

// i2a_ASN1_OBJECT: the long name, or the dotted OID.
const objectText = (oid: string) => longNames.get(oid) ?? oid;

// X509_NAME_print_ex with the core's flags: "longName = value", one attribute a line, values as they are.
export function opensslName(name: Name): string {
  return name.map((rdn) => rdn.map((attribute) => `${objectText(attribute.oid)} = ${attribute.value}`).join(" + ")).join("\n");
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

// ASN1_TIME_print: "Nov  6 05:38:54 2026 GMT".
export function opensslTime(date: Date): string {
  const two = (value: number) => String(value).padStart(2, "0");
  return `${MONTHS[date.getUTCMonth()]} ${String(date.getUTCDate()).padStart(2, " ")} ${two(date.getUTCHours())}:${two(date.getUTCMinutes())}:${two(date.getUTCSeconds())} ${date.getUTCFullYear()} GMT`;
}

// The serial as the integer's bytes, without the zero byte DER puts before a high bit.
export function opensslSerial(x509: X509): string {
  const pairs = x509.serialNumber.match(/../g) ?? ["00"];
  if (pairs.length > 1 && pairs[0] === "00") pairs.shift();
  return pairs.join(":");
}

const hexColon = (bytes: Uint8Array) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0").toUpperCase()).join(":");
const utf8 = (bytes: Uint8Array) => new TextDecoder().decode(bytes);
const latin1 = (bytes: Uint8Array) => new TextDecoder("latin1").decode(bytes);

// ASN1_tag2str.
const TAG_NAMES = [
  "EOC", "BOOLEAN", "INTEGER", "BIT STRING", "OCTET STRING", "NULL", "OBJECT", "OBJECT DESCRIPTOR", "EXTERNAL", "REAL",
  "ENUMERATED", "<ASN1 11>", "UTF8STRING", "<ASN1 13>", "<ASN1 14>", "<ASN1 15>", "SEQUENCE", "SET", "NUMERICSTRING",
  "PRINTABLESTRING", "T61STRING", "VIDEOTEXSTRING", "IA5STRING", "UTCTIME", "GENERALIZEDTIME", "GRAPHICSTRING",
  "VISIBLESTRING", "GENERALSTRING", "UNIVERSALSTRING", "<ASN1 29>", "BMPSTRING",
];

// BIO_dump_indent with an indent of 6: 16 bytes a row, a dash after the eighth, then the printable ones.
function hexDump(bytes: Uint8Array, indent: number): string {
  let out = "";
  for (let row = 0; row < bytes.length; row += 16) {
    let line = `${" ".repeat(indent)}${row.toString(16).padStart(4, "0")} - `;
    for (let j = 0; j < 16; j++) {
      const byte = bytes[row + j];
      line += byte === undefined ? "   " : `${byte.toString(16).padStart(2, "0")}${j === 7 ? "-" : " "}`;
    }
    line += "  ";
    for (const byte of bytes.subarray(row, row + 16)) line += byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : ".";
    out += `${line}\n`;
  }
  return out;
}

const STRING_TAGS = new Set([0x12, 0x13, 0x14, 0x16, 0x17, 0x18, 0x1a, 0x0c]);

// ASN1_parse_dump(…, indent = 1, dump = -1): one line an element, children indented by depth.
export function asn1Parse(der: Uint8Array): string {
  let out = "";
  const walk = (bytes: Uint8Array, base: number, depth: number) => {
    for (let offset = 0; offset < bytes.length; ) {
      const node: Node = read(bytes, offset);
      const header = node.der.length - node.value.length;
      const constructed = (node.tag & 0x20) !== 0;
      const klass = node.tag >> 6;
      const number = node.tag & 0x1f;
      const name = klass === 0 ? (TAG_NAMES[number] ?? `<ASN1 ${number}>`) : `${["univ", "appl", "cont", "priv"][klass]} [ ${number} ]`;
      out += `${String(base + offset).padStart(5, " ")}:d=${String(depth).padEnd(2, " ")} hl=${header} l=${String(node.value.length).padStart(4, " ")} `;
      out += `${constructed ? "cons" : "prim"}: ${" ".repeat(depth)}${name.padEnd(18, " ")}`;
      if (constructed) {
        out += "\n";
        walk(node.value, base + offset + header, depth + 1);
      } else if (klass !== 0) {
        out += "\n";
      } else if (STRING_TAGS.has(number)) {
        out += `:${utf8(node.value)}\n`;
      } else if (number === 0x06) {
        out += `:${objectText(decodeOid(node.value))}\n`;
      } else if (number === 0x01) {
        out += node.value.length === 1 ? `:${node.value[0]}\n` : "Bad boolean\n";
      } else if (number === 0x02 || number === 0x0a) {
        let value = node.value;
        if (value.length > 1 && value[0] === 0 && value[1]! >= 0x80) value = value.subarray(1);
        out += `:${value.length ? Array.from(value, (byte) => byte.toString(16).padStart(2, "0").toUpperCase()).join("") : "00"}\n`;
      } else if (number === 0x04) {
        const printable = node.value.every((byte) => (byte >= 0x20 && byte <= 0x7e) || byte === 0x0a || byte === 0x0d || byte === 0x09);
        if (!node.value.length) out += "\n";
        else if (printable) out += `:${latin1(node.value)}\n`;
        else out += `\n${hexDump(node.value, 6)}`;
      } else if (node.value.length) {
        out += `\n${hexDump(node.value, 6)}`;
      } else {
        out += "\n";
      }
      offset += node.der.length;
    }
  };
  walk(der, 0, 0);
  return out;
}

// GENERAL_NAME_print (`printed`: CRL distribution points) or i2v_GENERAL_NAME's name:value (the other extensions),
// which differ in the directory name only.
function generalName(node: Node, printed = false): string {
  const number = node.tag & 0x1f;
  switch (number) {
    case 1:
      return `email:${latin1(node.value)}`;
    case 2:
      return `DNS:${latin1(node.value)}`;
    case 6:
      return `URI:${latin1(node.value)}`;
    case 4:
      return printed ? `DirName: ${oneLineName(children(node)[0]!)}` : `DirName:${slashName(children(node)[0]!)}`;
    case 7:
      return node.value.length === 4 ? `IP Address:${Array.from(node.value).join(".")}` : `IP Address:${hexColon(node.value)}`;
    case 8:
      return `Registered ID:${objectText(decodeOid(node.value))}`;
    case 0:
      return "othername:<unsupported>";
    case 3:
      return "X400Name:<unsupported>";
    default:
      return "EdiPartyName:<unsupported>";
  }
}

// X509_NAME_print_ex(…, XN_FLAG_ONELINE): "C = RU, O = …", short names.
const shortNames = new Map<string, string>([
  ["2.5.4.3", "CN"], ["2.5.4.6", "C"], ["2.5.4.7", "L"], ["2.5.4.8", "ST"], ["2.5.4.9", "street"], ["2.5.4.10", "O"],
  ["2.5.4.11", "OU"], ["2.5.4.4", "SN"], ["2.5.4.42", "GN"], ["2.5.4.12", "title"], ["1.2.840.113549.1.9.1", "emailAddress"],
  ["1.2.643.3.131.1.1", "INN"], ["1.2.643.100.1", "OGRN"], ["1.2.643.100.3", "SNILS"],
]);

function oneLineName(sequence: Node): string {
  return children(sequence)
    .map((set) =>
      children(set)
        .map((attribute) => {
          const [type, value] = children(attribute);
          const oid = decodeOid(type!.value);
          return `${shortNames.get(oid) ?? oid} = ${value!.tag === 0x1e ? bmp(value!.value) : utf8(value!.value)}`;
        })
        .join(" + "),
    )
    .join(", ");
}

// X509_NAME_oneline: "/C=US/O=…", bytes outside printable ASCII as \xHH.
function slashName(sequence: Node): string {
  let text = "";
  for (const set of children(sequence)) {
    for (const attribute of children(set)) {
      const [type, value] = children(attribute);
      const oid = decodeOid(type!.value);
      const escaped = Array.from(value!.value, (byte) => (byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : `\\x${byte.toString(16).padStart(2, "0").toUpperCase()}`)).join("");
      text += `/${shortNames.get(oid) ?? oid}=${escaped}`;
    }
  }
  return text;
}

function bmp(bytes: Uint8Array): string {
  let text = "";
  for (let i = 0; i + 1 < bytes.length; i += 2) text += String.fromCharCode((bytes[i]! << 8) | bytes[i + 1]!);
  return text;
}

const KEY_USAGE_NAMES = [
  "Digital Signature", "Non Repudiation", "Key Encipherment", "Data Encipherment", "Key Agreement", "Certificate Sign",
  "CRL Sign", "Encipher Only", "Decipher Only",
];

function bitSet(bitString: Node, bit: number): boolean {
  const byte = bitString.value[1 + (bit >> 3)];
  return byte !== undefined && (byte & (0x80 >> (bit & 7))) !== 0;
}

// The text of one known extension at an indent of 4, ending as OpenSSL ends it (a multi-line one with a newline after
// every line, a one-line one without); undefined for an extension OpenSSL has no printer for.
function extensionText(oid: string, value: Uint8Array): string | undefined {
  const node = read(value);
  const pad = "    ";
  switch (oid) {
    case "2.5.29.14":
      return `${pad}${hexColon(node.value)}`;
    case "2.5.29.15":
      return `${pad}${KEY_USAGE_NAMES.filter((_, bit) => bitSet(node, bit)).join(", ")}`;
    case "2.5.29.19": {
      const [first, second] = children(node);
      const ca = first?.tag === 0x01 && first.value[0] !== 0;
      const pathLen = first?.tag === 0x02 ? first : second;
      return `${pad}CA:${ca ? "TRUE" : "FALSE"}${pathLen ? `, pathlen:${Array.from(pathLen.value).reduce((sum, byte) => sum * 256 + byte, 0)}` : ""}`;
    }
    case "2.5.29.37":
      return `${pad}${children(node).map((purpose) => objectText(decodeOid(purpose.value))).join(", ")}`;
    case "2.5.29.16": {
      const parts = children(node).map((part) => `${part.tag === 0x80 ? "Not Before" : "Not After"}: ${opensslTime(generalizedTime(part.value))}`);
      return `${pad}${parts.join(", ")}`;
    }
    case "2.5.29.17":
    case "2.5.29.18":
      return `${pad}${children(node).map((name) => generalName(name)).join(", ")}`;
    case "2.5.29.35": {
      let text = "";
      for (const part of children(node)) {
        if (part.tag === 0x80) text += `${pad}keyid:${hexColon(part.value)}\n`;
        else if (part.tag === 0xa1) for (const name of children(part)) text += `${pad}${generalName(name)}\n`;
        else if (part.tag === 0x82) text += `${pad}serial:${hexColon(part.value)}\n`;
      }
      return text;
    }
    case "1.3.6.1.5.5.7.1.1":
    case "1.3.6.1.5.5.7.1.11": {
      let text = "";
      for (const access of children(node)) {
        const [method, location] = children(access);
        const general = generalName(location!);
        const colon = general.indexOf(":");
        text += `${pad}${objectText(decodeOid(method!.value))} - ${general.slice(0, colon)}:${general.slice(colon + 1)}\n`;
      }
      return text;
    }
    case "2.5.29.31":
    case "2.5.29.46": {
      let text = "";
      for (const point of children(node)) {
        text += "\n";
        for (const field of children(point)) {
          if (field.tag === 0xa0) {
            const name = children(field)[0]!;
            if (name.tag === 0xa0) {
              text += `${pad}Full Name:\n`;
              for (const general of children(name)) text += `${pad}  ${generalName(general, true)}\n`;
            } else {
              text += `${pad}Relative Name:\n${pad}  ${oneLineName({ ...name, tag: 0x30, value: name.der })}\n`;
            }
          } else if (field.tag === 0xa2) {
            text += `${pad}CRL Issuer:\n`;
            for (const general of children(field)) text += `${pad}  ${generalName(general, true)}\n`;
          }
        }
      }
      return text;
    }
    case "2.5.29.32": {
      let text = "";
      for (const policy of children(node)) {
        const [id, qualifiers] = children(policy);
        text += `${pad}Policy: ${objectText(decodeOid(id!.value))}\n`;
        for (const qualifier of qualifiers ? children(qualifiers) : []) {
          const [kind, content] = children(qualifier);
          const type = decodeOid(kind!.value);
          if (type === "1.3.6.1.5.5.7.2.1") text += `${pad}  CPS: ${latin1(content!.value)}\n`;
          else if (type === "1.3.6.1.5.5.7.2.2") {
            text += `${pad}  User Notice:\n`;
            for (const part of children(content!)) if (part.tag !== 0x30) text += `${pad}    Explicit Text: ${part.tag === 0x1e ? bmp(part.value) : utf8(part.value)}\n`;
          } else text += `${pad}  Unknown Qualifier: ${objectText(type)}\n`;
        }
      }
      return text;
    }
    default:
      return undefined;
  }
}

function generalizedTime(value: Uint8Array): Date {
  const text = latin1(value);
  const match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/.exec(text);
  if (!match) throw new Error(`unsupported time ${text}`);
  const [y, mo, d, h, mi, s] = match.slice(1).map(Number) as [number, number, number, number, number, number];
  return new Date(Date.UTC(y, mo - 1, d, h, mi, s));
}

// X509V3_extensions_print, the trailing newlines dropped as the core does.
export function opensslExtensions(x509: X509): string {
  let out = "";
  for (const extension of x509.extensions) {
    out += `${objectText(extension.oid)}: ${extension.critical ? "critical" : ""}\n`;
    let text: string | undefined;
    try {
      text = extensionText(extension.oid, extension.value);
    } catch {
      text = undefined;
    }
    if (text === undefined) {
      try {
        text = asn1Parse(extension.value);
      } catch {
        text = `    ${hexColon(extension.value)}`;
      }
    }
    out += `${text}\n`;
  }
  return out.replace(/\n+$/, "");
}
