// What CAdESCOM.Certificate reports from a certificate beyond x509.ts, for its CAPICOM methods and Certificates.Find:
// GetInfo's names by CertGetNameString's rules (Microsoft's documentation of CAPICOM_CERT_INFO_TYPE and
// CertGetNameString), the extended key usages, basic constraints, certificate and application policies, and the
// Microsoft template extensions. Not compared with CryptoPro's plug-in.
import { children, decodeOid, expectTag, read, type Node } from "./asn1.ts";
import { decodeString, type Name } from "./dn.ts";
import type { X509 } from "./x509.ts";

export const EXTENSION_KEY_USAGE = "2.5.29.15";
export const EXTENSION_EXTENDED_KEY_USAGE = "2.5.29.37";
export const EXTENSION_BASIC_CONSTRAINTS = "2.5.29.19";
const EXTENSION_SUBJECT_ALT_NAME = "2.5.29.17";
const EXTENSION_ISSUER_ALT_NAME = "2.5.29.18";
const EXTENSION_CERTIFICATE_POLICIES = "2.5.29.32";
// Microsoft's: the template's name (szOID_ENROLL_CERTTYPE_EXTENSION), the template's OID and version
// (szOID_CERTIFICATE_TEMPLATE), the application policies (szOID_APPLICATION_CERT_POLICIES).
const EXTENSION_TEMPLATE_NAME = "1.3.6.1.4.1.311.20.2";
const EXTENSION_TEMPLATE = "1.3.6.1.4.1.311.21.7";
const EXTENSION_APPLICATION_POLICIES = "1.3.6.1.4.1.311.21.10";
// szOID_NT_PRINCIPAL_NAME, the UPN in an otherName.
const UPN = "1.3.6.1.4.1.311.20.2.3";

const COMMON_NAME = "2.5.4.3";
const EMAIL = "1.2.840.113549.1.9.1";

export function extensionOf(x509: X509, oid: string): X509["extensions"][number] | undefined {
  return x509.extensions.find((extension) => extension.oid === oid);
}

// GeneralNames: rfc822Name [1], dNSName [2], otherName [0] and the rest, each as its node.
function generalNames(value: Uint8Array): Node[] {
  return children(expectTag(read(value), 0x30, "GeneralNames"));
}

function first(name: Name, oid: string): string | undefined {
  return name.flat().find((attribute) => attribute.oid === oid)?.value;
}

const ascii = (bytes: Uint8Array) => new TextDecoder("latin1").decode(bytes);

// CAPICOM_CERT_INFO_TYPE 0–7: even for the subject, odd for the issuer (its name and its Issuer Alternative Name);
// an empty string when the certificate has nothing of the kind, as CertGetNameString answers.
export function nameInfo(x509: X509, type: number): string {
  const issuer = type % 2 === 1;
  const name = issuer ? x509.issuer : x509.subject;
  const alternative = extensionOf(x509, issuer ? EXTENSION_ISSUER_ALT_NAME : EXTENSION_SUBJECT_ALT_NAME);
  const names = alternative ? generalNames(alternative.value) : [];
  const alt = (tag: number) => names.find((node) => node.tag === tag);
  switch (type >> 1) {
    case 0: {
      for (const oid of [COMMON_NAME, "2.5.4.11", "2.5.4.10", EMAIL]) {
        const value = first(name, oid);
        if (value !== undefined) return value;
      }
      const email = alt(0x81);
      return email ? ascii(email.value) : (name.flat()[0]?.value ?? "");
    }
    case 1: {
      const email = alt(0x81);
      return email ? ascii(email.value) : (first(name, EMAIL) ?? "");
    }
    case 2:
      for (const node of names.filter((candidate) => candidate.tag === 0xa0)) {
        const [type, value] = children(node);
        if (type && decodeOid(type.value) === UPN && value) return decodeString(children(value)[0]!);
      }
      return "";
    case 3: {
      const dns = alt(0x82);
      return dns ? ascii(dns.value) : (first(name, COMMON_NAME) ?? "");
    }
    default:
      throw new RangeError(`CAPICOM_CERT_INFO_TYPE ${type}`);
  }
}

// The extended key usages' OIDs; null without the extension.
export function extendedKeyUsages(x509: X509): string[] | null {
  const extension = extensionOf(x509, EXTENSION_EXTENDED_KEY_USAGE);
  return extension ? children(expectTag(read(extension.value), 0x30, "ExtKeyUsageSyntax")).map((node) => decodeOid(node.value)) : null;
}

// BasicConstraints: cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPTIONAL; null without the extension.
export function basicConstraints(x509: X509): { ca: boolean; pathLength: number | null } | null {
  const extension = extensionOf(x509, EXTENSION_BASIC_CONSTRAINTS);
  if (!extension) return null;
  const fields = children(expectTag(read(extension.value), 0x30, "BasicConstraints"));
  const ca = fields[0]?.tag === 0x01 && fields[0].value[0] !== 0;
  const length = fields.find((field) => field.tag === 0x02);
  return { ca, pathLength: length ? length.value.reduce((sum, byte) => sum * 256 + byte, 0) : null };
}

// The policy identifiers of CertificatePolicies, the syntax Microsoft's application policies share.
function policies(x509: X509, oid: string): string[] {
  const extension = extensionOf(x509, oid);
  if (!extension) return [];
  return children(expectTag(read(extension.value), 0x30, "CertificatePolicies")).map((policy) => decodeOid(expectTag(children(policy)[0], 0x06, "policyIdentifier").value));
}

export function certificatePolicies(x509: X509): string[] {
  return policies(x509, EXTENSION_CERTIFICATE_POLICIES);
}

export function applicationPolicies(x509: X509): string[] {
  return policies(x509, EXTENSION_APPLICATION_POLICIES);
}

// The certificate template: its name (a string) and its OID, whichever the certificate carries.
export function templateNames(x509: X509): string[] {
  const result: string[] = [];
  const name = extensionOf(x509, EXTENSION_TEMPLATE_NAME);
  if (name) result.push(decodeString(read(name.value)));
  const template = extensionOf(x509, EXTENSION_TEMPLATE);
  if (template) result.push(decodeOid(expectTag(children(expectTag(read(template.value), 0x30, "CertificateTemplate"))[0], 0x06, "templateID").value));
  return result;
}
