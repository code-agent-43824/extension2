// The CAPICOM objects CAdESCOM.Certificate's methods give for its extensions (Microsoft's CAPICOM documentation):
// KeyUsage, ExtendedKeyUsage with its EKUs, BasicConstraints, Extensions with their EncodedData. Not compared with
// CryptoPro's plug-in.
import { constants } from "../constants.ts";
import { CadesError } from "../errors.ts";
import { basicConstraints, extendedKeyUsages, extensionOf, EXTENSION_BASIC_CONSTRAINTS, EXTENSION_EXTENDED_KEY_USAGE, EXTENSION_KEY_USAGE } from "../certificate-info.ts";
import { derToBase64, type X509 } from "../x509.ts";

const E_INVALIDARG = 0x80070057;
const E_NOTIMPL = 0x80004001;

// Base64 as Certificate.Export gives it, the only format checked against the plug-in: 64-column lines, each ending in
// LF.
export function base64Lines(der: Uint8Array): string {
  return (derToBase64(der).match(/.{1,64}/g) ?? []).map((line) => `${line}\n`).join("");
}

// CAPICOM.EncodedData. Value is Base64 only: the browser plug-in has no binary (CryptoPro's documentation of binary
// data); Format and Decoder, which need Windows' formatters and decoders, are not done.
export class EncodedData {
  readonly #der: Uint8Array;

  constructor(der: Uint8Array) {
    this.#der = der;
  }

  async Value(encoding: number = constants.CADESCOM_ENCODE_BASE64): Promise<string> {
    if (Number(encoding) !== constants.CADESCOM_ENCODE_BASE64) throw new CadesError(`Неподдерживаемая кодировка: ${encoding}`, E_INVALIDARG);
    return base64Lines(this.#der);
  }

  async Format(): Promise<string> {
    throw new CadesError("EncodedData.Format не поддерживается расширением", E_NOTIMPL);
  }

  async Decoder(): Promise<never> {
    throw new CadesError("EncodedData.Decoder не поддерживается расширением", E_NOTIMPL);
  }
}

// CAPICOM_OID's names of the extensions (Microsoft's documentation of the enumeration), for OID.Name and for
// Certificates.Find by extension.
export const extensionOids = new Map<number, string>([
  [9, "2.5.29.14"],
  [10, EXTENSION_KEY_USAGE],
  [11, "2.5.29.16"],
  [12, "2.5.29.17"],
  [13, "2.5.29.18"],
  [14, EXTENSION_BASIC_CONSTRAINTS],
  [15, "2.5.29.30"],
  [16, "2.5.29.31"],
  [17, "2.5.29.32"],
  [18, "2.5.29.33"],
  [19, "2.5.29.35"],
  [20, "2.5.29.36"],
  [21, EXTENSION_EXTENDED_KEY_USAGE],
  [22, "1.3.6.1.4.1.311.21.7"],
  [23, "1.3.6.1.4.1.311.21.10"],
  [26, "1.3.6.1.5.5.7.1.1"],
]);

// CAPICOM.OID of an extension: Name from CAPICOM_OID (CAPICOM_OID_OTHER for the rest); the friendly names CryptoPro
// gives are not known here, so FriendlyName is the OID itself.
class ExtensionOid {
  readonly #value: string;

  constructor(value: string) {
    this.#value = value;
  }

  get Name(): Promise<number> {
    return Promise.resolve([...extensionOids].find(([, oid]) => oid === this.#value)?.[0] ?? constants.CAPICOM_OID_OTHER);
  }

  get FriendlyName(): Promise<string> {
    return Promise.resolve(this.#value);
  }

  get Value(): Promise<string> {
    return Promise.resolve(this.#value);
  }
}

class Extension {
  readonly #extension: X509["extensions"][number];

  constructor(extension: X509["extensions"][number]) {
    this.#extension = extension;
  }

  get OID(): Promise<ExtensionOid> {
    return Promise.resolve(new ExtensionOid(this.#extension.oid));
  }

  get IsCritical(): Promise<boolean> {
    return Promise.resolve(this.#extension.critical);
  }

  get EncodedData(): Promise<EncodedData> {
    return Promise.resolve(new EncodedData(this.#extension.value));
  }
}

// Indexed from 1, or by the extension's OID.
export class Extensions {
  readonly #items: X509["extensions"];

  constructor(items: X509["extensions"]) {
    this.#items = items;
  }

  get Count(): Promise<number> {
    return Promise.resolve(this.#items.length);
  }

  async Item(index: unknown): Promise<Extension> {
    const item = typeof index === "string" && index.includes(".") ? this.#items.find((extension) => extension.oid === index) : this.#items[Number(index) - 1];
    if (!item) throw new CadesError("Неверный индекс расширения", E_INVALIDARG);
    return new Extension(item);
  }
}

// CAPICOM.KeyUsage, on the flags x509.ts keeps (CAPICOM's: digitalSignature 0x80 … decipherOnly 0x8000).
export class KeyUsage {
  readonly #x509: X509;

  constructor(x509: X509) {
    this.#x509 = x509;
  }

  #has(flag: number): Promise<boolean> {
    return Promise.resolve(((this.#x509.keyUsage ?? 0) & flag) !== 0);
  }

  get IsPresent(): Promise<boolean> {
    return Promise.resolve(this.#x509.keyUsage !== null);
  }

  get IsCritical(): Promise<boolean> {
    return Promise.resolve(extensionOf(this.#x509, EXTENSION_KEY_USAGE)?.critical ?? false);
  }

  get IsDigitalSignatureEnabled(): Promise<boolean> {
    return this.#has(0x80);
  }

  get IsNonRepudiationEnabled(): Promise<boolean> {
    return this.#has(0x40);
  }

  get IsKeyEnciphermentEnabled(): Promise<boolean> {
    return this.#has(0x20);
  }

  get IsDataEnciphermentEnabled(): Promise<boolean> {
    return this.#has(0x10);
  }

  get IsKeyAgreementEnabled(): Promise<boolean> {
    return this.#has(0x08);
  }

  get IsKeyCertSignEnabled(): Promise<boolean> {
    return this.#has(0x04);
  }

  get IsCRLSignEnabled(): Promise<boolean> {
    return this.#has(0x02);
  }

  get IsEncipherOnlyEnabled(): Promise<boolean> {
    return this.#has(0x01);
  }

  get IsDecipherOnlyEnabled(): Promise<boolean> {
    return this.#has(0x8000);
  }
}

// CAPICOM_EKU's names (Microsoft's documentation of the enumeration); CAPICOM_EKU_OTHER for the rest.
const ekuNames = new Map<string, number>([
  ["1.3.6.1.5.5.7.3.1", 1],
  ["1.3.6.1.5.5.7.3.2", 2],
  ["1.3.6.1.5.5.7.3.3", 3],
  ["1.3.6.1.5.5.7.3.4", 4],
  ["1.3.6.1.4.1.311.20.2.2", 5],
  ["1.3.6.1.4.1.311.10.3.4", 6],
]);

class Eku {
  readonly #oid: string;

  constructor(oid: string) {
    this.#oid = oid;
  }

  get Name(): Promise<number> {
    return Promise.resolve(ekuNames.get(this.#oid) ?? constants.CAPICOM_EKU_OTHER);
  }

  get OID(): Promise<string> {
    return Promise.resolve(this.#oid);
  }
}

class Ekus {
  readonly #items: string[];

  constructor(items: string[]) {
    this.#items = items;
  }

  get Count(): Promise<number> {
    return Promise.resolve(this.#items.length);
  }

  async Item(index: number): Promise<Eku> {
    const item = this.#items[Number(index) - 1];
    if (item === undefined) throw new CadesError("Неверный индекс назначения", E_INVALIDARG);
    return new Eku(item);
  }
}

export class ExtendedKeyUsage {
  readonly #x509: X509;

  constructor(x509: X509) {
    this.#x509 = x509;
  }

  get IsPresent(): Promise<boolean> {
    return Promise.resolve(extendedKeyUsages(this.#x509) !== null);
  }

  get IsCritical(): Promise<boolean> {
    return Promise.resolve(extensionOf(this.#x509, EXTENSION_EXTENDED_KEY_USAGE)?.critical ?? false);
  }

  get EKUs(): Promise<Ekus> {
    return Promise.resolve(new Ekus(extendedKeyUsages(this.#x509) ?? []));
  }
}

export class BasicConstraints {
  readonly #x509: X509;

  constructor(x509: X509) {
    this.#x509 = x509;
  }

  get IsPresent(): Promise<boolean> {
    return Promise.resolve(basicConstraints(this.#x509) !== null);
  }

  get IsCritical(): Promise<boolean> {
    return Promise.resolve(extensionOf(this.#x509, EXTENSION_BASIC_CONSTRAINTS)?.critical ?? false);
  }

  get IsCertificateAuthority(): Promise<boolean> {
    return Promise.resolve(basicConstraints(this.#x509)?.ca ?? false);
  }

  get IsPathLenConstraintPresent(): Promise<boolean> {
    return Promise.resolve((basicConstraints(this.#x509)?.pathLength ?? null) !== null);
  }

  get PathLenConstraint(): Promise<number> {
    return Promise.resolve(basicConstraints(this.#x509)?.pathLength ?? 0);
  }
}
