import { encode, octets, read } from "../asn1.ts";
import { attribute, encodeTime } from "../cms-sign.ts";
import { constants } from "../constants.ts";
import { CadesError } from "../errors.ts";
import type { TokenCertificate } from "../token.ts";
import { tokenOf } from "./certificate.ts";
import { binaryBytes, bytesBinary, ucs2leBinary } from "./hashed-data.ts";

const E_INVALIDARG = 0x80070057;
const CERT_E_EXPIRED = 0x800b0101;
// What CryptoPro's plug-in 2.0.15700 answers a type needing a timestamp when TSAAddress is empty (docs/JOURNAL.md,
// 2026-09-24).
const TSP_URL_NOT_SPECIFIED = 0xc2100121;

// The OIDs of CADESCOM_ATTRIBUTE's names: signingTime, and CAPICOM's document name and description, which .NET's
// Pkcs9DocumentName and Pkcs9DocumentDescription write as an OCTET STRING of UTF-16LE text ending in a zero character.
const ATTRIBUTE_OTHER = 0xffffffff;
const attributeOids = new Map<number, string>([
  [constants.CADESCOM_AUTHENTICATED_ATTRIBUTE_SIGNING_TIME, "1.2.840.113549.1.9.5"],
  [constants.CADESCOM_AUTHENTICATED_ATTRIBUTE_DOCUMENT_NAME, "1.3.6.1.4.1.311.88.2.1"],
  [constants.CADESCOM_AUTHENTICATED_ATTRIBUTE_DOCUMENT_DESCRIPTION, "1.3.6.1.4.1.311.88.2.2"],
]);
const E_NOTIMPL = 0x80004001;

// CAPICOM.OID of an attribute: setting its Value names the attribute.
class AttributeOid {
  readonly #attribute: CPAttribute;

  constructor(attribute: CPAttribute) {
    this.#attribute = attribute;
  }

  get Value(): Promise<string> {
    return Promise.resolve(this.#attribute.oid());
  }

  async propset_Value(value: unknown): Promise<void> {
    const oid = String(value ?? "");
    if (!/^[0-2](\.\d+)+$/.test(oid)) throw new CadesError(`Неверный OID: ${oid}`, E_INVALIDARG);
    this.#attribute.setOid(oid);
  }
}

// CADESCOM.CPAttribute: a signed attribute the site adds through the signer's AuthenticatedAttributes2. Name picks
// one CryptoPro knows; any other goes by OID.Value with its DER value in Base64 (ValueEncoding CAPICOM_ENCODE_BASE64).
export class CPAttribute {
  #name: number = constants.CAPICOM_AUTHENTICATED_ATTRIBUTE_SIGNING_TIME;
  #oid = attributeOids.get(constants.CAPICOM_AUTHENTICATED_ATTRIBUTE_SIGNING_TIME)!;
  #value: unknown;
  #encoding: number = constants.CADESCOM_ENCODE_ANY;
  // The value as encoded, for an attribute read from a verified signature.
  #der: Uint8Array | undefined;

  // An attribute of a verified signature, its Value as plug-in 2.0.15700 gives it (the owner's comparison,
  // docs/JOURNAL.md, 2026-10-29): a document's name or description as text; any other, the signing time included, the
  // contents of its value without the outer tag and length, read as UTF-8 with U+FFFD for what is not (a UTCTime comes
  // out as "261028193617Z"). With CAPICOM_ENCODE_BASE64, Base64 of the value's DER (not compared).
  static fromSignature(oid: string, der: Uint8Array): CPAttribute {
    const result = new CPAttribute();
    result.setOid(oid);
    result.#der = der;
    try {
      const node = read(der);
      const named = result.#name === constants.CADESCOM_AUTHENTICATED_ATTRIBUTE_DOCUMENT_NAME || result.#name === constants.CADESCOM_AUTHENTICATED_ATTRIBUTE_DOCUMENT_DESCRIPTION;
      result.#value = named ? new TextDecoder("utf-16le").decode(octets(node)).replace(/\0+$/, "") : new TextDecoder("utf-8", { ignoreBOM: true }).decode(node.value);
    } catch {
      result.#value = btoa(bytesBinary(der));
    }
    return result;
  }

  get Name(): Promise<number> {
    return Promise.resolve(this.#name);
  }

  async propset_Name(name: number): Promise<void> {
    const value = Number(name) >>> 0;
    const oid = attributeOids.get(value);
    if (oid) this.#oid = oid;
    else if (value !== ATTRIBUTE_OTHER) throw new CadesError(`Атрибут ${name} не поддерживается`, E_NOTIMPL);
    this.#name = value === ATTRIBUTE_OTHER ? constants.CADESCOM_ATTRIBUTE_OTHER : value;
  }

  get OID(): Promise<AttributeOid> {
    return Promise.resolve(new AttributeOid(this));
  }

  get Value(): Promise<unknown> {
    if (this.#der && this.#encoding === constants.CADESCOM_ENCODE_BASE64) return Promise.resolve(btoa(bytesBinary(this.#der)));
    return Promise.resolve(this.#value);
  }

  propset_Value(value: unknown): Promise<void> {
    this.#value = value;
    this.#der = undefined;
    return Promise.resolve();
  }

  get ValueEncoding(): Promise<number> {
    return Promise.resolve(this.#encoding);
  }

  async propset_ValueEncoding(encoding: number): Promise<void> {
    const value = Number(encoding);
    // The browser plug-in has no binary values (CryptoPro's documentation of ValueEncoding).
    if (value !== constants.CADESCOM_ENCODE_BASE64 && value !== constants.CADESCOM_ENCODE_ANY) {
      throw new CadesError(`Кодировка значения ${encoding} не поддерживается`, E_INVALIDARG);
    }
    this.#encoding = value;
  }

  oid(): string {
    return this.#oid;
  }

  setOid(oid: string): void {
    this.#oid = oid;
    const known = [...attributeOids].find(([, value]) => value === oid);
    this.#name = known ? known[0] : constants.CADESCOM_ATTRIBUTE_OTHER;
  }

  // The DER Attribute for the signature.
  der(): Uint8Array {
    if (this.#encoding === constants.CADESCOM_ENCODE_BASE64) {
      let value: Uint8Array;
      try {
        value = binaryBytes(atob(String(this.#value ?? "").replace(/\s+/g, "")));
        if (read(value).der.length !== value.length) throw new Error("trailing bytes");
      } catch {
        throw new CadesError(`Значение атрибута ${this.#oid} — не DER в Base64`, E_INVALIDARG);
      }
      return attribute(this.#oid, value);
    }
    if (this.#oid === attributeOids.get(constants.CADESCOM_AUTHENTICATED_ATTRIBUTE_SIGNING_TIME)) {
      const date = this.#value instanceof Date ? this.#value : new Date(this.#value as string);
      if (Number.isNaN(date.getTime())) throw new CadesError("Время подписи — не дата", E_INVALIDARG);
      return attribute(this.#oid, encodeTime(date));
    }
    if (this.#name === constants.CADESCOM_ATTRIBUTE_OTHER) {
      throw new CadesError(`Значение атрибута ${this.#oid} задаётся в Base64 (ValueEncoding = CAPICOM_ENCODE_BASE64)`, E_INVALIDARG);
    }
    return attribute(this.#oid, encode(0x04, binaryBytes(ucs2leBinary(`${String(this.#value ?? "")}\0`))));
  }
}

// CAdESCOM.CPAttributes, the signer's AuthenticatedAttributes2 collection, indexed from 1.
export class CPAttributes {
  readonly #items: CPAttribute[];

  constructor(items: CPAttribute[] = []) {
    this.#items = items;
  }

  get Count(): Promise<number> {
    return Promise.resolve(this.#items.length);
  }

  async Add(attribute: CPAttribute): Promise<void> {
    if (!(attribute instanceof CPAttribute)) throw new CadesError("Ожидается объект CADESCOM.CPAttribute", E_INVALIDARG);
    this.#items.push(attribute);
  }

  async Item(index: number): Promise<CPAttribute> {
    const item = this.#items[Number(index) - 1];
    if (!item) throw new CadesError("Неверный индекс атрибута", E_INVALIDARG);
    return item;
  }

  async Remove(index: number): Promise<void> {
    if (!this.#items[Number(index) - 1]) throw new CadesError("Неверный индекс атрибута", E_INVALIDARG);
    this.#items.splice(Number(index) - 1, 1);
  }

  Clear(): Promise<void> {
    this.#items.length = 0;
    return Promise.resolve();
  }

  // Each attribute as DER, for the signature.
  der(): Uint8Array[] {
    return this.#items.map((item) => item.der());
  }
}

// CAdESCOM.CPSigner.
export class CPSigner {
  #certificate: object | undefined;
  #checkCertificate = false;
  #options: number = constants.CAPICOM_CERTIFICATE_INCLUDE_CHAIN_EXCEPT_ROOT;
  #tsaAddress = "";
  #keyPin = "";
  readonly #attributes = new CPAttributes();

  get Certificate(): Promise<object | undefined> {
    return Promise.resolve(this.#certificate);
  }

  async propset_Certificate(certificate: object): Promise<void> {
    if (!tokenOf(certificate)) throw new CadesError("Сертификат должен быть получен из хранилища", E_INVALIDARG);
    this.#certificate = certificate;
  }

  get CheckCertificate(): Promise<boolean> {
    return Promise.resolve(this.#checkCertificate);
  }

  propset_CheckCertificate(value: unknown): Promise<void> {
    this.#checkCertificate = Boolean(value);
    return Promise.resolve();
  }

  get Options(): Promise<number> {
    return Promise.resolve(this.#options);
  }

  propset_Options(value: number): Promise<void> {
    this.#options = Number(value);
    return Promise.resolve();
  }

  get AuthenticatedAttributes2(): Promise<CPAttributes> {
    return Promise.resolve(this.#attributes);
  }

  // The timestamp service's address, for CAdES-T (docs/PLAN.md, action 25); webtools.html sets it, empty unless
  // filled in, for every signature.
  get TSAAddress(): Promise<string> {
    return Promise.resolve(this.#tsaAddress);
  }

  propset_TSAAddress(address: unknown): Promise<void> {
    this.#tsaAddress = address === undefined || address === null ? "" : String(address);
    return Promise.resolve();
  }

  // The token's PIN, given by the site: the PIN window then only asks the user to confirm (src/page/token-login.ts).
  // Write-only, as in CryptoPro's ICPSigner4.
  propset_KeyPin(pin: unknown): Promise<void> {
    this.#keyPin = pin === undefined || pin === null ? "" : String(pin);
    return Promise.resolve();
  }

  // For CadesSignedData: what the site configured, without going through the async surface.
  settings(): { token: TokenCertificate | undefined; checkCertificate: boolean; options: number; tsaAddress: string; keyPin: string; attributes: CPAttributes } {
    return {
      token: tokenOf(this.#certificate),
      checkCertificate: this.#checkCertificate,
      options: this.#options,
      tsaAddress: this.#tsaAddress,
      keyPin: this.#keyPin,
      attributes: this.#attributes,
    };
  }
}

// The signer's certificate for signing, with CheckCertificate applied: what SignCades, SignHash and
// SignedXML.Sign all need first.
// `attributes` are the site's signed attributes as DER.
export function signerCertificate(signer: unknown): { token: TokenCertificate; options: number; tsaAddress: string; keyPin: string; attributes: Uint8Array[] } {
  if (!(signer instanceof CPSigner)) throw new CadesError("Ожидается объект CAdESCOM.CPSigner", E_INVALIDARG);
  const { token, checkCertificate, options, tsaAddress, keyPin, attributes } = signer.settings();
  if (!token) throw new CadesError("Не задан сертификат подписанта", E_INVALIDARG);
  if (checkCertificate) {
    const now = Date.now();
    if (now < token.x509.notBefore.getTime() || now > token.x509.notAfter.getTime()) {
      throw new CadesError("Срок действия сертификата истёк или ещё не начался", CERT_E_EXPIRED);
    }
  }
  return { token, options, tsaAddress, keyPin, attributes: attributes.der() };
}

// The signer's TSAAddress for a signature that needs a timestamp (CAdES-T, XAdES-T).
export function tsaUrl(address: string): URL {
  if (!address.trim()) throw new CadesError("The URL of TSP service is not specified", TSP_URL_NOT_SPECIFIED);
  try {
    const url = new URL(address.trim());
    if (url.protocol === "http:" || url.protocol === "https:") return url;
  } catch {
    // Reported below with the address as given.
  }
  throw new CadesError(`Неверный адрес службы штампов времени: ${address}`, E_INVALIDARG);
}
