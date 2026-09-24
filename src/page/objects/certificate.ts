import { CadesError } from "../errors.ts";
import { About } from "./about.ts";
import { constants } from "../constants.ts";
import { formatName } from "../dn.ts";
import { algorithmName, derToBase64, type X509 } from "../x509.ts";
import type { TokenCertificate } from "../token.ts";
import type { Session } from "./session.ts";

const E_INVALIDARG = 0x80070057;
const E_NOTIMPL = 0x80004001;
// CAPICOM_PROPID_KEY_PROV_INFO, not among cadesplugin_api.js's constants. With FIND_EXTENDED_PROPERTY it picks
// the certificates that have a key: CryptoPro 2.0.15700 finds 1 of 1 in My and 0 of 165 in Root (docs/JOURNAL.md).
const PROPID_KEY_PROV_INFO = 2;
// The properties CryptoPro 2.0.15700 finds on every certificate, key or not (3 and 4 are CAPICOM's SHA-1 and MD5
// hashes); the other ids up to 30 on none of them; ids above 30 are 0x80070057.
const PROPIDS_OF_EVERY_CERTIFICATE = new Set([3, 4, 15, 20]);
const PROPID_MAX = 30;

// Dates cross the CryptoPro async API as strings in this form (DateToUTCStr in nmcades_plugin_api.js);
// sites pass them to new Date(). Not yet compared with a real CryptoPro installation: docs/JOURNAL.md.
function dateString(date: Date): string {
  return date.toISOString();
}

class Oid {
  readonly #value: string;

  constructor(value: string) {
    this.#value = value;
  }

  get Value(): Promise<string> {
    return Promise.resolve(this.#value);
  }

  get FriendlyName(): Promise<string> {
    return Promise.resolve(algorithmName(this.#value));
  }
}

class PublicKey {
  readonly #algorithm: string;

  constructor(algorithm: string) {
    this.#algorithm = algorithm;
  }

  get Algorithm(): Promise<Oid> {
    return Promise.resolve(new Oid(this.#algorithm));
  }
}

class PrivateKey {
  readonly #session: Session;
  readonly #token: TokenCertificate;

  constructor(session: Session, token: TokenCertificate) {
    this.#session = session;
    this.#token = token;
  }

  // The same name CAdESCOM.About.CSPName() reports.
  get ProviderName(): Promise<string> {
    return new About(this.#session).CSPName();
  }

  // Names the token and the certificate on it; signing (stage 4) finds the key by it.
  get UniqueContainerName(): Promise<string> {
    return Promise.resolve(`\\\\.\\Rutoken ${this.#token.serial}\\${this.#token.certId}`);
  }

  get ContainerName(): Promise<string> {
    return this.UniqueContainerName;
  }

  // CryptoPro keeps an entered PIN for the key when this is on. We ask for the PIN on every signature and log
  // out after it, so the value is only remembered (markirovka.crpt.ru turns it off before signing).
  #cachePin = false;

  get CachePin(): Promise<boolean> {
    return Promise.resolve(this.#cachePin);
  }

  propset_CachePin(value: unknown): Promise<void> {
    this.#cachePin = Boolean(value);
    return Promise.resolve();
  }
}

class CertificateStatus {
  readonly #result: boolean;

  constructor(result: boolean) {
    this.#result = result;
  }

  get Result(): Promise<boolean> {
    return Promise.resolve(this.#result);
  }
}

// Which token certificate an emulated Certificate stands for; sites hand these objects back to us,
// e.g. in CPSigner.propset_Certificate, and must not be able to forge one.
const tokens = new WeakMap<object, TokenCertificate>();
// The parsed certificate behind each emulated one, for Certificates.Find.
const parsed = new WeakMap<Certificate, X509>();

export function tokenOf(certificate: unknown): TokenCertificate | undefined {
  return typeof certificate === "object" && certificate !== null ? tokens.get(certificate) : undefined;
}

const CRYPT_E_NOT_FOUND = 0x80092004;

// CAdESCOM.Certificate: a certificate on a Rutoken, with its key, or one from the root store, without.
export class Certificate {
  readonly #session: Session;
  readonly #x509: X509;
  readonly #token: TokenCertificate | undefined;

  constructor(session: Session, certificate: TokenCertificate | X509) {
    this.#session = session;
    if ("x509" in certificate) {
      this.#token = certificate;
      this.#x509 = certificate.x509;
      tokens.set(this, certificate);
    } else {
      this.#token = undefined;
      this.#x509 = certificate;
    }
    parsed.set(this, this.#x509);
  }

  get SubjectName(): Promise<string> {
    return Promise.resolve(formatName(this.#x509.subject));
  }

  get IssuerName(): Promise<string> {
    return Promise.resolve(formatName(this.#x509.issuer));
  }

  get SerialNumber(): Promise<string> {
    return Promise.resolve(this.#x509.serialNumber);
  }

  get Thumbprint(): Promise<string> {
    return Promise.resolve(this.#x509.thumbprint);
  }

  get Version(): Promise<number> {
    return Promise.resolve(this.#x509.version);
  }

  get ValidFromDate(): Promise<string> {
    return Promise.resolve(dateString(this.#x509.notBefore));
  }

  get ValidToDate(): Promise<string> {
    return Promise.resolve(dateString(this.#x509.notAfter));
  }

  // null when the certificate has no 2.5.29.16 extension, as the demo page expects.
  get PrivateKeyUsagePeriodFrom(): Promise<string | null> {
    const date = this.#x509.privateKeyNotBefore;
    return Promise.resolve(date && dateString(date));
  }

  get PrivateKeyUsagePeriodTo(): Promise<string | null> {
    const date = this.#x509.privateKeyNotAfter;
    return Promise.resolve(date && dateString(date));
  }

  // Knowing for sure needs getKeyByCertificate, which needs the PIN; user-category certificates on a
  // Rutoken come with their key. The real check happens when signing. Chosen in docs/PLAN.md, stage 3.
  // A root store certificate has no key: false, and PrivateKey fails with CRYPT_E_NOT_FOUND, as CryptoPro
  // 2.0.15700 answers for its Root store (checked on the stand, docs/JOURNAL.md).
  HasPrivateKey(): Promise<boolean> {
    return Promise.resolve(this.#token !== undefined);
  }

  get PrivateKey(): Promise<PrivateKey> {
    if (!this.#token) return Promise.reject(new CadesError("Cannot find object or property.", CRYPT_E_NOT_FOUND));
    return Promise.resolve(new PrivateKey(this.#session, this.#token));
  }

  PublicKey(): Promise<PublicKey> {
    return Promise.resolve(new PublicKey(this.#x509.publicKeyAlgorithm));
  }

  // Only base64, as the real plug-in: 64-column lines, each ending in LF (2.0.15700 on the stand, docs/JOURNAL.md);
  // it refuses binary with E_INVALIDARG. lkfl2.nalog.ru reads it for every certificate it lists.
  Export(encoding: number): Promise<string> {
    if (encoding !== constants.CADESCOM_ENCODE_BASE64) throw new CadesError(`Неподдерживаемая кодировка: ${encoding}`, E_INVALIDARG);
    const text = derToBase64(this.#x509.der);
    return Promise.resolve((text.match(/.{1,64}/g) ?? []).map((line) => `${line}\n`).join(""));
  }

  // Only the validity period is checked so far; chain building is a later task (docs/PLAN.md, stage 3).
  IsValid(): Promise<CertificateStatus> {
    const now = Date.now();
    const { notBefore, notAfter } = this.#x509;
    return Promise.resolve(new CertificateStatus(notBefore.getTime() <= now && now <= notAfter.getTime()));
  }
}

// CAdESCOM.Certificates: a fixed snapshot, indexed from 1 like every CAPICOM collection.
export class Certificates {
  readonly #items: Certificate[];

  constructor(items: Certificate[]) {
    this.#items = items;
  }

  get Count(): Promise<number> {
    return Promise.resolve(this.#items.length);
  }

  async Item(index: number): Promise<Certificate> {
    const item = this.#items[Number(index) - 1];
    if (!item) throw new CadesError("Неверный индекс сертификата", E_INVALIDARG);
    return item;
  }

  // CAPICOM's search, for the kinds sites use (lkfl2.nalog.ru looks up the certificate to sign with by its
  // SHA-1): by thumbprint, or by a piece of the subject or issuer name, ignoring case; by key usage and validity
  // time, and by extended property as CryptoPro 2.0.15700 answers (docs/JOURNAL.md): a key usage is one flag, a number (anything else is
  // 0x80070057), and a certificate without the extension has none; the time is the criterion, now if none.
  async Find(findType: number, criteria?: unknown, validOnly = false): Promise<Certificates> {
    const wanted = String(criteria ?? "");
    const type = Number(findType);
    const flag = Number(criteria);
    if (
      type === constants.CAPICOM_CERTIFICATE_FIND_EXTENDED_PROPERTY &&
      criteria !== undefined &&
      !(typeof criteria === "number" && Number.isInteger(flag) && flag >= 0 && flag <= PROPID_MAX)
    ) {
      throw new CadesError("The parameter is incorrect.", E_INVALIDARG);
    }
    if (
      type === constants.CAPICOM_CERTIFICATE_FIND_KEY_USAGE &&
      !(typeof criteria === "number" && Number.isInteger(flag) && flag > 0 && flag <= 0x8000 && (flag & (flag - 1)) === 0)
    ) {
      throw new CadesError("The parameter is incorrect.", E_INVALIDARG);
    }
    const at = criteria === undefined || criteria === null || criteria === "" ? Date.now() : new Date(criteria as string).getTime();
    const matches = async (item: Certificate): Promise<boolean> => {
      const x509 = parsed.get(item)!;
      switch (type) {
        case constants.CAPICOM_CERTIFICATE_FIND_SHA1_HASH:
          return (await item.Thumbprint).toLowerCase() === wanted.replace(/\s+/g, "").toLowerCase();
        case constants.CAPICOM_CERTIFICATE_FIND_SUBJECT_NAME:
          return (await item.SubjectName).toLowerCase().includes(wanted.toLowerCase());
        case constants.CAPICOM_CERTIFICATE_FIND_ISSUER_NAME:
          return (await item.IssuerName).toLowerCase().includes(wanted.toLowerCase());
        case constants.CAPICOM_CERTIFICATE_FIND_EXTENDED_PROPERTY:
          if (flag === PROPID_KEY_PROV_INFO) return item.HasPrivateKey();
          return PROPIDS_OF_EVERY_CERTIFICATE.has(flag);
        case constants.CAPICOM_CERTIFICATE_FIND_KEY_USAGE:
          return ((x509.keyUsage ?? 0) & flag) !== 0;
        case constants.CAPICOM_CERTIFICATE_FIND_TIME_VALID:
          return x509.notBefore.getTime() <= at && at <= x509.notAfter.getTime();
        case constants.CAPICOM_CERTIFICATE_FIND_TIME_NOT_YET_VALID:
          return at < x509.notBefore.getTime();
        case constants.CAPICOM_CERTIFICATE_FIND_TIME_EXPIRED:
          return x509.notAfter.getTime() < at;
        default:
          throw new CadesError(`Поиск сертификатов вида ${findType} не поддерживается`, E_NOTIMPL);
      }
    };
    const found: Certificate[] = [];
    for (const item of this.#items) {
      if ((await matches(item)) && (!validOnly || (await (await item.IsValid()).Result))) found.push(item);
    }
    return new Certificates(found);
  }
}
