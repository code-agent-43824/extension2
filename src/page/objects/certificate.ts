import { CadesError } from "../errors.ts";
import { About } from "./about.ts";
import { constants } from "../constants.ts";
import { formatName } from "../dn.ts";
import { algorithmName, derToBase64 } from "../x509.ts";
import type { TokenCertificate } from "../token.ts";
import type { Session } from "./session.ts";

const E_INVALIDARG = 0x80070057;
const E_NOTIMPL = 0x80004001;

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

export function tokenOf(certificate: unknown): TokenCertificate | undefined {
  return typeof certificate === "object" && certificate !== null ? tokens.get(certificate) : undefined;
}

// CAdESCOM.Certificate for a certificate on a Rutoken.
export class Certificate {
  readonly #session: Session;
  readonly #token: TokenCertificate;

  constructor(session: Session, token: TokenCertificate) {
    this.#session = session;
    this.#token = token;
    tokens.set(this, token);
  }

  get SubjectName(): Promise<string> {
    return Promise.resolve(formatName(this.#token.x509.subject));
  }

  get IssuerName(): Promise<string> {
    return Promise.resolve(formatName(this.#token.x509.issuer));
  }

  get SerialNumber(): Promise<string> {
    return Promise.resolve(this.#token.x509.serialNumber);
  }

  get Thumbprint(): Promise<string> {
    return Promise.resolve(this.#token.x509.thumbprint);
  }

  get Version(): Promise<number> {
    return Promise.resolve(this.#token.x509.version);
  }

  get ValidFromDate(): Promise<string> {
    return Promise.resolve(dateString(this.#token.x509.notBefore));
  }

  get ValidToDate(): Promise<string> {
    return Promise.resolve(dateString(this.#token.x509.notAfter));
  }

  // null when the certificate has no 2.5.29.16 extension, as the demo page expects.
  get PrivateKeyUsagePeriodFrom(): Promise<string | null> {
    const date = this.#token.x509.privateKeyNotBefore;
    return Promise.resolve(date && dateString(date));
  }

  get PrivateKeyUsagePeriodTo(): Promise<string | null> {
    const date = this.#token.x509.privateKeyNotAfter;
    return Promise.resolve(date && dateString(date));
  }

  // Knowing for sure needs getKeyByCertificate, which needs the PIN; user-category certificates on a
  // Rutoken come with their key. The real check happens when signing. Chosen in docs/PLAN.md, stage 3.
  HasPrivateKey(): Promise<boolean> {
    return Promise.resolve(true);
  }

  get PrivateKey(): Promise<PrivateKey> {
    return Promise.resolve(new PrivateKey(this.#session, this.#token));
  }

  PublicKey(): Promise<PublicKey> {
    return Promise.resolve(new PublicKey(this.#token.x509.publicKeyAlgorithm));
  }

  // Only base64, as the real plug-in: 64-column lines, each ending in LF (2.0.15700 on the stand, docs/JOURNAL.md);
  // it refuses binary with E_INVALIDARG. lkfl2.nalog.ru reads it for every certificate it lists.
  Export(encoding: number): Promise<string> {
    if (encoding !== constants.CADESCOM_ENCODE_BASE64) throw new CadesError(`Неподдерживаемая кодировка: ${encoding}`, E_INVALIDARG);
    const text = derToBase64(this.#token.x509.der);
    return Promise.resolve((text.match(/.{1,64}/g) ?? []).map((line) => `${line}\n`).join(""));
  }

  // Only the validity period is checked so far; chain building is a later task (docs/PLAN.md, stage 3).
  IsValid(): Promise<CertificateStatus> {
    const now = Date.now();
    const { notBefore, notAfter } = this.#token.x509;
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
  // SHA-1): by thumbprint, or by a piece of the subject or issuer name, ignoring case.
  async Find(findType: number, criteria: unknown, validOnly = false): Promise<Certificates> {
    const wanted = String(criteria ?? "");
    const matches = async (item: Certificate): Promise<boolean> => {
      switch (Number(findType)) {
        case constants.CAPICOM_CERTIFICATE_FIND_SHA1_HASH:
          return (await item.Thumbprint).toLowerCase() === wanted.replace(/\s+/g, "").toLowerCase();
        case constants.CAPICOM_CERTIFICATE_FIND_SUBJECT_NAME:
          return (await item.SubjectName).toLowerCase().includes(wanted.toLowerCase());
        case constants.CAPICOM_CERTIFICATE_FIND_ISSUER_NAME:
          return (await item.IssuerName).toLowerCase().includes(wanted.toLowerCase());
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
