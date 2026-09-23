import { CadesError } from "../errors.ts";
import { About } from "./about.ts";
import { formatName } from "../dn.ts";
import type { TokenCertificate } from "../token.ts";
import type { Session } from "./session.ts";

const E_INVALIDARG = 0x80070057;

// Dates cross the CryptoPro async API as strings in this form (DateToUTCStr in nmcades_plugin_api.js);
// sites pass them to new Date(). Not yet compared with a real CryptoPro installation: docs/JOURNAL.md.
function dateString(date: Date): string {
  return date.toISOString();
}

// Friendly names CryptoPro gives the GOST public key algorithms; other algorithms show their OID.
const algorithmNames = new Map<string, string>([
  ["1.2.643.2.2.19", "ГОСТ Р 34.10-2001"],
  ["1.2.643.7.1.1.1.1", "ГОСТ Р 34.10-2012 256 бит"],
  ["1.2.643.7.1.1.1.2", "ГОСТ Р 34.10-2012 512 бит"],
]);

class Oid {
  readonly #value: string;

  constructor(value: string) {
    this.#value = value;
  }

  get Value(): Promise<string> {
    return Promise.resolve(this.#value);
  }

  get FriendlyName(): Promise<string> {
    return Promise.resolve(algorithmNames.get(this.#value) ?? this.#value);
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

// CAdESCOM.Certificate for a certificate on a Rutoken.
export class Certificate {
  readonly #session: Session;
  readonly #token: TokenCertificate;

  constructor(session: Session, token: TokenCertificate) {
    this.#session = session;
    this.#token = token;
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
}
