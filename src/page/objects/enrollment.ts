// X509Enrollment objects for getting a certificate from a CA web page (Microsoft certsrv, as on
// testgost2012.cryptopro.ru): the page describes a key and a request, CX509Enrollment.CreateRequest
// makes the key on the Rutoken and returns a PKCS#10 request, and InstallResponse writes the issued
// certificate next to that key. Only what such pages call is emulated; defaults in docs/PLAN.md, stage 5.
import { children, decodeOid, expectTag, read } from "../asn1.ts";
import { constants } from "../constants.ts";
import { formatName, parseNameString, type Attribute } from "../dn.ts";
import { CadesError } from "../errors.ts";
import { RutokenError, rutokenErrorCode, type RutokenPlugin, type SubjectAttribute } from "../rutoken.ts";
import { certificateLines, commonName } from "../signing.ts";
import { singleDevice, withLogin } from "../token-login.ts";
import { parseCertificate, pemToDer, type X509 } from "../x509.ts";
import { About } from "./about.ts";
import type { Session } from "./session.ts";

const E_INVALIDARG = 0x80070057;
const E_NOTIMPL = 0x80004001;
const E_UNEXPECTED = 0x8000ffff;
const CRYPT_E_NOT_FOUND = 0x80092004;

// X509KeySpec and AlgorithmType values from CertEnroll.
const AT_KEYEXCHANGE = 1;
const AT_SIGNATURE = 2;
const XCN_CRYPT_HASH_INTERFACE = 2;
const XCN_CRYPT_SIGNATURE_INTERFACE = 5;

// The two "providers" we list, one per GOST key size. Type 80 is what CryptoPro CSP registers for
// GOST R 34.10-2012 256 and pages pre-select it; 81 is its 512-bit type. Length is the public key
// size in bits, as CSPs report it for GOST.
interface Provider {
  type: number;
  suffix: string;
  length: number;
  publicKeyAlgorithm: "PUBLIC_KEY_ALGORITHM_GOST3410_2012_256" | "PUBLIC_KEY_ALGORITHM_GOST3410_2012_512";
  signatureSize: number;
  hashOid: string;
  hashType: "HASH_TYPE_GOST3411_12_256" | "HASH_TYPE_GOST3411_12_512";
  algorithmName: string;
}

const providers: Provider[] = [
  {
    type: 80,
    suffix: "",
    length: 512,
    publicKeyAlgorithm: "PUBLIC_KEY_ALGORITHM_GOST3410_2012_256",
    signatureSize: 512,
    hashOid: "1.2.643.7.1.1.2.2",
    hashType: "HASH_TYPE_GOST3411_12_256",
    algorithmName: "ГОСТ Р 34.10-2012 256 бит",
  },
  {
    type: 81,
    suffix: " (ГОСТ Р 34.10-2012 512 бит)",
    length: 1024,
    publicKeyAlgorithm: "PUBLIC_KEY_ALGORITHM_GOST3410_2012_512",
    signatureSize: 1024,
    hashOid: "1.2.643.7.1.1.2.3",
    hashType: "HASH_TYPE_GOST3411_12_512",
    algorithmName: "ГОСТ Р 34.10-2012 512 бит",
  },
];

// Our own labels for the OIDs these pages show in lists; any other OID shows as itself.
const oidNames = new Map<string, string>([
  ["1.2.643.7.1.1.2.2", "ГОСТ Р 34.11-2012 256 бит"],
  ["1.2.643.7.1.1.2.3", "ГОСТ Р 34.11-2012 512 бит"],
  ["1.2.643.7.1.1.1.1", "ГОСТ Р 34.10-2012 256 бит"],
  ["1.2.643.7.1.1.1.2", "ГОСТ Р 34.10-2012 512 бит"],
  ["1.3.6.1.5.5.7.3.2", "Проверка подлинности клиента"],
  ["1.3.6.1.5.5.7.3.4", "Защищённая электронная почта"],
]);

async function providerName(session: Session, provider: Provider): Promise<string> {
  return (await new About(session).CSPName()) + provider.suffix;
}

async function providerByName(session: Session, name: string): Promise<Provider | undefined> {
  for (const provider of providers) if ((await providerName(session, provider)) === name) return provider;
  return undefined;
}

// X509Enrollment.CObjectId.
export class ObjectId {
  #value = "";

  async InitializeFromValue(value: string): Promise<void> {
    const text = String(value).trim();
    if (!/^\d+(\.\d+)+$/.test(text)) throw new CadesError(`Неверный OID «${text}»`, E_INVALIDARG);
    this.#value = text;
  }

  get Value(): Promise<string> {
    return Promise.resolve(this.#value);
  }

  get FriendlyName(): Promise<string> {
    return Promise.resolve(oidNames.get(this.#value) ?? this.#value);
  }

  get value(): string {
    return this.#value;
  }

  static of(value: string): ObjectId {
    const id = new ObjectId();
    id.#value = value;
    return id;
  }
}

// X509Enrollment.CObjectIds, indexed from 0 like every CertEnroll collection.
export class ObjectIds {
  readonly items: ObjectId[] = [];

  get Count(): Promise<number> {
    return Promise.resolve(this.items.length);
  }

  async Add(id: ObjectId): Promise<void> {
    if (!(id instanceof ObjectId)) throw new CadesError("Ожидается объект X509Enrollment.CObjectId", E_INVALIDARG);
    this.items.push(id);
  }

  async ItemByIndex(index: number): Promise<ObjectId> {
    const item = this.items[Number(index)];
    if (!item) throw new CadesError("Неверный индекс", E_INVALIDARG);
    return item;
  }
}

// KeyUsage bits as CryptoAPI numbers them (CERT_*_KEY_USAGE), with the names the Rutoken Plugin takes.
const keyUsageBits: [number, string][] = [
  [0x80, "digitalSignature"],
  [0x40, "nonRepudiation"],
  [0x20, "keyEncipherment"],
  [0x10, "dataEncipherment"],
  [0x08, "keyAgreement"],
  [0x04, "keyCertSign"],
  [0x02, "cRLSign"],
  [0x01, "encipherOnly"],
  [0x8000, "decipherOnly"],
];

// X509Enrollment.CX509ExtensionKeyUsage.
export class ExtensionKeyUsage {
  usages: string[] = [];

  async InitializeEncode(flags: number): Promise<void> {
    this.usages = keyUsageBits.filter(([bit]) => Number(flags) & bit).map(([, name]) => name);
  }
}

// X509Enrollment.CX509ExtensionEnhancedKeyUsage.
export class ExtensionEnhancedKeyUsage {
  oids: string[] = [];

  async InitializeEncode(ids: ObjectIds): Promise<void> {
    if (!(ids instanceof ObjectIds)) throw new CadesError("Ожидается объект X509Enrollment.CObjectIds", E_INVALIDARG);
    this.oids = ids.items.map((id) => id.value);
  }
}

type Extension = ExtensionKeyUsage | ExtensionEnhancedKeyUsage;

// X509Enrollment.CX509Extensions.
export class Extensions {
  readonly items: Extension[] = [];

  get Count(): Promise<number> {
    return Promise.resolve(this.items.length);
  }

  async Add(extension: Extension): Promise<void> {
    if (!(extension instanceof ExtensionKeyUsage || extension instanceof ExtensionEnhancedKeyUsage)) {
      throw new CadesError("Расширение этого типа Рутокен Плагин в запрос не добавляет", E_NOTIMPL);
    }
    this.items.push(extension);
  }

  async ItemByIndex(index: number): Promise<Extension> {
    const item = this.items[Number(index)];
    if (!item) throw new CadesError("Неверный индекс", E_INVALIDARG);
    return item;
  }
}

// X509Enrollment.CX500DistinguishedName.
export class DistinguishedName {
  attributes: Attribute[] = [];

  async Encode(name: string, _flags?: number): Promise<void> {
    try {
      this.attributes = parseNameString(String(name));
    } catch (error) {
      throw new CadesError(`Неверное имя субъекта: ${(error as Error).message}`, E_INVALIDARG);
    }
  }

  get Name(): Promise<string> {
    return Promise.resolve(formatName(this.attributes.map((attribute) => [attribute])));
  }
}

// X509Enrollment.CX509PrivateKey: only a description of the key to create; the key itself appears
// on the token in CreateRequest. Every field reads as a Promise and is set with propset_<field>.
const keyDefaults = {
  ProviderName: "",
  ProviderType: 0,
  KeySpec: AT_KEYEXCHANGE,
  ContainerName: "",
  Existing: false,
  MachineContext: false,
  KeyProtection: 0,
  ExportPolicy: 0,
  Length: 0,
};

type KeyFields = typeof keyDefaults;

export interface PrivateKey extends Readonly<{ [K in keyof KeyFields]: Promise<KeyFields[K]> }> {}

export class PrivateKey {
  readonly fields: KeyFields = { ...keyDefaults };
}

for (const [key, initial] of Object.entries(keyDefaults)) {
  const convert = typeof initial === "number" ? Number : typeof initial === "boolean" ? Boolean : String;
  Object.defineProperty(PrivateKey.prototype, key, {
    get(this: PrivateKey) {
      return Promise.resolve(this.fields[key as keyof KeyFields]);
    },
  });
  Object.defineProperty(PrivateKey.prototype, `propset_${key}`, {
    value(this: PrivateKey, value: unknown) {
      (this.fields as Record<string, unknown>)[key] = convert(value);
      return Promise.resolve();
    },
  });
}

// X509Enrollment.CX509CertificateRequestPkcs10.
export class CertificateRequestPkcs10 {
  readonly #session: Session;
  readonly #extensions = new Extensions();
  #privateKey: PrivateKey | undefined;
  #provider: Provider | undefined;
  #subject: DistinguishedName | undefined;
  #hash: string | undefined;

  constructor(session: Session) {
    this.#session = session;
  }

  async InitializeFromPrivateKey(context: number, privateKey: PrivateKey, _template?: string): Promise<void> {
    if (!(privateKey instanceof PrivateKey)) throw new CadesError("Ожидается объект X509Enrollment.CX509PrivateKey", E_INVALIDARG);
    const key = privateKey.fields;
    if (Number(context) !== constants.ContextUser || key.MachineContext) {
      throw new CadesError("Ключ на Рутокене создаётся только для пользователя, не для компьютера", E_NOTIMPL);
    }
    if (key.Existing) throw new CadesError("Запрос на существующий ключ Рутокен Плагин не создаёт", E_NOTIMPL);
    const provider = await providerByName(this.#session, key.ProviderName);
    if (!provider) throw new CadesError(`Провайдер «${key.ProviderName}» не найден`, CRYPT_E_NOT_FOUND);
    this.#privateKey = privateKey;
    this.#provider = provider;
  }

  get PrivateKey(): Promise<PrivateKey | undefined> {
    return Promise.resolve(this.#privateKey);
  }

  get X509Extensions(): Promise<Extensions> {
    return Promise.resolve(this.#extensions);
  }

  get Subject(): Promise<DistinguishedName | undefined> {
    return Promise.resolve(this.#subject);
  }

  async propset_Subject(subject: DistinguishedName): Promise<void> {
    if (!(subject instanceof DistinguishedName)) throw new CadesError("Ожидается объект X509Enrollment.CX500DistinguishedName", E_INVALIDARG);
    this.#subject = subject;
  }

  get HashAlgorithm(): Promise<ObjectId | undefined> {
    return Promise.resolve(this.#hash === undefined ? undefined : ObjectId.of(this.#hash));
  }

  async propset_HashAlgorithm(id: ObjectId): Promise<void> {
    if (!(id instanceof ObjectId)) throw new CadesError("Ожидается объект X509Enrollment.CObjectId", E_INVALIDARG);
    if (!providers.some((provider) => provider.hashOid === id.value)) {
      throw new CadesError(`Алгоритм хеширования ${id.value} Рутокен Плагин в запросе не поддерживает`, E_NOTIMPL);
    }
    this.#hash = id.value;
  }

  // What CreateRequest needs, checked before the PIN is asked for.
  job(): RequestJob {
    const key = this.#privateKey;
    const provider = this.#provider;
    if (!key || !provider) throw new CadesError("Запрос не инициализирован: не вызван InitializeFromPrivateKey", E_UNEXPECTED);
    const subject = this.#subject?.attributes ?? [];
    if (subject.length === 0) throw new CadesError("В запросе нет имени субъекта", E_INVALIDARG);
    const hash = providers.find((candidate) => candidate.hashOid === this.#hash) ?? provider;
    return {
      provider,
      hashType: hash.hashType,
      signOnly: key.fields.KeySpec === AT_SIGNATURE,
      subject,
      keyUsage: this.#extensions.items.flatMap((extension) => (extension instanceof ExtensionKeyUsage ? extension.usages : [])),
      extKeyUsage: this.#extensions.items.flatMap((extension) => (extension instanceof ExtensionEnhancedKeyUsage ? extension.oids : [])),
    };
  }
}

interface RequestJob {
  provider: Provider;
  hashType: Provider["hashType"];
  signOnly: boolean;
  subject: Attribute[];
  keyUsage: string[];
  extKeyUsage: string[];
}

// Names from the Rutoken Plugin's createPkcs10 list; other attributes go by OID, which it also takes.
const rdnNames = new Map<string, string>([
  ["2.5.4.3", "commonName"],
  ["2.5.4.4", "surname"],
  ["2.5.4.42", "givenName"],
  ["2.5.4.6", "countryName"],
  ["2.5.4.8", "stateOrProvinceName"],
  ["2.5.4.7", "localityName"],
  ["2.5.4.9", "streetAddress"],
  ["2.5.4.10", "organizationName"],
  ["2.5.4.11", "organizationalUnitName"],
  ["2.5.4.12", "title"],
  ["1.2.643.100.1", "OGRN"],
  ["1.2.643.100.3", "SNILS"],
  ["1.2.643.3.131.1.1", "INN"],
  ["1.2.643.100.4", "INNLE"],
  ["1.2.643.100.5", "OGRNIP"],
  ["1.2.840.113549.1.9.1", "emailAddress"],
]);

function subjectAttributes(subject: Attribute[]): SubjectAttribute[] {
  return subject.map(({ oid, value }) => ({ rdn: rdnNames.get(oid) ?? oid, value }));
}

function base64(der: Uint8Array): string {
  let binary = "";
  for (const byte of der) binary += String.fromCharCode(byte);
  return btoa(binary);
}

// CryptBinaryToString layout: 64-column lines ending in CRLF.
function lines(text: string): string {
  return (text.match(/.{1,64}/g) ?? []).map((line) => `${line}\r\n`).join("");
}

const requestEncodings: number[] = [
  constants.XCN_CRYPT_STRING_BASE64REQUESTHEADER,
  constants.XCN_CRYPT_STRING_BASE64HEADER,
  constants.XCN_CRYPT_STRING_BASE64,
];

function encodeRequest(der: Uint8Array, encoding: number): string {
  switch (Number(encoding)) {
    case constants.XCN_CRYPT_STRING_BASE64REQUESTHEADER:
      return `-----BEGIN NEW CERTIFICATE REQUEST-----\r\n${lines(base64(der))}-----END NEW CERTIFICATE REQUEST-----\r\n`;
    case constants.XCN_CRYPT_STRING_BASE64HEADER:
      return `-----BEGIN CERTIFICATE REQUEST-----\r\n${lines(base64(der))}-----END CERTIFICATE REQUEST-----\r\n`;
    case constants.XCN_CRYPT_STRING_BASE64:
      return lines(base64(der));
    default:
      throw new CadesError(`Кодировка запроса ${encoding} не поддерживается`, E_NOTIMPL);
  }
}

function toPem(der: Uint8Array): string {
  return `-----BEGIN CERTIFICATE-----\n${(base64(der).match(/.{1,64}/g) ?? []).join("\n")}\n-----END CERTIFICATE-----\n`;
}

const SIGNED_DATA = "1.2.840.113549.1.7.2";

// The certificates of a CA response: a PKCS#7/CMC SignedData (certsrv sends CMC) or one certificate,
// in base64 with or without a PEM header (CRYPT_STRING_ANY accepts all of these).
export function responseCertificates(response: string): X509[] {
  const der = pemToDer(String(response));
  const top = expectTag(read(der), 0x30, "ответ УЦ");
  const [first, content] = children(top);
  if (first?.tag !== 0x06) return [parseCertificate(top.der)];
  if (decodeOid(first.value) !== SIGNED_DATA) throw new Error("ответ УЦ не SignedData");
  const signedData = children(expectTag(children(expectTag(content, 0xa0, "content"))[0], 0x30, "SignedData"));
  const certificates = signedData.find((node) => node.tag === 0xa0);
  return certificates ? children(certificates).filter((node) => node.tag === 0x30).map((node) => parseCertificate(node.der)) : [];
}

const nameKey = (x509: X509["subject"]) => formatName(x509);

// The certificate issued to the user: not self-signed and not the issuer of another one in the set.
export function endEntity(certificates: X509[]): X509 | undefined {
  const issuers = new Set(certificates.filter((c) => nameKey(c.issuer) !== nameKey(c.subject)).map((c) => nameKey(c.issuer)));
  const leaves = certificates.filter((c) => nameKey(c.issuer) !== nameKey(c.subject) && !issuers.has(nameKey(c.subject)));
  return leaves.length === 1 ? leaves[0] : undefined;
}

function algorithmOf(plugin: RutokenPlugin, name: Provider["publicKeyAlgorithm"] | Provider["hashType"] | "KEY_SPEC_SIGN" | "KEY_SPEC_SIGN_AND_EXCHANGE"): PromiseLike<number> {
  return plugin[name];
}

// X509Enrollment.CX509Enrollment.
export class Enrollment {
  readonly #session: Session;
  #request: CertificateRequestPkcs10 | undefined;
  #friendlyName = "";

  constructor(session: Session) {
    this.#session = session;
  }

  async Initialize(context: number): Promise<void> {
    if (Number(context) !== constants.ContextUser) throw new CadesError("Сертификат на Рутокен ставится только для пользователя", E_NOTIMPL);
  }

  async InitializeFromRequest(request: CertificateRequestPkcs10): Promise<void> {
    if (!(request instanceof CertificateRequestPkcs10)) {
      throw new CadesError("Ожидается объект X509Enrollment.CX509CertificateRequestPkcs10", E_INVALIDARG);
    }
    this.#request = request;
  }

  get Request(): Promise<CertificateRequestPkcs10 | undefined> {
    return Promise.resolve(this.#request);
  }

  // Kept for the page to read back; the Rutoken Plugin gives certificates no friendly name.
  get CertificateFriendlyName(): Promise<string> {
    return Promise.resolve(this.#friendlyName);
  }

  propset_CertificateFriendlyName(name: string): Promise<void> {
    this.#friendlyName = String(name);
    return Promise.resolve();
  }

  // Makes the key pair on the token and returns the request signed with it.
  async CreateRequest(encoding: number = constants.XCN_CRYPT_STRING_BASE64): Promise<string> {
    if (!this.#request) throw new CadesError("Не вызван InitializeFromRequest", E_UNEXPECTED);
    const job = this.#request.job();
    if (!requestEncodings.includes(Number(encoding))) throw new CadesError(`Кодировка запроса ${encoding} не поддерживается`, E_NOTIMPL);
    const plugin = this.#session.plugin;
    const { deviceId, serial } = await singleDevice(this.#session);
    const owner = job.subject.find((attribute) => attribute.oid === "2.5.4.3")?.value ?? formatName(job.subject.map((a) => [a]));
    const request = {
      origin: this.#session.origin,
      action: "просит создать на Рутокене ключ и запрос на сертификат.",
      details: [`Владелец: ${owner}`, `Ключ: ${job.provider.algorithmName}`, `Рутокен ${serial}`],
      confirm: "Создать",
    };
    const pem = await withLogin(this.#session, deviceId, request, async () => {
      const keyId = await plugin.generateKeyPair(deviceId, undefined, "", {
        publicKeyAlgorithm: await algorithmOf(plugin, job.provider.publicKeyAlgorithm),
        signatureSize: job.provider.signatureSize,
        keySpec: await algorithmOf(plugin, job.signOnly ? "KEY_SPEC_SIGN" : "KEY_SPEC_SIGN_AND_EXCHANGE"),
      });
      try {
        const extensions = {
          ...(job.keyUsage.length ? { keyUsage: job.keyUsage } : {}),
          ...(job.extKeyUsage.length ? { extKeyUsage: job.extKeyUsage } : {}),
        };
        return await plugin.createPkcs10(deviceId, keyId, subjectAttributes(job.subject), extensions, {
          hashAlgorithm: await algorithmOf(plugin, job.hashType),
        });
      } catch (error) {
        // A key nobody can get a certificate for is only clutter on the token.
        try {
          await plugin.deleteKeyPair(deviceId, keyId);
        } catch {
          // Reported below is the original failure.
        }
        throw error;
      }
    });
    return encodeRequest(pemToDer(pem), encoding);
  }

  // Writes the issued certificate onto the token that holds its key. CA certificates in the response
  // are not written: signing needs only the user's certificate (docs/PLAN.md, stage 5).
  async InstallResponse(_restrictions: number, response: string, _encoding?: number, _password?: string): Promise<void> {
    let certificate: X509 | undefined;
    try {
      certificate = endEntity(responseCertificates(response));
    } catch (error) {
      throw new CadesError(`Ответ УЦ не разобран: ${(error as Error).message}`, E_INVALIDARG);
    }
    if (!certificate) throw new CadesError("В ответе УЦ не найден сертификат пользователя", CRYPT_E_NOT_FOUND);
    const plugin = this.#session.plugin;
    const { deviceId, serial } = await singleDevice(this.#session);
    const request = {
      origin: this.#session.origin,
      action: "просит записать сертификат на Рутокен.",
      details: [...certificateLines(certificate), `Рутокен ${serial}`],
      confirm: "Записать",
    };
    await withLogin(this.#session, deviceId, request, async () => {
      const category = await plugin.CERT_CATEGORY_USER;
      let certId: string;
      try {
        certId = await plugin.importCertificate(deviceId, toPem(certificate.der), category);
      } catch (error) {
        // Installing the same response twice leaves the token as it is, like a second install into a store.
        if (rutokenErrorCode(error) === RutokenError.CERTIFICATE_EXISTS) return;
        throw error;
      }
      let keyId: string | undefined;
      try {
        keyId = await plugin.getKeyByCertificate(deviceId, certId);
      } catch (error) {
        if (rutokenErrorCode(error) !== RutokenError.KEY_NOT_FOUND) throw error;
      }
      if (!keyId) {
        await plugin.deleteCertificate(deviceId, certId);
        throw new CadesError(`На Рутокене нет ключа для сертификата «${commonName(certificate.subject)}»`, CRYPT_E_NOT_FOUND);
      }
    });
  }
}

// X509Enrollment.CCspAlgorithm: the key or hash algorithm of one of our providers.
class CspAlgorithm {
  readonly #provider: Provider;
  readonly #type: number;

  constructor(provider: Provider, type: number) {
    this.#provider = provider;
    this.#type = type;
  }

  get Type(): Promise<number> {
    return Promise.resolve(this.#type);
  }

  get Name(): Promise<string> {
    return Promise.resolve(oidNames.get(this.#oid()) ?? this.#oid());
  }

  get MinLength(): Promise<number> {
    return Promise.resolve(this.#provider.length);
  }

  get MaxLength(): Promise<number> {
    return Promise.resolve(this.#provider.length);
  }

  get DefaultLength(): Promise<number> {
    return Promise.resolve(this.#provider.length);
  }

  get IncrementLength(): Promise<number> {
    return Promise.resolve(0);
  }

  async GetAlgorithmOid(_length?: number, _flags?: number): Promise<ObjectId> {
    return ObjectId.of(this.#oid());
  }

  #oid(): string {
    if (this.#type === XCN_CRYPT_HASH_INTERFACE) return this.#provider.hashOid;
    return this.#provider.type === 80 ? "1.2.643.7.1.1.1.1" : "1.2.643.7.1.1.1.2";
  }
}

class CspAlgorithms {
  readonly #items: CspAlgorithm[];

  constructor(provider: Provider) {
    this.#items = [new CspAlgorithm(provider, XCN_CRYPT_SIGNATURE_INTERFACE), new CspAlgorithm(provider, XCN_CRYPT_HASH_INTERFACE)];
  }

  get Count(): Promise<number> {
    return Promise.resolve(this.#items.length);
  }

  async ItemByIndex(index: number): Promise<CspAlgorithm> {
    const item = this.#items[Number(index)];
    if (!item) throw new CadesError("Неверный индекс", E_INVALIDARG);
    return item;
  }
}

// X509Enrollment.CCspInformation as an item of CCspInformations.
class ProviderInformation {
  readonly #provider: Provider;
  readonly #name: string;

  constructor(provider: Provider, name: string) {
    this.#provider = provider;
    this.#name = name;
  }

  get Name(): Promise<string> {
    return Promise.resolve(this.#name);
  }

  get Type(): Promise<number> {
    return Promise.resolve(this.#provider.type);
  }

  get LegacyCsp(): Promise<boolean> {
    return Promise.resolve(true);
  }

  get IsHardwareDevice(): Promise<boolean> {
    return Promise.resolve(true);
  }

  // Signature and key exchange, so pages offer both; KEY_SPEC_SIGN is used when a site asks for signature only.
  get KeySpec(): Promise<number> {
    return Promise.resolve(AT_KEYEXCHANGE | AT_SIGNATURE);
  }

  get CspAlgorithms(): Promise<CspAlgorithms> {
    return Promise.resolve(new CspAlgorithms(this.#provider));
  }
}

class CspStatus {
  readonly #algorithm: CspAlgorithm;

  constructor(algorithm: CspAlgorithm) {
    this.#algorithm = algorithm;
  }

  get CspAlgorithm(): Promise<CspAlgorithm> {
    return Promise.resolve(this.#algorithm);
  }
}

// X509Enrollment.CCspInformations.
export class CspInformations {
  readonly #session: Session;
  #items: ProviderInformation[] = [];

  constructor(session: Session) {
    this.#session = session;
  }

  async AddAvailableCsps(): Promise<void> {
    const items: ProviderInformation[] = [];
    for (const provider of providers) items.push(new ProviderInformation(provider, await providerName(this.#session, provider)));
    this.#items = items;
  }

  get Count(): Promise<number> {
    return Promise.resolve(this.#items.length);
  }

  async ItemByIndex(index: number): Promise<ProviderInformation> {
    const item = this.#items[Number(index)];
    if (!item) throw new CadesError("Неверный индекс", E_INVALIDARG);
    return item;
  }

  async ItemByName(name: string): Promise<ProviderInformation> {
    for (const item of this.#items) if ((await item.Name) === String(name)) return item;
    throw new CadesError(`Провайдер «${name}» не найден`, CRYPT_E_NOT_FOUND);
  }

  async GetCspStatusFromProviderName(name: string, _keySpec?: number): Promise<CspStatus> {
    const provider = await providerByName(this.#session, String(name));
    if (!provider) throw new CadesError(`Провайдер «${name}» не найден`, CRYPT_E_NOT_FOUND);
    return new CspStatus(new CspAlgorithm(provider, XCN_CRYPT_SIGNATURE_INTERFACE));
  }
}
