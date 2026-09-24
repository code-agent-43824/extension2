import { chainError } from "../chain.ts";
import {
  ATTRIBUTE_CERTIFICATE_REFS,
  ATTRIBUTE_REVOCATION_REFS,
  ATTRIBUTE_SIGNATURE_TIMESTAMP,
  ATTRIBUTE_SIGNING_CERTIFICATE,
  ATTRIBUTE_SIGNING_CERTIFICATE_V2,
  checkSigner,
  findSignerCertificate,
  parseSignedData,
  signerDigest,
  signingCertificateMatches,
  signingTime,
  type SignedData,
  type SignerInfo,
} from "../cms.ts";
import { constants } from "../constants.ts";
import { CadesError } from "../errors.ts";
import { digest, isGostKey, type DigestName } from "../gost.ts";
import { signWithToken } from "../signing.ts";
import type { X509 } from "../x509.ts";
import { Certificate, Certificates, x509Of } from "./certificate.ts";
import { binaryBytes, bytesBinary, HashedData, ucs2leBinary } from "./hashed-data.ts";
import type { Session } from "./session.ts";
import { signerCertificate } from "./signer.ts";
import { Store } from "./store.ts";
import { Signers, type VerifiedSignature } from "./signers.ts";

const E_INVALIDARG = 0x80070057;
const E_NOTIMPL = 0x80004001;
// What CryptoPro's plug-in 2.0.15700 answers VerifyCades and VerifyHash with (docs/JOURNAL.md, 2026-09-24).
const NTE_BAD_SIGNATURE = 0x80090006;
const NTE_BAD_ALGID = 0x80090008;
const CRYPT_E_INVALID_MSG_TYPE = 0x80091004;
const CRYPT_E_HASH_VALUE = 0x80091007;
const CRYPT_E_SIGNER_NOT_FOUND = 0x8009100e;
const CRYPT_E_ATTRIBUTES_MISSING = 0x8009100f;
const CRYPT_E_NO_SIGNER = 0x8009200e;
const TRUST_E_NOSIGNATURE = 0x800b0100;
const CERT_E_WRONG_USAGE = 0x800b0110;
// Key usage bits (CAPICOM's flags, src/page/x509.ts) that allow a signature on data.
const SIGNATURE_KEY_USAGE = 0x80 | 0x40;
// SignCades' type argument carries flags above the type itself (CADES_USE_OCSP_AUTHORIZED_POLICY).
const TYPE_MASK = 0xffff;

// The texts the real plug-in gives these codes (Windows' messages).
const certificateMessages = new Map<number, string>([
  [0x800b0101, "A required certificate is not within its validity period when verifying against the current system clock or the timestamp in the signed file."],
  [0x800b010a, "A certificate chain could not be built to a trusted root authority."],
  [CERT_E_WRONG_USAGE, "The certificate is not valid for the requested usage."],
]);

// UTF-16LE, what CryptoPro signs for a string under the default CADESCOM_STRING_TO_UCS2LE.
export function ucs2leBase64(text: string): string {
  return btoa(ucs2leBinary(text));
}

// The hash algorithm CryptoPro's plug-in requires for each GOST key: another one fails with E_INVALIDARG
// (checked with 2.0.15700 for a 256-bit key, docs/JOURNAL.md 2026-09-24).
const hashForKey = new Map<string, number>([
  ["1.2.643.2.2.19", constants.CADESCOM_HASH_ALGORITHM_CP_GOST_3411],
  ["1.2.643.7.1.1.1.1", constants.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256],
  ["1.2.643.7.1.1.1.2", constants.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_512],
]);

// CAdES-BES and PKCS#7 are what the Rutoken Plugin's sign() makes; the other types need a timestamp service.
function signatureKind(type: number): number {
  const kind = Number(type) & TYPE_MASK;
  if (kind !== constants.CADESCOM_CADES_BES && kind !== constants.CADESCOM_PKCS7_TYPE) {
    throw new CadesError(`Тип подписи ${type} пока не поддерживается: доступны CAdES-BES и PKCS#7`, E_NOTIMPL);
  }
  return kind;
}

// The unsigned attributes each CAdES type beyond BES needs; the real plug-in answers a signature without them
// with CRYPT_E_ATTRIBUTES_MISSING (CADES_DEFAULT means X Long Type 1).
const xLong = [ATTRIBUTE_SIGNATURE_TIMESTAMP, ATTRIBUTE_CERTIFICATE_REFS, ATTRIBUTE_REVOCATION_REFS];
const requiredAttributes = new Map<number, string[]>([
  [constants.CADESCOM_CADES_BES, []],
  [constants.CADESCOM_PKCS7_TYPE, []],
  [constants.CADESCOM_CADES_T, [ATTRIBUTE_SIGNATURE_TIMESTAMP]],
  [constants.CADESCOM_CADES_X_LONG_TYPE_1, xLong],
  [constants.CADESCOM_CADES_DEFAULT, xLong],
  [constants.CADESCOM_CADES_A, xLong],
]);

function decodeMessage(message: unknown): SignedData {
  if (typeof message !== "string" || !message.trim()) throw new CadesError("Нет подписи для проверки", E_INVALIDARG);
  try {
    return parseSignedData(binaryBytes(atob(message.replace(/\s+/g, ""))));
  } catch {
    throw new CadesError("Cannot find the original signer.", CRYPT_E_SIGNER_NOT_FOUND);
  }
}

function fromHex(hex: string): Uint8Array {
  return Uint8Array.from(hex.match(/../g) ?? [], (byte) => parseInt(byte, 16));
}

// CAdESCOM.CadesSignedData: signing on the token; verification in the page (src/page/cms.ts, src/page/gost.ts),
// with the chain ending in the extension's root store and without revocation checks (docs/PLAN.md, action 16).
export class CadesSignedData {
  readonly #session: Session;
  #encoding: number = constants.CADESCOM_STRING_TO_UCS2LE;
  #content = "";
  #displayData = 0;
  // Certificates of the stores AdditionalStore added: more candidates for the signer and the chain.
  #additional: X509[] = [];
  // What the last verification found; undefined before one, or after one that failed on the signature.
  #verified: { signers: VerifiedSignature[]; certificates: X509[] } | undefined;

  constructor(session: Session) {
    this.#session = session;
  }

  get ContentEncoding(): Promise<number> {
    return Promise.resolve(this.#encoding);
  }

  async propset_ContentEncoding(encoding: number): Promise<void> {
    const value = Number(encoding);
    if (value !== constants.CADESCOM_STRING_TO_UCS2LE && value !== constants.CADESCOM_BASE64_TO_BINARY) {
      throw new CadesError(`Неизвестная кодировка содержимого: ${encoding}`, E_INVALIDARG);
    }
    this.#encoding = value;
  }

  get Content(): Promise<string> {
    return Promise.resolve(this.#content);
  }

  propset_Content(content: unknown): Promise<void> {
    this.#content = String(content);
    return Promise.resolve();
  }

  // For Rutoken PINPad devices; the PIN window always shows what is being signed.
  get DisplayData(): Promise<number> {
    return Promise.resolve(this.#displayData);
  }

  propset_DisplayData(value: number): Promise<void> {
    this.#displayData = Number(value);
    return Promise.resolve();
  }

  async SignCades(signer: unknown, type: number = constants.CADESCOM_CADES_DEFAULT, detached: unknown = false): Promise<string> {
    const kind = signatureKind(type);
    const { token, options } = signerCertificate(signer);
    const cades = kind === constants.CADESCOM_CADES_BES;
    const content = this.#encoding === constants.CADESCOM_BASE64_TO_BINARY ? this.#content.replace(/\s+/g, "") : ucs2leBase64(this.#content);
    if (!content) throw new CadesError("Нет данных для подписи", E_INVALIDARG);
    return signWithToken(this.#session, {
      token,
      content,
      hash: false,
      options: {
        detached: Boolean(detached),
        addUserCertificate: options !== constants.CAPICOM_CERTIFICATE_INCLUDE_NONE,
        // CAdES-BES needs the signing-certificate-v2 attribute; the signing time is Rutoken's own.
        addEssCert: cades,
        addSignTime: cades,
      },
    });
  }

  // A detached signature of a hash computed by CAdESCOM.HashedData. CryptoPro's plug-in 2.0.15700 puts the
  // same signed attributes (content type, signing time, message digest, signing-certificate-v2) into the
  // PKCS#7 type as into CAdES-BES, and takes only Base64 output.
  async SignHash(hashed: unknown, signer: unknown, type: number = constants.CADESCOM_CADES_DEFAULT, encoding: number = constants.CADESCOM_ENCODE_BASE64): Promise<string> {
    if (!(hashed instanceof HashedData)) throw new CadesError("Ожидается объект CAdESCOM.HashedData", E_INVALIDARG);
    signatureKind(type);
    if (Number(encoding) !== constants.CADESCOM_ENCODE_BASE64) throw new CadesError("Подпись хеша выдаётся только в Base64", E_INVALIDARG);
    const { token, options } = signerCertificate(signer);
    const { algorithm, value } = await hashed.hash();
    const required = hashForKey.get(token.x509.publicKeyAlgorithm);
    if (required !== undefined && required !== algorithm) {
      throw new CadesError("Алгоритм хеша не подходит к ключу сертификата", E_INVALIDARG);
    }
    return signWithToken(this.#session, {
      token,
      content: value,
      hash: true,
      options: {
        detached: true,
        addUserCertificate: options !== constants.CAPICOM_CERTIFICATE_INCLUDE_NONE,
        addEssCert: true,
        addSignTime: true,
      },
    });
  }

  // Signers and Certificates exist once a verification has checked the signature itself; before, or after
  // a signature that did not verify, the real plug-in answers TRUST_E_NOSIGNATURE.
  get Signers(): Promise<Signers> {
    const verified = this.#verified;
    if (!verified) return Promise.reject(new CadesError("No signature was present in the subject.", TRUST_E_NOSIGNATURE));
    return Promise.resolve(new Signers(this.#session, verified.signers));
  }

  get Certificates(): Promise<Certificates> {
    const verified = this.#verified;
    if (!verified) return Promise.reject(new CadesError("No signature was present in the subject.", TRUST_E_NOSIGNATURE));
    return Promise.resolve(new Certificates(verified.certificates.map((x509) => new Certificate(this.#session, x509))));
  }

  // Adds a store's certificates to those verification looks in, as the demo page verify.html does with the
  // (for us empty) AddressBook store; anything but a store is E_INVALIDARG, as with plug-in 2.0.15700.
  async AdditionalStore(store: unknown): Promise<void> {
    if (!(store instanceof Store)) throw new CadesError("The parameter is incorrect.", E_INVALIDARG);
    const certificates = await store.Certificates;
    const count = await certificates.Count;
    for (let i = 1; i <= count; i++) {
      const x509 = x509Of(await certificates.Item(i));
      if (x509) this.#additional.push(x509);
    }
  }

  // The type a signature was made as, by its first signer's attributes, as plug-in 2.0.15700 answers
  // (docs/JOURNAL.md, 2026-09-24): a signature timestamp makes CAdES-T, a signing-certificate attribute
  // CAdES-BES, neither PKCS#7. X Long and A signatures were not at hand to check; they come out as CAdES-T,
  // which VerifyCades does not verify either.
  async GetMsgType(message: unknown): Promise<number> {
    if (typeof message !== "string" || !message.trim()) throw new CadesError("The parameter is incorrect.", E_INVALIDARG);
    let info: SignerInfo | undefined;
    try {
      info = parseSignedData(binaryBytes(atob(message.replace(/\s+/g, "")))).signers[0];
    } catch {
      info = undefined;
    }
    if (!info) throw new CadesError("Invalid cryptographic message type.", CRYPT_E_INVALID_MSG_TYPE);
    if (info.unsignedAttributes.has(ATTRIBUTE_SIGNATURE_TIMESTAMP)) return constants.CADESCOM_CADES_T;
    if (info.signedAttributes.has(ATTRIBUTE_SIGNING_CERTIFICATE_V2) || info.signedAttributes.has(ATTRIBUTE_SIGNING_CERTIFICATE)) {
      return constants.CADESCOM_CADES_BES;
    }
    return constants.CADESCOM_PKCS7_TYPE;
  }

  // Verifies an attached signature, or a detached one of Content. On success an attached signature's content
  // becomes Content, decoded by ContentEncoding.
  async VerifyCades(message: unknown, type: number = constants.CADESCOM_CADES_DEFAULT, detached: unknown = false): Promise<void> {
    const kind = Number(type) & TYPE_MASK;
    if (!requiredAttributes.has(kind)) throw new CadesError(`Неизвестный тип подписи ${type}`, E_INVALIDARG);
    this.#verified = undefined;
    const cms = decodeMessage(message);
    let content = cms.content;
    if (!content && detached) {
      try {
        content = binaryBytes(this.#encoding === constants.CADESCOM_BASE64_TO_BINARY ? atob(this.#content.replace(/\s+/g, "")) : ucs2leBinary(this.#content));
      } catch {
        throw new CadesError("Содержимое не в Base64", E_INVALIDARG);
      }
    }
    await this.#verify(cms, kind, (name) => (content ? digest(name, content) : undefined), NTE_BAD_SIGNATURE);
    if (cms.content) {
      this.#content =
        this.#encoding === constants.CADESCOM_BASE64_TO_BINARY ? btoa(bytesBinary(cms.content)) : new TextDecoder("utf-16le").decode(cms.content);
    }
  }

  // Verifies a signature of the hash a CAdESCOM.HashedData holds: the message digest must be that hash.
  async VerifyHash(hashed: unknown, message: unknown, type: number = constants.CADESCOM_CADES_DEFAULT): Promise<void> {
    if (!(hashed instanceof HashedData)) throw new CadesError("Ожидается объект CAdESCOM.HashedData", E_INVALIDARG);
    const kind = Number(type) & TYPE_MASK;
    if (!requiredAttributes.has(kind)) throw new CadesError(`Неизвестный тип подписи ${type}`, E_INVALIDARG);
    this.#verified = undefined;
    const cms = decodeMessage(message);
    const hash = fromHex((await hashed.hash()).value);
    await this.#verify(cms, kind, () => hash, CRYPT_E_HASH_VALUE);
  }

  // Checks every signer: the signature over the content's hash (`hashFor`, undefined without content), the
  // signing-certificate attribute, then the certificate's key usage and chain. A failure of the signature
  // itself leaves no signers; a certificate failure leaves them, marked not valid.
  async #verify(cms: SignedData, kind: number, hashFor: (name: DigestName) => Uint8Array | undefined, mismatch: number): Promise<void> {
    if (cms.signers.length === 0) throw new CadesError("Cannot find the original signer.", CRYPT_E_SIGNER_NOT_FOUND);
    const required = requiredAttributes.get(kind)!;
    if (cms.signers.some((info) => required.some((oid) => !info.unsignedAttributes.has(oid)))) {
      throw new CadesError("The cryptographic message does not contain all of the requested attributes.", CRYPT_E_ATTRIBUTES_MISSING);
    }
    if (required.length > 0) throw new CadesError("Проверка штампов времени и доказательств CAdES-T и X Long пока не поддерживается", E_NOTIMPL);
    const roots = await this.#session.rootCertificates();
    const found: { info: SignerInfo; certificate: X509 }[] = [];
    for (const info of cms.signers) {
      const certificate = findSignerCertificate(info, [...cms.certificates, ...this.#additional, ...roots]);
      if (!certificate) throw new CadesError("Cannot find the original signer.", CRYPT_E_SIGNER_NOT_FOUND);
      const name = signerDigest(info);
      if (!name || !isGostKey(certificate)) throw new CadesError("Проверяются только подписи ГОСТ Р 34.10", NTE_BAD_ALGID);
      const hash = hashFor(name);
      const check = hash ? checkSigner(info, certificate, hash) : "bad-signature";
      if (check !== "valid") throw new CadesError(check === "digest-mismatch" && mismatch === CRYPT_E_HASH_VALUE ? "The hash value is not correct." : "Invalid Signature.", check === "digest-mismatch" ? mismatch : NTE_BAD_SIGNATURE);
      const hasSigningCertificate = info.signedAttributes.has(ATTRIBUTE_SIGNING_CERTIFICATE_V2) || info.signedAttributes.has(ATTRIBUTE_SIGNING_CERTIFICATE);
      if ((kind !== constants.CADESCOM_PKCS7_TYPE && !hasSigningCertificate) || !signingCertificateMatches(info, certificate)) {
        throw new CadesError("The signed cryptographic message does not have a signer for the specified signer index.", CRYPT_E_NO_SIGNER);
      }
      found.push({ info, certificate });
    }
    let error: number | null = null;
    const signers = found.map(({ info, certificate }): VerifiedSignature => {
      const usage = certificate.keyUsage;
      const problem = usage !== null && !(usage & SIGNATURE_KEY_USAGE) ? CERT_E_WRONG_USAGE : chainError(certificate, [...cms.certificates, ...this.#additional], roots);
      error ??= problem;
      return { certificate, signingTime: signingTime(info), valid: problem === null };
    });
    this.#verified = { signers, certificates: cms.certificates };
    if (error !== null) throw new CadesError(certificateMessages.get(error) ?? "Certificate check failed.", error);
  }
}
