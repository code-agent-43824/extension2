import { constants } from "../constants.ts";
import { CadesError } from "../errors.ts";
import { signWithToken } from "../signing.ts";
import type { TokenCertificate } from "../token.ts";
import { HashedData, ucs2leBinary } from "./hashed-data.ts";
import type { Session } from "./session.ts";
import { CPSigner } from "./signer.ts";

const E_INVALIDARG = 0x80070057;
const E_NOTIMPL = 0x80004001;
const CERT_E_EXPIRED = 0x800b0101;
// SignCades' type argument carries flags above the type itself (CADES_USE_OCSP_AUTHORIZED_POLICY).
const TYPE_MASK = 0xffff;

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

// The signer's certificate, checked as SignCades and SignHash both need it.
function signerToken(signer: unknown): { token: TokenCertificate; options: number } {
  if (!(signer instanceof CPSigner)) throw new CadesError("Ожидается объект CAdESCOM.CPSigner", E_INVALIDARG);
  const { token, checkCertificate, options } = signer.settings();
  if (!token) throw new CadesError("Не задан сертификат подписанта", E_INVALIDARG);
  if (checkCertificate) {
    const now = Date.now();
    if (now < token.x509.notBefore.getTime() || now > token.x509.notAfter.getTime()) {
      throw new CadesError("Срок действия сертификата истёк или ещё не начался", CERT_E_EXPIRED);
    }
  }
  return { token, options };
}

// CAdES-BES and PKCS#7 are what the Rutoken Plugin's sign() makes; the other types need a timestamp service.
function signatureKind(type: number): number {
  const kind = Number(type) & TYPE_MASK;
  if (kind !== constants.CADESCOM_CADES_BES && kind !== constants.CADESCOM_PKCS7_TYPE) {
    throw new CadesError(`Тип подписи ${type} пока не поддерживается: доступны CAdES-BES и PKCS#7`, E_NOTIMPL);
  }
  return kind;
}

// CAdESCOM.CadesSignedData, signing only for now (verification and co-signing: stage 6).
export class CadesSignedData {
  readonly #session: Session;
  #encoding: number = constants.CADESCOM_STRING_TO_UCS2LE;
  #content = "";
  #displayData = 0;

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
    const { token, options } = signerToken(signer);
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
    const { token, options } = signerToken(signer);
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
}
