import { constants } from "../constants.ts";
import { CadesError } from "../errors.ts";
import { signWithToken } from "../signing.ts";
import type { Session } from "./session.ts";
import { CPSigner } from "./signer.ts";

const E_INVALIDARG = 0x80070057;
const E_NOTIMPL = 0x80004001;
const CERT_E_EXPIRED = 0x800b0101;
// SignCades' type argument carries flags above the type itself (CADES_USE_OCSP_AUTHORIZED_POLICY).
const TYPE_MASK = 0xffff;

// UTF-16LE, what CryptoPro signs for a string under the default CADESCOM_STRING_TO_UCS2LE.
export function ucs2leBase64(text: string): string {
  let binary = "";
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    binary += String.fromCharCode(unit & 0xff, unit >> 8);
  }
  return btoa(binary);
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
    if (!(signer instanceof CPSigner)) throw new CadesError("Ожидается объект CAdESCOM.CPSigner", E_INVALIDARG);
    const kind = Number(type) & TYPE_MASK;
    const cades = kind === constants.CADESCOM_CADES_BES;
    if (!cades && kind !== constants.CADESCOM_PKCS7_TYPE) {
      throw new CadesError(`Тип подписи ${type} пока не поддерживается: доступны CAdES-BES и PKCS#7`, E_NOTIMPL);
    }
    const { token, checkCertificate, options } = signer.settings();
    if (!token) throw new CadesError("Не задан сертификат подписанта", E_INVALIDARG);
    if (checkCertificate) {
      const now = Date.now();
      if (now < token.x509.notBefore.getTime() || now > token.x509.notAfter.getTime()) {
        throw new CadesError("Срок действия сертификата истёк или ещё не начался", CERT_E_EXPIRED);
      }
    }
    const content = this.#encoding === constants.CADESCOM_BASE64_TO_BINARY ? this.#content.replace(/\s+/g, "") : ucs2leBase64(this.#content);
    if (!content) throw new CadesError("Нет данных для подписи", E_INVALIDARG);
    return signWithToken(this.#session, {
      token,
      content,
      options: {
        detached: Boolean(detached),
        addUserCertificate: options !== constants.CAPICOM_CERTIFICATE_INCLUDE_NONE,
        // CAdES-BES needs the signing-certificate-v2 attribute; the signing time is Rutoken's own.
        addEssCert: cades,
        addSignTime: cades,
      },
    });
  }
}
