import { read } from "../asn1.ts";
import { envelopedRecipients, identifies, type CertificateId } from "../cms.ts";
import { constants } from "../constants.ts";
import { CadesError } from "../errors.ts";
import { rutokenErrorCode, type RutokenPlugin } from "../rutoken.ts";
import { certificateLines, commonName, sizeText } from "../signing.ts";
import { findDevice, userCertificates } from "../token.ts";
import { singleDevice, withLogin } from "../token-login.ts";
import { derToBase64, type X509 } from "../x509.ts";
import { Certificate, tokenOf, x509Of } from "./certificate.ts";
import { binaryBytes, bytesBinary, ucs2leBinary } from "./hashed-data.ts";
import type { Session } from "./session.ts";

const E_INVALIDARG = 0x80070057;
const E_FAIL = 0x80004005;
const NTE_BAD_DATA = 0x80090005;
const NTE_BAD_ALGID = 0x80090008;
const CRYPT_E_INVALID_MSG_TYPE = 0x80091004;
const CRYPT_E_NO_DECRYPT_CERT = 0x8009200c;
// CAPICOM's, not among cadesplugin_api.js's constants: the longest key the algorithm has.
const CAPICOM_ENCRYPTION_KEY_LENGTH_MAXIMUM = 0;

type CipherConstant =
  | "CIPHER_ALGORITHM_GOST28147"
  | "CIPHER_ALGORITHM_MAGMA_CTR_ACPKM"
  | "CIPHER_ALGORITHM_MAGMA_CTR_ACPKM_OMAC"
  | "CIPHER_ALGORITHM_KUZNECHIK_CTR_ACPKM"
  | "CIPHER_ALGORITHM_KUZNECHIK_CTR_ACPKM_OMAC";

// CryptoPro's GOST algorithms and the Rutoken Plugin's ciphers for them: GOST 28147-89, and "Magma" and
// "Kuznyechik" in CTR-ACPKM mode, with an OMAC or without, as the CMS of GOST R 34.12-2015 defines them.
const ciphers = new Map<number, { constant: CipherConstant; name: string }>([
  [constants.CADESCOM_ENCRYPTION_ALGORITHM_GOST_28147_89, { constant: "CIPHER_ALGORITHM_GOST28147", name: "ГОСТ 28147-89" }],
  [constants.CADESCOM_ENCRYPTION_ALGORITHM_GOST_MAGMA, { constant: "CIPHER_ALGORITHM_MAGMA_CTR_ACPKM", name: "«Магма»" }],
  [constants.CADESCOM_ENCRYPTION_ALGORITHM_GOST_MAGMA_OMAC, { constant: "CIPHER_ALGORITHM_MAGMA_CTR_ACPKM_OMAC", name: "«Магма» с имитовставкой" }],
  [constants.CADESCOM_ENCRYPTION_ALGORITHM_GOST_KUZNYECHIK, { constant: "CIPHER_ALGORITHM_KUZNECHIK_CTR_ACPKM", name: "«Кузнечик»" }],
  [constants.CADESCOM_ENCRYPTION_ALGORITHM_GOST_KUZNYECHIK_OMAC, { constant: "CIPHER_ALGORITHM_KUZNECHIK_CTR_ACPKM_OMAC", name: "«Кузнечик» с имитовставкой" }],
]);

// The Algorithm property: which cipher Encrypt uses, GOST 28147-89 unless the site says otherwise
// (docs/PLAN.md, action 24); an algorithm without a GOST cipher is refused when encrypting.
class Algorithm {
  #name: number = constants.CADESCOM_ENCRYPTION_ALGORITHM_GOST_28147_89;
  #keyLength = CAPICOM_ENCRYPTION_KEY_LENGTH_MAXIMUM;

  get Name(): Promise<number> {
    return Promise.resolve(this.#name);
  }

  propset_Name(name: unknown): Promise<void> {
    this.#name = Number(name);
    return Promise.resolve();
  }

  // Kept only: every GOST cipher has a 256-bit key.
  get KeyLength(): Promise<number> {
    return Promise.resolve(this.#keyLength);
  }

  propset_KeyLength(length: unknown): Promise<void> {
    this.#keyLength = Number(length);
    return Promise.resolve();
  }

  cipher(): { constant: CipherConstant; name: string } {
    const cipher = ciphers.get(this.#name);
    if (!cipher) throw new CadesError(`Алгоритм шифрования ${this.#name} не поддерживается: доступны ГОСТ 28147-89, «Магма» и «Кузнечик»`, NTE_BAD_ALGID);
    return cipher;
  }
}

// The Recipients property: the certificates to encrypt for, indexed from 1 like every CAPICOM collection.
class Recipients {
  readonly #items: Certificate[] = [];

  get Count(): Promise<number> {
    return Promise.resolve(this.#items.length);
  }

  async Item(index: number): Promise<Certificate> {
    const item = this.#items[Number(index) - 1];
    if (!item) throw new CadesError("The parameter is incorrect.", E_INVALIDARG);
    return item;
  }

  async Add(certificate: unknown): Promise<void> {
    if (!x509Of(certificate)) throw new CadesError("The parameter is incorrect.", E_INVALIDARG);
    this.#items.push(certificate as Certificate);
  }

  async Remove(index: number): Promise<void> {
    if (!this.#items[Number(index) - 1]) throw new CadesError("The parameter is incorrect.", E_INVALIDARG);
    this.#items.splice(Number(index) - 1, 1);
  }

  Clear(): Promise<void> {
    this.#items.length = 0;
    return Promise.resolve();
  }

  certificates(): Certificate[] {
    return [...this.#items];
  }
}

function pem(x509: X509): string {
  const lines = derToBase64(x509.der).match(/.{1,64}/g) ?? [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----\n`;
}

function decodeBase64(text: unknown): string {
  try {
    return atob(String(text ?? "").replace(/\s+/g, ""));
  } catch {
    throw new CadesError("Данные не в Base64", E_INVALIDARG);
  }
}

// A whole BER message, or undefined while more of it is still to come. A CMS ContentInfo is a SEQUENCE.
function complete(bytes: Uint8Array): Uint8Array | undefined {
  if (bytes.length > 0 && bytes[0] !== 0x30) throw new CadesError("Invalid cryptographic message type.", CRYPT_E_INVALID_MSG_TYPE);
  try {
    return read(bytes).der;
  } catch (error) {
    if (error instanceof Error && /truncated/.test(error.message)) return undefined;
    throw new CadesError("Invalid cryptographic message type.", CRYPT_E_INVALID_MSG_TYPE);
  }
}

function pluginFailure(action: string, error: unknown, code: number): unknown {
  const rutoken = rutokenErrorCode(error);
  return rutoken === undefined ? error : new CadesError(`Рутокен Плагин не ${action} сообщение: ошибка ${rutoken}`, code);
}

// CAdESCOM.CPEnvelopedData: CMS encryption and decryption by the Rutoken Plugin's cmsEncrypt and cmsDecrypt
// (docs/PLAN.md, action 24). Both need the token's PIN: the plugin encrypts only after a login, although no key of
// the token is used then. Encrypt and Decrypt take and give Content as ContentEncoding says; the Stream methods
// take and give Base64 pieces, whole messages coming out once all their pieces are in.
export class CPEnvelopedData {
  readonly #session: Session;
  readonly #algorithm = new Algorithm();
  readonly #recipients = new Recipients();
  #encoding: number = constants.CADESCOM_STRING_TO_UCS2LE;
  #content = "";
  // StreamEncrypt's data and StreamDecrypt's message so far, as binary strings.
  #plain = "";
  #message = "";

  constructor(session: Session) {
    this.#session = session;
  }

  get Algorithm(): Promise<Algorithm> {
    return Promise.resolve(this.#algorithm);
  }

  get Recipients(): Promise<Recipients> {
    return Promise.resolve(this.#recipients);
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
    this.#content = String(content ?? "");
    return Promise.resolve();
  }

  // Base64 only, as in CryptoPro's browser plug-in.
  async Encrypt(encoding: number = constants.CADESCOM_ENCODE_BASE64): Promise<string> {
    if (Number(encoding) !== constants.CADESCOM_ENCODE_BASE64) throw new CadesError("The parameter is incorrect.", E_INVALIDARG);
    return this.#encrypt(this.#encoding === constants.CADESCOM_BASE64_TO_BINARY ? decodeBase64(this.#content) : ucs2leBinary(this.#content));
  }

  async Decrypt(message: unknown): Promise<void> {
    const plain = await this.#decrypt(binaryBytes(decodeBase64(message)));
    this.#content = this.#encoding === constants.CADESCOM_BASE64_TO_BINARY ? btoa(bytesBinary(plain)) : new TextDecoder("utf-16le").decode(plain);
  }

  async StreamEncrypt(data: unknown, isFinal: unknown = false): Promise<string> {
    this.#plain += decodeBase64(data);
    if (!isFinal) return "";
    const plain = this.#plain;
    this.#plain = "";
    return this.#encrypt(plain);
  }

  // webtools.html passes a whole message without isFinal: a message is decrypted as soon as it is complete.
  async StreamDecrypt(data: unknown, isFinal: unknown = false): Promise<string> {
    this.#message += decodeBase64(data);
    const bytes = binaryBytes(this.#message);
    let message: Uint8Array | undefined;
    try {
      message = complete(bytes);
    } catch (error) {
      this.#message = "";
      throw error;
    }
    if (!message) {
      if (!isFinal) return "";
      this.#message = "";
      throw new CadesError("Сообщение оборвано", CRYPT_E_INVALID_MSG_TYPE);
    }
    this.#message = "";
    return btoa(bytesBinary(await this.#decrypt(message)));
  }

  async #encrypt(plain: string): Promise<string> {
    const recipients = this.#recipients.certificates();
    if (recipients.length === 0) throw new CadesError("Не задан ни один получатель", E_INVALIDARG);
    if (!plain) throw new CadesError("Нет данных для шифрования", E_INVALIDARG);
    const cipher = this.#algorithm.cipher();
    const plugin = this.#session.plugin;
    // Any token can encrypt: the one with a recipient's certificate, so its PIN is the one the user expects, or else
    // the only one connected.
    let deviceId: number | undefined;
    for (const certificate of recipients) {
      const token = tokenOf(certificate);
      deviceId ??= token && (await findDevice(plugin, token.serial));
    }
    deviceId ??= (await singleDevice(this.#session)).deviceId;
    const x509s = recipients.map((certificate) => x509Of(certificate)!);
    const request = {
      origin: this.#session.origin,
      action: "просит зашифровать данные.",
      details: [
        `${sizeText(plain.length)}, ${cipher.name}.`,
        ...x509s.map((x509) => `Получатель: ${commonName(x509.subject)}`),
        "Рутокен Плагин шифрует только после ввода PIN-кода токена.",
      ],
      confirm: "Зашифровать",
    };
    const device = deviceId;
    return withLogin(this.#session, device, request, async () => {
      const algorithm = await plugin[cipher.constant];
      try {
        return await plugin.cmsEncrypt(device, "", x509s.map(pem), btoa(plain), { base64: true, cipherAlgorithm: algorithm });
      } catch (error) {
        throw pluginFailure("зашифровал", error, E_FAIL);
      }
    });
  }

  // The token that holds the certificate of one of the message's recipients decrypts it.
  async #decrypt(message: Uint8Array): Promise<Uint8Array> {
    let recipients: CertificateId[];
    try {
      recipients = envelopedRecipients(message);
    } catch {
      throw new CadesError("Invalid cryptographic message type.", CRYPT_E_INVALID_MSG_TYPE);
    }
    const plugin: RutokenPlugin = this.#session.plugin;
    const token = (await userCertificates(plugin)).find((candidate) => recipients.some((id) => identifies(id, candidate.x509)));
    if (!token) throw new CadesError("Cannot find the certificate and private key to use for decryption.", CRYPT_E_NO_DECRYPT_CERT);
    const { deviceId } = token;
    const request = {
      origin: this.#session.origin,
      action: "просит расшифровать данные.",
      details: [`Зашифрованное сообщение, ${sizeText(message.length)}.`, ...certificateLines(token.x509)],
      confirm: "Расшифровать",
    };
    return withLogin(this.#session, deviceId, request, async () => {
      const keyId = await plugin.getKeyByCertificate(deviceId, token.certId);
      try {
        return binaryBytes(decodeBase64(await plugin.cmsDecrypt(deviceId, keyId, btoa(bytesBinary(message)), { base64: true })));
      } catch (error) {
        throw pluginFailure("расшифровал", error, NTE_BAD_DATA);
      }
    });
  }
}
