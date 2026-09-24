import { constants } from "../constants.ts";
import { CadesError } from "../errors.ts";
import type { RutokenPlugin } from "../rutoken.ts";
import { SCARD_E_NO_SMARTCARD } from "../token-login.ts";
import type { Session } from "./session.ts";

const E_INVALIDARG = 0x80070057;
const E_FAIL = 0x80004005;

export type HashType =
  | "HASH_TYPE_GOST3411_94"
  | "HASH_TYPE_GOST3411_12_256"
  | "HASH_TYPE_GOST3411_12_512"
  | "HASH_TYPE_MD5"
  | "HASH_TYPE_SHA1"
  | "HASH_TYPE_SHA256"
  | "HASH_TYPE_SHA384"
  | "HASH_TYPE_SHA512";

// CAdESCOM hash algorithms the Rutoken Plugin's digest() also has, with their hash sizes in bytes.
const algorithms = new Map<number, { type: HashType; size: number }>([
  [constants.CADESCOM_HASH_ALGORITHM_CP_GOST_3411, { type: "HASH_TYPE_GOST3411_94", size: 32 }],
  [constants.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256, { type: "HASH_TYPE_GOST3411_12_256", size: 32 }],
  [constants.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_512, { type: "HASH_TYPE_GOST3411_12_512", size: 64 }],
  [constants.CADESCOM_HASH_ALGORITHM_MD5, { type: "HASH_TYPE_MD5", size: 16 }],
  [constants.CADESCOM_HASH_ALGORITHM_SHA1, { type: "HASH_TYPE_SHA1", size: 20 }],
  [constants.CADESCOM_HASH_ALGORITHM_SHA_256, { type: "HASH_TYPE_SHA256", size: 32 }],
  [constants.CADESCOM_HASH_ALGORITHM_SHA_384, { type: "HASH_TYPE_SHA384", size: 48 }],
  [constants.CADESCOM_HASH_ALGORITHM_SHA_512, { type: "HASH_TYPE_SHA512", size: 64 }],
]);

// UTF-16LE as a binary string, what CryptoPro hashes and signs for a string under CADESCOM_STRING_TO_UCS2LE.
export function ucs2leBinary(text: string): string {
  let binary = "";
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    binary += String.fromCharCode(unit & 0xff, unit >> 8);
  }
  return binary;
}

// The hash of `binary` (a binary string) as upper-case hex, computed by the Rutoken Plugin on the token
// `deviceId`, or on the first connected one: the hash involves no key.
export async function tokenDigest(plugin: RutokenPlugin, deviceId: number | undefined, type: HashType, binary: string): Promise<string> {
  if (!binary) throw new CadesError("Рутокен Плагин не хеширует пустые данные.", E_INVALIDARG);
  deviceId ??= (await plugin.enumerateDevices())[0];
  if (deviceId === undefined) throw new CadesError("Рутокен не подключён: хеш считает Рутокен Плагин на токене.", SCARD_E_NO_SMARTCARD);
  let value: string;
  try {
    value = await plugin.digest(deviceId, await plugin[type], btoa(binary), { base64: true });
  } catch (error) {
    throw new CadesError(`Рутокен Плагин не посчитал хеш: ошибка ${(error as Error | null)?.message ?? error}.`, E_FAIL);
  }
  return value.replace(/:/g, "").toUpperCase();
}

// CAdESCOM.HashedData, as CryptoPro's plug-in 2.0.15700 behaves (docs/JOURNAL.md, 2026-09-24): the
// default algorithm is GOST R 34.11-94, Hash() may be called several times and hashes the pieces as one,
// reading Value ends the hash (the next Hash() starts a new one), Value is upper-case hex. The data is
// kept until the hash is needed and then hashed in one digest() call of the Rutoken Plugin.
export class HashedData {
  readonly #session: Session;
  #algorithm: number = constants.CADESCOM_HASH_ALGORITHM_CP_GOST_3411;
  #encoding: number = constants.CADESCOM_STRING_TO_UCS2LE;
  // Bytes passed to Hash() since the hash was last ended, as a binary string; null before any Hash().
  #data: string | null = null;
  #value: string | undefined;

  constructor(session: Session) {
    this.#session = session;
  }

  get Algorithm(): Promise<number> {
    return Promise.resolve(this.#algorithm);
  }

  // Any number is taken, as by the real plug-in; an unknown one fails in Hash() and Value.
  propset_Algorithm(algorithm: number): Promise<void> {
    this.#algorithm = Number(algorithm);
    return Promise.resolve();
  }

  get DataEncoding(): Promise<number> {
    return Promise.resolve(this.#encoding);
  }

  async propset_DataEncoding(encoding: number): Promise<void> {
    const value = Number(encoding);
    if (value !== constants.CADESCOM_STRING_TO_UCS2LE && value !== constants.CADESCOM_BASE64_TO_BINARY) {
      throw new CadesError(`Неизвестная кодировка данных: ${encoding}`, E_INVALIDARG);
    }
    this.#encoding = value;
  }

  async Hash(data: unknown): Promise<void> {
    this.#known();
    if (typeof data !== "string") throw new CadesError("Хешируются только строки.", E_INVALIDARG);
    let binary: string;
    if (this.#encoding === constants.CADESCOM_BASE64_TO_BINARY) {
      try {
        binary = atob(data.replace(/\s+/g, ""));
      } catch {
        throw new CadesError("Данные не в Base64.", E_INVALIDARG);
      }
    } else {
      binary = ucs2leBinary(data);
    }
    if (this.#value !== undefined) {
      this.#value = undefined;
      this.#data = null;
    }
    this.#data = (this.#data ?? "") + binary;
  }

  async SetHashValue(value: unknown): Promise<void> {
    const { size } = this.#known();
    if (typeof value !== "string" || !new RegExp(`^[0-9a-fA-F]{${size * 2}}$`).test(value)) {
      throw new CadesError("Значение хеша не подходит к алгоритму.", E_INVALIDARG);
    }
    this.#value = value.toUpperCase();
    this.#data = null;
  }

  get Value(): Promise<string> {
    return this.hash().then((hash) => hash.value);
  }

  // For CadesSignedData.SignHash: the algorithm and the ended hash.
  async hash(): Promise<{ algorithm: number; value: string }> {
    const { type } = this.#known();
    if (this.#value === undefined) {
      if (this.#data === null) throw new CadesError("Хеш ещё не вычислен: нет данных.", E_INVALIDARG);
      this.#value = await tokenDigest(this.#session.plugin, undefined, type, this.#data);
      this.#data = null;
    }
    return { algorithm: this.#algorithm, value: this.#value };
  }

  #known(): { type: HashType; size: number } {
    const known = algorithms.get(this.#algorithm);
    if (!known) throw new CadesError(`Алгоритм хеширования ${this.#algorithm} не поддерживается.`, E_INVALIDARG);
    return known;
  }
}
