import { constants } from "../constants.ts";
import { CadesError } from "../errors.ts";
import { digest, type DigestName } from "../gost.ts";

const E_INVALIDARG = 0x80070057;

// CAdESCOM hash algorithms, with their hash sizes in bytes.
const algorithms = new Map<number, { name: DigestName; size: number }>([
  [constants.CADESCOM_HASH_ALGORITHM_CP_GOST_3411, { name: "gost94", size: 32 }],
  [constants.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256, { name: "streebog256", size: 32 }],
  [constants.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_512, { name: "streebog512", size: 64 }],
  [constants.CADESCOM_HASH_ALGORITHM_MD5, { name: "md5", size: 16 }],
  [constants.CADESCOM_HASH_ALGORITHM_SHA1, { name: "sha1", size: 20 }],
  [constants.CADESCOM_HASH_ALGORITHM_SHA_256, { name: "sha256", size: 32 }],
  [constants.CADESCOM_HASH_ALGORITHM_SHA_384, { name: "sha384", size: 48 }],
  [constants.CADESCOM_HASH_ALGORITHM_SHA_512, { name: "sha512", size: 64 }],
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

export function binaryBytes(binary: string): Uint8Array {
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

// Bytes as a binary string, in slices: spreading a whole document into one call would overflow the stack.
export function bytesBinary(bytes: Uint8Array): string {
  let result = "";
  for (let i = 0; i < bytes.length; i += 0x8000) result += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return result;
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("").toUpperCase();
}

// CAdESCOM.HashedData, as CryptoPro's plug-in 2.0.15700 behaves (docs/JOURNAL.md, 2026-09-24): the
// default algorithm is GOST R 34.11-94, Hash() may be called several times and hashes the pieces as one,
// reading Value ends the hash (the next Hash() starts a new one), Value is upper-case hex. The data is
// kept until the hash is needed and hashed in the page (src/page/gost.ts): no token is involved.
export class HashedData {
  #algorithm: number = constants.CADESCOM_HASH_ALGORITHM_CP_GOST_3411;
  #encoding: number = constants.CADESCOM_STRING_TO_UCS2LE;
  // Bytes passed to Hash() since the hash was last ended, as a binary string; null before any Hash().
  #data: string | null = null;
  #value: string | undefined;

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

  // For CadesSignedData's SignHash and VerifyHash: the algorithm and the ended hash.
  async hash(): Promise<{ algorithm: number; value: string }> {
    const { name } = this.#known();
    if (this.#value === undefined) {
      if (this.#data === null) throw new CadesError("Хеш ещё не вычислен: нет данных.", E_INVALIDARG);
      this.#value = toHex(digest(name, binaryBytes(this.#data)));
      this.#data = null;
    }
    return { algorithm: this.#algorithm, value: this.#value };
  }

  #known(): { name: DigestName; size: number } {
    const known = algorithms.get(this.#algorithm);
    if (!known) throw new CadesError(`Алгоритм хеширования ${this.#algorithm} не поддерживается.`, E_INVALIDARG);
    return known;
  }
}
