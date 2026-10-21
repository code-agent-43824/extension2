// CAdESCOM.RawSignature: a bare GOST R 34.10 signature of a hash, without CMS. CryptoPro's documentation
// (IRawSignature::SignHash, VerifyHash): the signature of RFC 4491, 2.2.2 (s||r, big-endian, as in CMS) with its bytes
// in reverse order, as hex digits, two per byte, separated by spaces. Not compared with the real plug-in.
import { CadesError } from "../errors.ts";
import { isGostKey, verifyHash } from "../gost.ts";
import { certificateLines } from "../signing.ts";
import { findDevice } from "../token.ts";
import { SCARD_E_NO_SMARTCARD, withLogin } from "../token-login.ts";
import { tokenOf, x509Of } from "./certificate.ts";
import { HashedData } from "./hashed-data.ts";
import type { Session } from "./session.ts";
import { checkHashForKey } from "./signed-data.ts";

const E_INVALIDARG = 0x80070057;
// What CryptoPro answers a signature that does not verify and a key it cannot check (CadesSignedData.VerifyHash).
const NTE_BAD_SIGNATURE = 0x80090006;
const NTE_BAD_ALGID = 0x80090008;

function bytesOf(hex: string): Uint8Array {
  return Uint8Array.from(hex.match(/../g) ?? [], (pair) => parseInt(pair, 16));
}

export class RawSignature {
  readonly #session: Session;

  constructor(session: Session) {
    this.#session = session;
  }

  // The certificate is required: choosing one, as CryptoPro does on Windows without it, is not ours to do.
  async SignHash(hashed: unknown, certificate: unknown): Promise<string> {
    if (!(hashed instanceof HashedData)) throw new CadesError("Ожидается объект CAdESCOM.HashedData", E_INVALIDARG);
    const token = tokenOf(certificate);
    if (!token) throw new CadesError("Нужен сертификат из хранилища, с ключом на Рутокене", E_INVALIDARG);
    const { algorithm, value } = await hashed.hash();
    checkHashForKey(algorithm, token);
    const plugin = this.#session.plugin;
    const deviceId = await findDevice(plugin, token.serial);
    if (deviceId === undefined) throw new CadesError("Рутокен с этим сертификатом не подключён.", SCARD_E_NO_SMARTCARD);
    const request = {
      origin: this.#session.origin,
      action: "просит подписать хеш данных.",
      details: ["Хеш данных, подпись без конверта CMS.", ...certificateLines(token.x509)],
      confirm: "Подписать",
    };
    const raw = await withLogin(this.#session, deviceId, request, async () => {
      const keyId = await plugin.getKeyByCertificate(deviceId, token.certId);
      return plugin.rawSign(deviceId, keyId, value.toLowerCase().replace(/(..)(?!$)/g, "$1:"), {});
    });
    return Array.from(bytesOf(raw.replace(/:/g, "")).reverse(), (byte) => byte.toString(16).toUpperCase().padStart(2, "0")).join(" ");
  }

  // Checked in the page, as CadesSignedData's verification: no token is involved.
  async VerifyHash(hashed: unknown, certificate: unknown, signature: unknown): Promise<void> {
    if (!(hashed instanceof HashedData)) throw new CadesError("Ожидается объект CAdESCOM.HashedData", E_INVALIDARG);
    const x509 = x509Of(certificate);
    if (!x509) throw new CadesError("Ожидается объект CAdESCOM.Certificate", E_INVALIDARG);
    const digits = typeof signature === "string" ? signature.replace(/\s+/g, "") : "";
    if (!/^(?:[0-9a-fA-F]{2})+$/.test(digits)) throw new CadesError("The parameter is incorrect.", E_INVALIDARG);
    if (!isGostKey(x509)) throw new CadesError("Проверяются только подписи ГОСТ Р 34.10", NTE_BAD_ALGID);
    const hash = bytesOf((await hashed.hash()).value);
    if (!verifyHash(x509, hash, bytesOf(digits).reverse())) throw new CadesError("Invalid Signature.", NTE_BAD_SIGNATURE);
  }
}

