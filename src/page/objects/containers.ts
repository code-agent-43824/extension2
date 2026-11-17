// CryptoPro's key containers for the keys on the connected Rutokens (docs/PLAN.md, actions 25 (e) and 51): each user
// certificate on a token is the container of its key, \\.\<reader>\ID_<thumbprint>, in CryptoPro's form (the owner's
// screenshot, 2026-10-08) with the certificate's thumbprint in place of the key's CKA_ID, which the Rutoken Plugin gives
// only after a login. So listing needs no PIN (the owner, 2026-11-17, CLAUDE.md), and what the key is comes from its
// certificate; a key without a certificate is not listed. Deleting finds the key by the certificate after the PIN.
import { children, expectTag, read } from "../asn1.ts";
import { constants } from "../constants.ts";
import { CadesError } from "../errors.ts";
import { certificateLines } from "../signing.ts";
import { findDevice, userCertificates, type TokenCertificate } from "../token.ts";
import { SCARD_E_NO_SMARTCARD, withLogin } from "../token-login.ts";
import { Certificate, certificateKey, PublicKey } from "./certificate.ts";
import type { Session } from "./session.ts";

const E_INVALIDARG = 0x80070057;
const CRYPT_E_NOT_FOUND = 0x80092004;
// What CryptoAPI answers for a container that does not exist.
export const NTE_BAD_KEYSET = 0x80090016;

// CryptoPro's ALG_ID of each key kind (GostConstants.cs of CryptoPro's .NET; RSA from the table in Code.js), by the
// certificate's public key algorithm.
const algIds: Record<string, { signature: number; exchange: number }> = {
  "1.2.643.7.1.1.1.1": { signature: 0x2e49, exchange: 0xaa46 },
  "1.2.643.7.1.1.1.2": { signature: 0x2e3d, exchange: 0xaa42 },
  "1.2.643.2.2.19": { signature: 0x2e23, exchange: 0xaa24 },
  "1.2.840.113549.1.1.1": { signature: 0x2400, exchange: 0xa400 },
};

// CAPICOM's key usage flags that let a key encrypt: keyEncipherment and keyAgreement.
const EXCHANGE_USAGE = 0x20 | 0x08;

// A key is an exchange key when its certificate lets it encrypt, or does not limit its usage.
const isExchange = (certificate: TokenCertificate) => certificate.x509.keyUsage === null || (certificate.x509.keyUsage & EXCHANGE_USAGE) !== 0;

// The key's value as the token keeps it: a GOST key's point (x||y), an RSA key's modulus.
function keyValue(certificate: TokenCertificate): Uint8Array {
  try {
    const key = read(certificate.x509.publicKey);
    if (key.tag === 0x04) return key.value;
    const modulus = children(expectTag(key, 0x30, "RSAPublicKey"))[0]!.value;
    return modulus[0] === 0 ? modulus.subarray(1) : modulus;
  } catch {
    return certificate.x509.publicKey;
  }
}

interface TokenInfo {
  serial: string;
  reader: string;
  media: string;
}

// CPContainerKey: the key itself, never exportable from a Rutoken.
export class ContainerKey {
  readonly #session: Session;
  readonly #certificate: TokenCertificate;

  constructor(session: Session, certificate: TokenCertificate) {
    this.#session = session;
    this.#certificate = certificate;
  }

  get Type(): Promise<number> {
    return Promise.resolve(isExchange(this.#certificate) ? constants.AT_KEYEXCHANGE : constants.AT_SIGNATURE);
  }

  get IsExportable(): Promise<boolean> {
    return Promise.resolve(false);
  }

  get HasCertificate(): Promise<boolean> {
    return Promise.resolve(true);
  }

  get Certificate(): Promise<Certificate> {
    return Promise.resolve(new Certificate(this.#session, this.#certificate));
  }

  // The private key's usage period in its certificate; a certificate without one gives no date (webtools.html then
  // shows "-").
  get ExpirationTime(): Promise<string> {
    const date = this.#certificate.x509.privateKeyNotAfter;
    if (!date) return Promise.reject(new CadesError("Срок действия ключа не задан", CRYPT_E_NOT_FOUND));
    return Promise.resolve(date.toISOString());
  }

  // The first 8 bytes of the public key, as hex without spaces.
  get KP_FP(): Promise<string> {
    return Promise.resolve(Array.from(keyValue(this.#certificate).subarray(0, 8), (byte) => byte.toString(16).padStart(2, "0")).join("").toUpperCase());
  }

  get KP_ALGID(): Promise<number> {
    const ids = algIds[this.#certificate.x509.publicKeyAlgorithm];
    return Promise.resolve(ids ? (isExchange(this.#certificate) ? ids.exchange : ids.signature) : 0);
  }

  // The certificate's public key.
  get PublicKey(): Promise<PublicKey> {
    return Promise.resolve(new PublicKey(certificateKey(this.#certificate.x509)));
  }
}

// CPContainerKeys, indexed from 0 as webtools.html reads it: one key per container.
class ContainerKeys {
  readonly #items: ContainerKey[];

  constructor(items: ContainerKey[]) {
    this.#items = items;
  }

  get Count(): Promise<number> {
    return Promise.resolve(this.#items.length);
  }

  async ItemByIndex(index: number): Promise<ContainerKey> {
    const item = this.#items[Number(index)];
    if (!item) throw new CadesError("The parameter is incorrect.", E_INVALIDARG);
    return item;
  }
}

// CPContainer. UniqueName is the FQCN: how CryptoPro forms it for a Rutoken key was not compared, nor Media, which is
// the token's model and serial number, as the reader's.
export class Container {
  readonly #session: Session;
  readonly #token: TokenInfo;
  readonly #certificate: TokenCertificate;
  #silent = false;

  constructor(session: Session, token: TokenInfo, certificate: TokenCertificate) {
    this.#session = session;
    this.#token = token;
    this.#certificate = certificate;
  }

  get Name(): Promise<string> {
    return Promise.resolve(this.name());
  }

  get FQCN(): Promise<string> {
    return Promise.resolve(this.fqcn());
  }

  get UniqueName(): Promise<string> {
    return Promise.resolve(this.fqcn());
  }

  get Reader(): Promise<string> {
    return Promise.resolve(this.#token.reader);
  }

  get Media(): Promise<string> {
    return Promise.resolve(this.#token.media);
  }

  // Kept only: the PIN window is the one window this works through, and it always shows.
  get Silent(): Promise<boolean> {
    return Promise.resolve(this.#silent);
  }

  propset_Silent(value: unknown): Promise<void> {
    this.#silent = Boolean(value);
    return Promise.resolve();
  }

  get Keys(): Promise<ContainerKeys> {
    return Promise.resolve(new ContainerKeys([new ContainerKey(this.#session, this.#certificate)]));
  }

  // Deletes the certificate's key pair, found by the certificate after the PIN, and the certificate.
  async Delete(): Promise<void> {
    const plugin = this.#session.plugin;
    const deviceId = await findDevice(plugin, this.#token.serial);
    if (deviceId === undefined) throw new CadesError("Рутокен с этим контейнером не подключён.", SCARD_E_NO_SMARTCARD);
    const certificate = this.#certificate;
    const request = {
      origin: this.#session.origin,
      action: "просит удалить ключ с Рутокена.",
      details: [`Контейнер ${this.fqcn()}.`, ...certificateLines(certificate.x509), "Ключ и сертификат удаляются безвозвратно."],
      confirm: "Удалить",
    };
    await withLogin(this.#session, deviceId, request, async () => {
      let keyId: string | undefined;
      try {
        keyId = await plugin.getKeyByCertificate(deviceId, certificate.certId);
      } catch {
        // A certificate whose key is gone: only the certificate is left to delete.
      }
      if (keyId !== undefined) await plugin.deleteKeyPair(deviceId, keyId);
      await plugin.deleteCertificate(deviceId, certificate.certId);
    });
  }

  name(): string {
    return `ID_${this.#certificate.x509.thumbprint.toLowerCase()}`;
  }

  fqcn(): string {
    return `\\\\.\\${this.#token.reader}\\${this.name()}`;
  }
}

// CPContainers, indexed from 0.
export class Containers {
  readonly #items: Container[];

  constructor(items: Container[]) {
    this.#items = items;
  }

  get Count(): Promise<number> {
    return Promise.resolve(this.#items.length);
  }

  async ItemByIndex(index: number): Promise<Container> {
    const item = this.#items[Number(index)];
    if (!item) throw new CadesError("The parameter is incorrect.", E_INVALIDARG);
    return item;
  }
}

// Every user certificate on the connected tokens, read anew each time, without a login.
export async function containers(session: Session): Promise<Container[]> {
  const plugin = session.plugin;
  const [serialInfo, readerInfo, modelInfo] = await Promise.all([plugin.TOKEN_INFO_SERIAL, plugin.TOKEN_INFO_READER, plugin.TOKEN_INFO_MODEL]);
  const all = await userCertificates(plugin);
  const result: Container[] = [];
  for (const deviceId of await plugin.enumerateDevices()) {
    const serial = String(await plugin.getDeviceInfo(deviceId, serialInfo));
    const token = { serial, reader: String(await plugin.getDeviceInfo(deviceId, readerInfo)), media: `${String(await plugin.getDeviceInfo(deviceId, modelInfo))} ${serial}` };
    for (const certificate of all.filter((candidate) => candidate.serial === serial)) result.push(new Container(session, token, certificate));
  }
  return result;
}
