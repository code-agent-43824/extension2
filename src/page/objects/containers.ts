// CryptoPro's key containers for the keys on the connected Rutokens (docs/PLAN.md, action 25 (e)): every private
// key the Rutoken Plugin sees is the container \\.\<reader>\ID_<CKA_ID>, as CryptoPro names it (the owner's
// screenshot, 2026-10-08). Key ids come only after a login, so listing asks for each token's PIN (the owner's
// decision, CLAUDE.md); what one login found is kept for the page until the extension itself changes the token's keys.
import { constants } from "../constants.ts";
import { CadesError } from "../errors.ts";
import { certificateLines } from "../signing.ts";
import { findDevice, userCertificates, type TokenCertificate } from "../token.ts";
import { SCARD_E_NO_SMARTCARD, withLogin } from "../token-login.ts";
import { Certificate, PublicKey } from "./certificate.ts";
import type { Session } from "./session.ts";

const E_INVALIDARG = 0x80070057;
const CRYPT_E_NOT_FOUND = 0x80092004;
// What CryptoAPI answers for a container that does not exist.
export const NTE_BAD_KEYSET = 0x80090016;

// CryptoPro's ALG_ID of each key kind (GostConstants.cs of CryptoPro's .NET; RSA from the table in Code.js).
const algIds = {
  gost2012_256: { signature: 0x2e49, exchange: 0xaa46, oid: "1.2.643.7.1.1.1.1" },
  gost2012_512: { signature: 0x2e3d, exchange: 0xaa42, oid: "1.2.643.7.1.1.1.2" },
  gost2001: { signature: 0x2e23, exchange: 0xaa24, oid: "1.2.643.2.2.19" },
  rsa: { signature: 0x2400, exchange: 0xa400, oid: "1.2.840.113549.1.1.1" },
} as const;

type KeyKind = keyof typeof algIds;

// What one login told about a key.
interface KeyRecord {
  keyId: string;
  kind: KeyKind | undefined;
  exchange: boolean;
  publicKey: Uint8Array;
  notAfter: Date | undefined;
  certificate: TokenCertificate | undefined;
}

interface TokenKeys {
  serial: string;
  reader: string;
  media: string;
  keys: KeyRecord[];
}

// By token serial number: what a login found, or the login still under way, which a second caller waits for rather
// than opening a second PIN window.
const remembered = new WeakMap<Session, Map<string, Promise<TokenKeys>>>();

// After the extension creates or deletes a key, or writes a certificate, the next listing asks again.
export function forgetContainers(session: Session): void {
  remembered.delete(session);
}

function fromHex(hex: string): Uint8Array {
  return Uint8Array.from(hex.replace(/[^0-9a-f]/gi, "").match(/../g) ?? [], (byte) => parseInt(byte, 16));
}

const sameKeyId = (a: string, b: string) => a.replace(/:/g, "").toLowerCase() === b.replace(/:/g, "").toLowerCase();

async function readKeys(session: Session, deviceId: number, certificates: TokenCertificate[]): Promise<KeyRecord[]> {
  const plugin = session.plugin;
  const [algorithmInfo, specInfo, periodInfo] = await Promise.all([plugin.KEY_INFO_ALGORITHM, plugin.KEY_INFO_SPEC, plugin.KEY_INFO_USAGE_PERIOD]);
  const kinds = new Map<number, KeyKind>([
    [await plugin.PUBLIC_KEY_ALGORITHM_GOST3410_2012_256, "gost2012_256"],
    [await plugin.PUBLIC_KEY_ALGORITHM_GOST3410_2012_512, "gost2012_512"],
    [await plugin.PUBLIC_KEY_ALGORITHM_GOST3410_2001, "gost2001"],
    [await plugin.PUBLIC_KEY_ALGORITHM_RSA, "rsa"],
  ]);
  const exchangeSpec = await plugin.KEY_SPEC_SIGN_AND_EXCHANGE;
  // A certificate without a key on the token belongs to no container.
  const owners: { keyId: string; certificate: TokenCertificate }[] = [];
  for (const certificate of certificates) {
    try {
      owners.push({ keyId: await plugin.getKeyByCertificate(deviceId, certificate.certId), certificate });
    } catch {
      // No key for it.
    }
  }
  const keys: KeyRecord[] = [];
  for (const keyId of await plugin.enumerateKeys(deviceId, "")) {
    const period = (await plugin.getKeyInfo(deviceId, keyId, periodInfo)) as { notAfter?: number } | null;
    keys.push({
      keyId,
      kind: kinds.get(Number(await plugin.getKeyInfo(deviceId, keyId, algorithmInfo))),
      exchange: Number(await plugin.getKeyInfo(deviceId, keyId, specInfo)) === exchangeSpec,
      publicKey: fromHex(await plugin.getPublicKeyValue(deviceId, keyId, {})),
      notAfter: typeof period?.notAfter === "number" ? new Date(period.notAfter * 1000) : undefined,
      certificate: owners.find((owner) => sameKeyId(owner.keyId, keyId))?.certificate,
    });
  }
  return keys;
}

// The containers of every connected token, a PIN window for each token not read yet on this page.
async function tokenKeys(session: Session): Promise<{ deviceId: number; token: TokenKeys }[]> {
  const plugin = session.plugin;
  const [serialInfo, readerInfo, modelInfo] = await Promise.all([plugin.TOKEN_INFO_SERIAL, plugin.TOKEN_INFO_READER, plugin.TOKEN_INFO_MODEL]);
  const known = remembered.get(session) ?? new Map<string, Promise<TokenKeys>>();
  remembered.set(session, known);
  const result: { deviceId: number; token: TokenKeys }[] = [];
  for (const deviceId of await plugin.enumerateDevices()) {
    const serial = String(await plugin.getDeviceInfo(deviceId, serialInfo));
    let pending = known.get(serial);
    if (!pending) {
      pending = (async () => {
        const reader = String(await plugin.getDeviceInfo(deviceId, readerInfo));
        const model = String(await plugin.getDeviceInfo(deviceId, modelInfo));
        const own = (await userCertificates(plugin)).filter((certificate) => certificate.serial === serial);
        const request = {
          origin: session.origin,
          action: "просит показать ключи на Рутокене.",
          details: [`Рутокен ${model} ${serial}, считыватель «${reader}».`, "Сайт увидит ключи как контейнеры КриптоПро: их идентификаторы и открытые ключи."],
          confirm: "Показать",
        };
        const keys = await withLogin(session, deviceId, request, () => readKeys(session, deviceId, own));
        return { serial, reader, media: `${model} ${serial}`, keys };
      })();
      known.set(serial, pending);
      // A refused PIN or a failure is not kept: the next listing asks again.
      pending.catch(() => {
        if (known.get(serial) === pending) known.delete(serial);
      });
    }
    result.push({ deviceId, token: await pending });
  }
  return result;
}

// CPContainerKey: the key itself, never exportable from a Rutoken.
export class ContainerKey {
  readonly #session: Session;
  readonly #key: KeyRecord;

  constructor(session: Session, key: KeyRecord) {
    this.#session = session;
    this.#key = key;
  }

  get Type(): Promise<number> {
    return Promise.resolve(this.#key.exchange ? constants.AT_KEYEXCHANGE : constants.AT_SIGNATURE);
  }

  get IsExportable(): Promise<boolean> {
    return Promise.resolve(false);
  }

  get HasCertificate(): Promise<boolean> {
    return Promise.resolve(this.#key.certificate !== undefined);
  }

  get Certificate(): Promise<Certificate> {
    const certificate = this.#key.certificate;
    if (!certificate) return Promise.reject(new CadesError("В контейнере нет сертификата", CRYPT_E_NOT_FOUND));
    return Promise.resolve(new Certificate(this.#session, certificate));
  }

  // The private key's usage period on the token; a key without one has no date (webtools.html then shows "-").
  get ExpirationTime(): Promise<string> {
    const date = this.#key.notAfter;
    if (!date) return Promise.reject(new CadesError("Срок действия ключа не задан", CRYPT_E_NOT_FOUND));
    return Promise.resolve(date.toISOString());
  }

  // The first 8 bytes of the public key, as hex without spaces.
  get KP_FP(): Promise<string> {
    return Promise.resolve(Array.from(this.#key.publicKey.subarray(0, 8), (byte) => byte.toString(16).padStart(2, "0")).join("").toUpperCase());
  }

  get KP_ALGID(): Promise<number> {
    const ids = this.#key.kind && algIds[this.#key.kind];
    return Promise.resolve(ids ? (this.#key.exchange ? ids.exchange : ids.signature) : 0);
  }

  get PublicKey(): Promise<PublicKey> {
    const ids = this.#key.kind && algIds[this.#key.kind];
    return Promise.resolve(new PublicKey(ids ? ids.oid : "", this.#key.publicKey.length * 8));
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
  readonly #token: TokenKeys;
  readonly #key: KeyRecord;
  #silent = false;

  constructor(session: Session, token: TokenKeys, key: KeyRecord) {
    this.#session = session;
    this.#token = token;
    this.#key = key;
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
    return Promise.resolve(new ContainerKeys([new ContainerKey(this.#session, this.#key)]));
  }

  // Deletes the key pair and the certificate that goes with it, after the PIN.
  async Delete(): Promise<void> {
    const plugin = this.#session.plugin;
    const deviceId = await findDevice(plugin, this.#token.serial);
    if (deviceId === undefined) throw new CadesError("Рутокен с этим контейнером не подключён.", SCARD_E_NO_SMARTCARD);
    const certificate = this.#key.certificate;
    const request = {
      origin: this.#session.origin,
      action: "просит удалить ключ с Рутокена.",
      details: [`Контейнер ${this.fqcn()}.`, ...(certificate ? certificateLines(certificate.x509) : []), `Ключ${certificate ? " и сертификат удаляются" : " удаляется"} безвозвратно.`],
      confirm: "Удалить",
    };
    await withLogin(this.#session, deviceId, request, async () => {
      await plugin.deleteKeyPair(deviceId, this.#key.keyId);
      if (certificate) await plugin.deleteCertificate(deviceId, certificate.certId);
    });
    forgetContainers(this.#session);
  }

  name(): string {
    return `ID_${this.#key.keyId.replace(/:/g, "").toLowerCase()}`;
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

export async function containers(session: Session): Promise<Container[]> {
  return (await tokenKeys(session)).flatMap(({ token }) => token.keys.map((key) => new Container(session, token, key)));
}
