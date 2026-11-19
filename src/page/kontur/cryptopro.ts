// CryptoPro CSP as Kontur.Plugin sees it through CryptoAPI (docs/JOURNAL.md, 2026-11-19; the owner, 2026-11-19:
// «керриеры и инфу о контейнерах передавай такую же какую бы криптопро плагин передавал», «лицензии тоже фейковые»):
// the providers, readers and containers the extension's CryptoPro emulation shows a page — the two provider types
// named by About.CSPName(), each token as a reader, each certificate's key as the container \\.\<reader>\ID_<thumbprint>
// — and a made-up licence that is in force. The host under Linux without CryptoPro has none of it.
import { CSP_VERSION } from "../compat.ts";
import { constants } from "../constants.ts";
import { keySpecOf } from "../objects/containers.ts";
import { emulatedProviders } from "../objects/enrollment.ts";
import type { Session } from "../objects/session.ts";
import type { TokenCertificate } from "../token.ts";
import { KonturError, invalidStructure } from "./errors.ts";
import { checkSink } from "./streams.ts";

const isObject = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);

const GOST_2012_512 = "1.2.643.7.1.1.1.2";

export interface CryptoApiProvider {
  id: number;
  name: string;
  type: "cryptoApi";
  version: string;
}

export async function cryptoApiProviders(session: Session): Promise<CryptoApiProvider[]> {
  return (await emulatedProviders(session)).map((provider) => ({ id: provider.type, name: provider.name, type: "cryptoApi", version: CSP_VERSION }));
}

// The providers a request names: by its id, or else by its name; all of them when it names none, none for another.
export async function namedProviders(session: Session, value: Record<string, unknown>): Promise<CryptoApiProvider[]> {
  const all = await cryptoApiProviders(session);
  if (typeof value.id === "number") return all.filter((provider) => provider.id === value.id);
  if (typeof value.name === "string") return all.filter((provider) => provider.name === value.name);
  return all;
}

// The container of a certificate's key, as the CryptoPro emulation names it.
export const containerFqcn = (reader: string, certificate: TokenCertificate) => `\\\\.\\${reader}\\ID_${certificate.x509.thumbprint.toLowerCase()}`;

// Whether the provider holds this key: type 81 the 512-bit ones, type 80 the others.
export const holds = (provider: CryptoApiProvider, certificate: TokenCertificate) => (certificate.x509.publicKeyAlgorithm === GOST_2012_512) === (provider.id === 81);

export interface Reader {
  name: string;
  nickname: string;
  media: string;
  freeMemory?: number;
}

// The readers: a token each, named by its reader, its label as the nickname, its model and serial as the media.
export async function readers(session: Session): Promise<Reader[]> {
  const plugin = session.plugin;
  const [reader, label, model, serial, free] = await Promise.all([plugin.TOKEN_INFO_READER, plugin.TOKEN_INFO_LABEL, plugin.TOKEN_INFO_MODEL, plugin.TOKEN_INFO_SERIAL, (plugin as unknown as Record<string, PromiseLike<number>>).TOKEN_INFO_FREE_MEMORY!]);
  const result: Reader[] = [];
  for (const deviceId of await plugin.enumerateDevices()) {
    const info = async (option: number) => String(await plugin.getDeviceInfo(deviceId, option));
    const memory = Number(await info(free).catch(() => ""));
    result.push({ name: await info(reader), nickname: await info(label), media: `${await info(model)} ${await info(serial)}`, ...(Number.isFinite(memory) ? { freeMemory: memory } : {}) });
  }
  return result;
}

// crypto.provider.getCarriers for a CryptoAPI provider: {media, name, nickname} of each reader.
export async function providerCarriers(session: Session): Promise<unknown[]> {
  return (await readers(session)).map(({ media, name, nickname }) => ({ media, name, nickname }));
}

// cryptopro.carriers {provider, extended?}: with the carrier flags CryptoPro gives a token (removable, unique), and
// its free memory when extended.
export async function cryptoProCarriers(session: Session, request: Record<string, unknown>): Promise<unknown[]> {
  if (!isObject(request.provider)) throw invalidStructure();
  if (!(await namedProviders(session, request.provider)).length) return [];
  const flags = constants.CARRIER_FLAG_REMOVABLE | constants.CARRIER_FLAG_UNIQUE;
  return (await readers(session)).map(({ media, name, nickname, freeMemory }) => ({ flags, media, name, nickname, ...(request.extended === true && freeMemory !== undefined ? { freeMemory } : {}) }));
}

// A container's KeySpec, as CPContainerKey gives it.
export const containerKeySpec = keySpecOf;

// crypto.container.cryptopro.getExtension {containerInfo, oid, sink}: the emulation's containers have no CryptoPro
// extensions (a licence in the container): the host's 208, which Kontur's client takes for "not there".
export function containerExtension(request: Record<string, unknown>): never {
  if (!isObject(request.containerInfo) || typeof request.oid !== "string") throw invalidStructure();
  if (request.sink !== undefined) checkSink(request.sink);
  throw new KonturError({ type: "plugin", code: 208, message: "PLUGIN[0x000000D0] key container extension not found" });
}

// The made-up licence: a client's, not a demo, in force until the end of 2099. Its date is what
// crypto.provider.cryptopro.getLicense answers, which Kontur's client reads with new Date().
export const LICENSE_EXPIRES = "2099-12-31T00:00:00Z";

export function licenseInfo(): Record<string, unknown> {
  return { client: true, demo: false, expireDate: LICENSE_EXPIRES, server: false, type: "client" };
}
