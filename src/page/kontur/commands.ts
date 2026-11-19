// Kontur.Plugin's host commands over the Rutoken Plugin (docs/PLAN.md, stage 9), answered as the host 4.15.1 answered
// them on the stand (docs/JOURNAL.md, 2026-11-19). The site's access is its being enabled (the owner, 2026-11-19), so
// plugin.info says it is not denied, and no window asks. Answers have their keys sorted, as the host's JSON has them.
import type { Session } from "../objects/session.ts";
import type { Settings } from "../settings.ts";
import { pkcs11Serial, userCertificates, type TokenCertificate } from "../token.ts";

import { certificateFields, wanted, type TokenPlace } from "./certificate.ts";
import { cryptoError, invalidStructure, KonturError, pluginError, unknownCommand } from "./errors.ts";
import { checkAlgorithm, decrypt, encrypt, parseEnveloped } from "./encryption.ts";
import { createCertRequest, installCert, storeCommand } from "./issuance.ts";
import { checkVerifyOptions, isQualified, verifyCertificate } from "./qualified.ts";
import { decodeText, encodeText } from "./text.ts";
import type { FileDialogs } from "./file-dialog.ts";
import { FileStore, openFile, saveFile, selectFolder } from "./files.ts";
import { httpRequest } from "./http.ts";
import { addSigner, anyCertificate, pemText, rawSign, rawVerify, signatureParts, signContents, signFlags, signHash, verifySignature } from "./signing.ts";
import { checkSink, readStream, writeStream, type Cache } from "./streams.ts";

export const PLUGIN_VERSION = "4.15.1.6119";
// What the host's PKCS#11 token driver is: Aktiv's library 2.14, which the host carries (C_GetInfo's libraryVersion;
// the fork on the stand says 2.21).
const PKCS11_LIBRARY_VERSION = { major: 2, minor: 14 };
// The model the token's PKCS#11 info has for every Rutoken ECP.
const TOKEN_MODEL = "Rutoken ECP";

export interface KonturContext {
  session: Session;
  settings: Promise<Settings>;
  platform: string;
  // The host keeps "cache" streams per connection: here per page session id, by name.
  caches: Map<string, Cache>;
  // The files the user chose in the file windows, for the whole page as the host keeps them for its process.
  files: FileStore;
  dialogs: FileDialogs;
}

export function newKonturContext(session: Session, settings: Promise<Settings>, platform: string, dialogs: FileDialogs, download: (name: string, bytes: Uint8Array) => void): KonturContext {
  return { session, settings, platform, caches: new Map(), files: new FileStore(platformName(platform), download), dialogs };
}

export type Request = Record<string, unknown> & { sessionId?: unknown; type?: unknown; hostUri?: string };

const isObject = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);

// The host's platform name: "linux" as it answered on the stand; the others by the same pattern, not seen.
function platformName(platform: string): string {
  if (/^Win/i.test(platform)) return "windows";
  if (/^Mac/i.test(platform)) return "mac";
  return "linux";
}

function cacheOf(context: KonturContext, request: Request): Cache {
  const id = String(request.sessionId);
  let cache = context.caches.get(id);
  if (!cache) context.caches.set(id, (cache = Object.assign(new Map<string, Uint8Array>(), { files: context.files })));
  return cache;
}

// The JSON the host writes: object keys in order, recursively.
export function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value instanceof Uint8Array || !isObject(value)) return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortKeys(value[key])]));
}

interface TokenEntry {
  deviceId: number;
  slot: string;
  serial: string;
}

async function tokens(context: KonturContext): Promise<TokenEntry[]> {
  const plugin = context.session.plugin;
  const [readerInfo, serialInfo] = await Promise.all([plugin.TOKEN_INFO_READER, plugin.TOKEN_INFO_SERIAL]);
  const result: TokenEntry[] = [];
  for (const deviceId of await plugin.enumerateDevices()) {
    result.push({ deviceId, slot: String(await plugin.getDeviceInfo(deviceId, readerInfo)), serial: String(await plugin.getDeviceInfo(deviceId, serialInfo)) });
  }
  return result;
}

// crypto.getTokens. The versions are the fork's, as for Gosplugin, since the Rutoken Plugin does not tell them; the
// total memory is PKCS#11's "unavailable", which the host printed for the fork's.
async function tokenList(context: KonturContext): Promise<unknown[]> {
  const plugin = context.session.plugin;
  const result: unknown[] = [];
  for (const token of await tokens(context)) {
    const info = async (name: string) => {
      try {
        return await plugin.getDeviceInfo(token.deviceId, await (plugin as unknown as Record<string, PromiseLike<number>>)[name]!);
      } catch {
        return undefined;
      }
    };
    const features = ((await info("TOKEN_INFO_FEATURES")) ?? {}) as { flashDrive?: boolean; interfaces?: number[] };
    const free = Number(await info("TOKEN_INFO_FREE_MEMORY"));
    result.push({
      firmwareVersion: { major: 34, minor: 2 },
      freeMemory: Number.isFinite(free) ? free : 18446744073709551615,
      hardwareVersion: { major: 67, minor: 4 },
      hasFlashDrive: features.flashDrive === true,
      manufacturer: "Aktiv Co.",
      model: TOKEN_MODEL,
      serialNumber: pkcs11Serial(token.serial),
      slot: token.slot,
      // The Rutoken Plugin's interface 32 is NFC; the host said true for the fork, which has it.
      supportsNfc: Array.isArray(features.interfaces) && features.interfaces.includes(32),
      totalMemory: 18446744073709551615,
      type: "PCSC",
    });
  }
  return result;
}

const providerOf = (slot: string) => ({ slot, token: TOKEN_MODEL, type: "pkcs11", versionInfo: PKCS11_LIBRARY_VERSION });

const invalidEnumeration = () => new KonturError({ message: "invalid enumeration value" } as never);

async function providers(context: KonturContext, request: Request): Promise<unknown[]> {
  const type = request.cryptoProviderType;
  if (type === "cryptoApi") return [];
  if (type !== undefined && type !== "pkcs11") throw invalidEnumeration();
  return (await tokens(context)).map((token) => providerOf(token.slot));
}

async function tokenCertificates(context: KonturContext): Promise<{ certificate: TokenCertificate; slot: string }[]> {
  const slots = new Map((await tokens(context)).map((token) => [token.serial, token.slot]));
  return (await userCertificates(context.session.plugin)).map((certificate) => ({ certificate, slot: slots.get(certificate.serial) ?? "" }));
}

async function containers(context: KonturContext, request: Request): Promise<unknown[]> {
  const provider = request.provider;
  if (!isObject(provider) || !isObject(request.properties)) throw invalidStructure();
  const slots = (await tokens(context)).map((token) => token.slot);
  if (typeof provider.slot === "string" && !slots.includes(provider.slot)) throw cryptoError(53, "unable to find a token for the specified slot");
  const certProperties = request.properties.cert;
  return (await tokenCertificates(context))
    .filter(({ slot }) => typeof provider.slot !== "string" || slot === provider.slot)
    .map(({ certificate }) => ({
      ...(isObject(certProperties) ? { cert: certificateFields(certificate.x509, wanted(certProperties)) } : {}),
      name: `_HEX__${certificate.x509.thumbprint.toLowerCase()}`,
      type: "pkcs11",
    }));
}

const sameHex = (a: unknown, b: string) => typeof a === "string" && a.replace(/[^0-9a-f]/gi, "").toLowerCase() === b.toLowerCase();

// CryptoAPI's store locations as Kontur's client names them.
function checkLocation(location: unknown): void {
  if (location !== undefined && location !== "user" && location !== "machine") throw invalidEnumeration();
}

// Windows' store names are not case-sensitive, nor is this one.
const isMyStore = (name: unknown) => typeof name === "string" && name.toLowerCase() === "my";

async function searchCertificates(context: KonturContext, request: Request): Promise<unknown[]> {
  const filter = request.filter;
  if (!isObject(filter)) throw invalidStructure();
  // CryptoAPI's stores, named in `store` or in the older storeName and storeLocation, in the locations "user" and
  // "machine": the host on Linux has none to read and answers []; here the personal store `My` holds the tokens'
  // certificates, as the owner decided (CLAUDE.md), and the others stay empty.
  const store = filter.store;
  let pkcs11Store: Record<string, unknown> | undefined;
  if (!isObject(store)) {
    if (filter.storeName === undefined) throw invalidStructure();
    checkLocation(filter.storeLocation);
    if (!isMyStore(filter.storeName)) return [];
  } else if (store.storeType === "cryptoApi") {
    checkLocation(store.location ?? store.storeLocation);
    if (!isMyStore(store.name ?? store.storeName)) return [];
  } else if (store.storeType === "pkcs11") pkcs11Store = store;
  else throw invalidStructure();
  const asked = wanted(request.properties);
  const found = [];
  for (const { certificate, slot } of await tokenCertificates(context)) {
    const x509 = certificate.x509;
    if (typeof pkcs11Store?.slot === "string" && pkcs11Store.slot !== slot) continue;
    if (typeof pkcs11Store?.name === "string" && pkcs11Store.name !== TOKEN_MODEL) continue;
    if (isObject(filter.hash) && !sameHex(filter.hash.data, x509.thumbprint)) continue;
    if (isObject(filter.serialNumber) && !sameHex(filter.serialNumber.data, x509.serialNumber)) continue;
    if (filter.qualified === true && !isQualified(x509)) continue;
    if (filter.gost === true && !x509.publicKeyAlgorithm.startsWith("1.2.643.")) continue;
    const place: TokenPlace = { slot, token: TOKEN_MODEL };
    found.push(certificateFields(x509, asked, place));
    if (filter.firstOnly === true) break;
  }
  return found;
}

async function parseOne(context: KonturContext, request: Request): Promise<unknown> {
  const asked = wanted(request.properties);
  if (!isObject(request.properties) || !Object.keys(request.properties).length || !isObject(request.cert)) throw invalidStructure();
  const x509 = await anyCertificate(context, request.cert);
  return certificateFields(x509, asked);
}

const contentOf = (request: Request, cache: Cache) => readStream(cache, request.source);

async function sign(context: KonturContext, request: Request): Promise<unknown> {
  const cache = cacheOf(context, request);
  if (!Array.isArray(request.certs) || !request.certs.length) throw invalidStructure();
  checkSink(request.sink);
  const content = contentOf(request, cache);
  const [cms] = await signContents(context, request.certs[0], [content], signFlags(request));
  return writeStream(cache, request.sink, request.textualEncoding === true ? pemText(cms!) : cms!);
}

async function batchSign(context: KonturContext, request: Request): Promise<unknown> {
  const cache = cacheOf(context, request);
  const { source, sink } = request;
  if (!Array.isArray(request.certs) || !request.certs.length || !Array.isArray(source) || !Array.isArray(sink) || source.length !== sink.length) throw invalidStructure();
  sink.forEach(checkSink);
  const contents = source.map((stream) => readStream(cache, stream));
  const signatures = await signContents(context, request.certs[0], contents, signFlags(request));
  return signatures.map((cms, index) => writeStream(cache, sink[index], request.textualEncoding === true ? pemText(cms) : cms));
}

async function hashSign(context: KonturContext, request: Request): Promise<unknown> {
  const cache = cacheOf(context, request);
  if (!Array.isArray(request.certs) || !request.certs.length || !isObject(request.hashes)) throw invalidStructure();
  checkSink(request.sink);
  const hashes = new Map(Object.entries(request.hashes).map(([oid, stream]) => [oid, readStream(cache, stream)]));
  const cms = await signHash(context, request.certs[0], hashes, signFlags(request));
  return writeStream(cache, request.sink, request.textualEncoding === true ? pemText(cms) : cms);
}

async function bareSign(context: KonturContext, request: Request): Promise<unknown> {
  const cache = cacheOf(context, request);
  if (!isObject(request.cert)) throw invalidStructure();
  checkSink(request.sink);
  return writeStream(cache, request.sink, await rawSign(context, request.cert, contentOf(request, cache)));
}

async function bareVerify(context: KonturContext, request: Request): Promise<unknown> {
  const cache = cacheOf(context, request);
  if (!isObject(request.cert)) throw invalidStructure();
  return rawVerify(context, request.cert, contentOf(request, cache), readStream(cache, request.signature));
}

async function verify(context: KonturContext, request: Request): Promise<unknown> {
  const cache = cacheOf(context, request);
  const source = contentOf(request, cache);
  const signers = request.signature === undefined ? await verifySignature(context, source, undefined) : await verifySignature(context, readStream(cache, request.signature), source);
  return signers.map((thumbprint) => ({ hash: { data: thumbprint.toLowerCase(), size: 20, type: "hex" } }));
}

async function parseSignature(context: KonturContext, request: Request): Promise<unknown> {
  const cache = cacheOf(context, request);
  const source = contentOf(request, cache);
  const properties = request.properties;
  // Without properties the host answered with no result at all.
  if (properties === undefined) return undefined;
  if (!isObject(properties) || (properties.content !== undefined && !isObject(properties.content)) || (properties.certs !== undefined && !isObject(properties.certs))) throw invalidStructure();
  const signed = signatureParts(source);
  const result: Record<string, unknown> = {};
  if (isObject(properties.certs)) result.certs = signed.certificates.map((x509) => certificateFields(x509, wanted(properties.certs)));
  if (isObject(properties.content) && signed.content) result.content = writeStream(cache, properties.content, signed.content);
  // Nothing asked, no result, as the host answers.
  return Object.keys(result).length ? result : undefined;
}

async function addSignerTo(context: KonturContext, request: Request): Promise<unknown> {
  const cache = cacheOf(context, request);
  if (!Array.isArray(request.certs) || !request.certs.length) throw invalidStructure();
  checkSink(request.sink);
  const source = contentOf(request, cache);
  const cms = request.signature === undefined ? await addSigner(context, request.certs[0], source, undefined) : await addSigner(context, request.certs[0], readStream(cache, request.signature), source);
  return writeStream(cache, request.sink, request.textualEncoding === true ? pemText(cms) : cms);
}

async function encryptCommand(context: KonturContext, request: Request): Promise<unknown> {
  const cache = cacheOf(context, request);
  if (!Array.isArray(request.certs) || !request.certs.length) throw invalidStructure();
  checkSink(request.sink);
  checkAlgorithm(request.encryptionAlgorithm);
  const content = contentOf(request, cache);
  const message = await encrypt(context, request.certs, content);
  return writeStream(cache, request.sink, request.textualEncoding === true ? pemText(message) : message);
}

async function decryptCommand(context: KonturContext, request: Request): Promise<unknown> {
  const cache = cacheOf(context, request);
  checkSink(request.sink);
  return writeStream(cache, request.sink, await decrypt(context, contentOf(request, cache)));
}

export async function answerCommand(context: KonturContext, request: Request): Promise<unknown> {
  switch (request.type) {
    case "plugin.info":
      return {
        architecture: "x86_64",
        buildType: "stable",
        clientId: (await context.settings).konturClientId,
        denied: false,
        platform: platformName(context.platform),
        pluginVersion: PLUGIN_VERSION,
      };
    case "crypto.getTokens":
      return sortKeys(await tokenList(context));
    case "crypto.getCryptoProviders":
    case "crypto.provider.search":
      return sortKeys(await providers(context, request));
    case "crypto.provider.getContainers":
      return sortKeys(await containers(context, request));
    case "cert.search":
      return sortKeys(await searchCertificates(context, request));
    case "cert.parse":
      return sortKeys(await parseOne(context, request));
    case "crypto.sign":
      return sign(context, request);
    case "crypto.batch.sign":
      return batchSign(context, request);
    case "crypto.signHash":
      return hashSign(context, request);
    case "crypto.rawSign":
      return bareSign(context, request);
    case "crypto.rawVerify":
      return bareVerify(context, request);
    case "crypto.verify":
      return sortKeys(await verify(context, request));
    case "crypto.signature.parse":
      return sortKeys(await parseSignature(context, request));
    case "crypto.signature.addSigner":
      return addSignerTo(context, request);
    case "crypto.encrypt":
      return encryptCommand(context, request);
    case "crypto.decrypt":
      return decryptCommand(context, request);
    case "crypto.encryption.parse": {
      const cache = cacheOf(context, request);
      return sortKeys(parseEnveloped(cache, contentOf(request, cache), request.properties));
    }
    case "cert.verify": {
      checkVerifyOptions(request);
      if (request.cert === undefined) throw invalidStructure();
      return sortKeys(await verifyCertificate(request, await anyCertificate(context, request.cert), () => context.session.storeCertificates()));
    }
    case "io.decode":
      return decodeText(request, cacheOf(context, request));
    case "io.encode":
      return encodeText(request, cacheOf(context, request));
    case "http.request":
      return sortKeys(await httpRequest(request, cacheOf(context, request)));
    case "ui.openFile":
      return openFile({ files: context.files, dialogs: context.dialogs, origin: context.session.origin }, request);
    case "ui.saveFile":
      return saveFile({ files: context.files, dialogs: context.dialogs, origin: context.session.origin }, request);
    case "ui.selectFolder":
      return selectFolder({ files: context.files, dialogs: context.dialogs, origin: context.session.origin }, request);
    case "crypto.createCertRequest":
      return sortKeys(await createCertRequest(context, request, cacheOf(context, request), await tokens(context)));
    case "crypto.installCert":
      return installCert(context, request, cacheOf(context, request), await tokens(context));
    case "cert.store.install":
    case "cert.store.remove":
      return storeCommand(request, cacheOf(context, request), request.type === "cert.store.install");
    // The host answers a cancel with nothing, and progress of a command that is not running as unknown.
    case "cancel":
      return undefined;
    case "progress":
      throw pluginError(5, "command not found");
  }
  throw unknownCommand();
}
