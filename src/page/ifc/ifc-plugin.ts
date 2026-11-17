// IFCPlugin, the old Gosuslugi plug-in (docs/PLAN.md, action 45), over the Rutoken Plugin. Its Firefox extension (1.2.8)
// marks the page with div#ifcplugin-extension-is-installed and, once the port to the native host is open,
// div#ifc-plugin-is-installed; the page posts JSON strings {"type":"TO_IFC_EXT","msg_data":{func_name, params}} and gets
// {"type":"FROM_IFC_EXT","msg_data":answer} back, one answer a request, in order (nothing else ties them together), or
// {"type":"IFC_EXT_DISCONNECT"} when the host goes away. The answers are the core's (IFCPlugin 3.1.1), recorded on the
// stand: docs/JOURNAL.md, 2026-11-17. A site passes the token's PIN in its requests; by the options page's switch the
// extension asks it in its own window instead (src/extension/sites.ts, IFC_PIN_WINDOW_KEY).
import { checkSigner, parseSignedData, signerDigest } from "../cms.ts";
import { decodeCp1251, encodeCp1251 } from "../cp1251.ts";
import { CadesError } from "../errors.ts";
import { digest, GOST_2001, GOST_2012_512, verifyHash, type DigestName } from "../gost.ts";
import type { Session } from "../objects/session.ts";
import { pageSession } from "../page-session.ts";
import type { PinRequest } from "../pin-dialog.ts";
import type { Clock } from "../rutoken.ts";
import { pageSettings, type Settings } from "../settings.ts";
import { certificateLines, sizeText } from "../signing.ts";
import { pkcs11Serial, userCertificates, type TokenCertificate } from "../token.ts";
import type { TokenKeyIds } from "../key-ids.ts";
import { PinRejected, SCARD_W_CANCELLED_BY_USER, withGivenPin, withLogin } from "../token-login.ts";
import { parseCertificate, pemToDer, type X509 } from "../x509.ts";
import { opensslExtensions, opensslName, opensslSerial, opensslTime } from "./openssl-text.ts";
import { certificatePolicies, encodeSubject, extendedKeyUsage, KEY_USAGE, nconfExtension, requestInfo, requestPublicKey, signedRequest, signingTool, type SubjectEntry } from "./request.ts";
import { parseXml, securityToken, signTemplate, verifyTemplate, WsSecurityError } from "./ws-security.ts";

export const TO_IFC_EXT = "TO_IFC_EXT";
export const FROM_IFC_EXT = "FROM_IFC_EXT";
export const IFC_EXT_DISCONNECT = "IFC_EXT_DISCONNECT";
export const EXTENSION_MARKER = "ifcplugin-extension-is-installed";
export const PLUGIN_MARKER = "ifc-plugin-is-installed";

export const IFC_VERSION = "3.1.1";
// The token's entry in the core's configuration (ifc.cfg): its alias in cryptoIDs and container ids.
export const ALIAS = "ruTokenECP";

// The core's codes (libwebparser's table): 1 unknown error, 5 incorrect parameters, 7 crypto not found, 9 certificate
// not found, 10 key container not found, 14 incorrect signature type, 17 unsupported operation, 19 unable to verify
// signature, 25 no such slot, 27 no element with the id; 160 and 164 are CKR_PIN_INCORRECT and CKR_PIN_LOCKED.
export class IfcError extends Error {
  readonly code: number;

  constructor(code: number) {
    super(`IFCPlugin error ${code}`);
    this.name = "IfcError";
    this.code = code;
  }
}

type Params = Record<string, unknown>;
type Answer = Record<string, unknown>;

interface Token {
  deviceId: number;
  slot: number;
  serial: string;
  reader: string;
}

// What a page's requests share: the session, the certificates loaded under handles, and the containers named by the
// site (key_gen's names) mapped to keys, which the Rutoken Plugin shows only after a login.
interface Context {
  session: Session;
  settings: Promise<Settings>;
  handles: Map<number, X509>;
  nextHandle: number;
  named: Map<string, { keyId: string; size: 256 | 512 }>;
  // Posts a frame before the answer (show_progress).
  progress(frame: Answer): void;
}

const libraryPath = () => {
  const platform = String((globalThis.navigator as { platform?: string } | undefined)?.platform ?? "");
  if (/^Win/i.test(platform)) return "rtpkcs11ecp.dll";
  if (/^Mac/i.test(platform)) return "librtpkcs11ecp.dylib";
  return "librtpkcs11ecp.so";
};

const serialHex = pkcs11Serial;

async function tokens(session: Session): Promise<Token[]> {
  const plugin = session.plugin;
  const [serialInfo, readerInfo] = await Promise.all([plugin.TOKEN_INFO_SERIAL, plugin.TOKEN_INFO_READER]);
  const result: Token[] = [];
  for (const [slot, deviceId] of (await plugin.enumerateDevices()).entries()) {
    result.push({ deviceId, slot, serial: String(await plugin.getDeviceInfo(deviceId, serialInfo)), reader: String(await plugin.getDeviceInfo(deviceId, readerInfo)) });
  }
  return result;
}

// "ruTokenECP/0": the token in that slot.
async function tokenOf(context: Context, cryptoId: unknown): Promise<Token> {
  if (typeof cryptoId !== "string" || !cryptoId) throw new IfcError(5);
  const [alias, slot, ...rest] = cryptoId.split("/");
  if (alias !== ALIAS) throw new IfcError(7);
  if (slot === undefined || rest.length || !/^\d+$/.test(slot)) throw new IfcError(10);
  const token = (await tokens(context.session)).find((candidate) => candidate.slot === Number(slot));
  if (!token) throw new IfcError(25);
  return token;
}

// A container id: "ruTokenECP/0/<id>", the id being a certificate's (its thumbprint) or a key's name.
async function containerOf(context: Context, containerId: unknown): Promise<{ token: Token; id: string }> {
  if (typeof containerId !== "string" || !containerId) throw new IfcError(5);
  const parts = containerId.split("/");
  if (parts.length < 3) throw new IfcError(1);
  return { token: await tokenOf(context, parts.slice(0, 2).join("/")), id: parts.slice(2).join("/") };
}

async function tokenCertificates(context: Context, token: Token): Promise<TokenCertificate[]> {
  return (await userCertificates(context.session.plugin)).filter((certificate) => certificate.deviceId === token.deviceId);
}

const keySize = (x509: X509): 256 | 512 => (x509.publicKeyAlgorithm === GOST_2012_512 ? 512 : 256);
const keyDigest = (x509: X509): DigestName => (x509.publicKeyAlgorithm === GOST_2001 ? "gost94" : x509.publicKeyAlgorithm === GOST_2012_512 ? "streebog512" : "streebog256");
const sizeDigest = (size: 256 | 512): DigestName => (size === 512 ? "streebog512" : "streebog256");

// A key's CKA_ID as the Rutoken Plugin writes it, from a container name: its bytes in Windows-1251.
function keyIdOfName(name: string): string | undefined {
  const bytes = encodeCp1251(name);
  return bytes?.length ? Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(":") : undefined;
}

// The name the core gives a key: its CKA_ID in Windows-1251, up to the first zero byte (it reads the id as a C string).
function nameOfKeyId(keyId: string): string {
  const bytes = keyId.split(":").map((pair) => parseInt(pair, 16));
  const zero = bytes.indexOf(0);
  return decodeCp1251(Uint8Array.from(zero < 0 ? bytes : bytes.slice(0, zero)));
}

interface Resolved {
  token: Token;
  certificate?: TokenCertificate;
  // Known without a login only for keys the page named.
  keyId?: string;
  size: 256 | 512;
  digest: DigestName;
}

// The keys' ids of a token known from earlier logins (src/page/key-ids.ts).
async function knownIds(context: Context, token: Token): Promise<TokenKeyIds> {
  return (await context.session.keyIds())[token.serial] ?? { certificates: {}, keys: [] };
}

// A certificate's id as the core shows it: its key's CKA_ID in Windows-1251, once a login has told it; until then, the
// certificate's thumbprint.
async function certificateId(context: Context, token: Token, x509: X509): Promise<string> {
  const keyId = (await knownIds(context, token)).certificates[x509.thumbprint];
  return keyId ? nameOfKeyId(keyId) : x509.thumbprint;
}

async function certificateList(context: Context, token: Token): Promise<Answer[]> {
  const result: Answer[] = [];
  for (const certificate of await tokenCertificates(context, token)) result.push(certificateEntry(certificate.x509, await certificateId(context, token, certificate.x509)));
  return result;
}

// What a container id names, without a login: a certificate by its key's id or its thumbprint, or a key known from a
// login or made on this page.
async function resolve(context: Context, containerId: unknown): Promise<Resolved> {
  const { token, id } = await containerOf(context, containerId);
  const certificates = await tokenCertificates(context, token);
  const known = await knownIds(context, token);
  const byKey = Object.entries(known.certificates).find(([, keyId]) => nameOfKeyId(keyId) === id);
  const certificate = certificates.find((candidate) => candidate.x509.thumbprint === (byKey ? byKey[0] : id.toUpperCase()));
  if (certificate) return { token, certificate, ...(byKey ? { keyId: byKey[1] } : {}), size: keySize(certificate.x509), digest: keyDigest(certificate.x509) };
  const named = context.named.get(`${token.serial}/${id}`);
  if (named) return { token, keyId: named.keyId, size: named.size, digest: sizeDigest(named.size) };
  const knownKey = known.keys.find((keyId) => nameOfKeyId(keyId) === id);
  if (knownKey) return { token, keyId: knownKey, size: 256, digest: "streebog256" };
  // A key by its name, found after a login (keyOf).
  const keyId = keyIdOfName(id);
  if (!keyId) throw new IfcError(1);
  return { token, keyId: `?${keyId}`, size: 256, digest: "streebog256" };
}

// Inside a login: the key's id on the token, and its certificate if it has one; throws 1 when there is no such key.
async function keyOf(context: Context, resolved: Resolved): Promise<{ keyId: string; certificate?: TokenCertificate }> {
  const plugin = context.session.plugin;
  const deviceId = resolved.token.deviceId;
  if (resolved.certificate) {
    try {
      return { keyId: resolved.keyId ?? (await plugin.getKeyByCertificate(deviceId, resolved.certificate.certId)), certificate: resolved.certificate };
    } catch {
      throw new IfcError(1);
    }
  }
  const wanted = resolved.keyId!.replace(/^\?/, "");
  const keys = await plugin.enumerateKeys(deviceId, "");
  // The core reads the id up to its first zero byte; the name may be that prefix.
  const keyId = keys.find((key) => key.toLowerCase() === wanted) ?? keys.find((key) => keyIdOfName(nameOfKeyId(key)) === wanted);
  if (!keyId) throw new IfcError(1);
  for (const certificate of await tokenCertificates(context, resolved.token)) {
    try {
      if ((await plugin.getKeyByCertificate(deviceId, certificate.certId)) === keyId) return { keyId, certificate };
    } catch {
      // A certificate without its key.
    }
  }
  return { keyId };
}

// One operation logged in: with the site's PIN, as the original does, or by the switch with the extension's window.
async function loggedIn<T>(context: Context, token: Token, pin: unknown, request: () => PinRequest, work: () => Promise<T>, noPin = 1): Promise<T> {
  const session = context.session;
  if ((await context.settings).ifcPinWindow) {
    try {
      return await withLogin(session, token.deviceId, request(), work);
    } catch (error) {
      if (error instanceof CadesError && error.number === SCARD_W_CANCELLED_BY_USER) throw new IfcError(1);
      throw error;
    }
  }
  if (typeof pin !== "string" || !pin) throw new IfcError(noPin);
  try {
    return await withGivenPin(session, token.deviceId, pin, work);
  } catch (error) {
    if (error instanceof PinRejected) throw new IfcError(error.locked ? 164 : 160);
    throw error;
  }
}

function pinRequest(context: Context, action: string, details: string[], confirm: string): () => PinRequest {
  return () => ({ origin: context.session.origin, action, details: ["Запрос сайта к плагину Госуслуг (IFCPlugin).", ...details], confirm });
}

const base64Of = (bytes: Uint8Array) => btoa(Array.from(bytes, (byte) => String.fromCharCode(byte)).join(""));

function bytesOfBase64(text: unknown): Uint8Array {
  if (typeof text !== "string") throw new IfcError(5);
  try {
    return Uint8Array.from(atob(text.replace(/\s+/g, "")), (char) => char.charCodeAt(0));
  } catch {
    throw new IfcError(20);
  }
}

// inDataType 1: the string's own bytes; 2: Base64.
function inputData(params: Params): Uint8Array {
  if (params.data === undefined) throw new IfcError(5);
  if (params.inDataType === 1) return new TextEncoder().encode(String(params.data));
  if (params.inDataType === 2) return bytesOfBase64(params.data);
  throw new IfcError(17);
}

const hexColonOf = (bytes: Uint8Array) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(":");
const bytesOfHexColon = (hex: string) => Uint8Array.from(hex.split(":"), (pair) => parseInt(pair, 16));

function certificateEntry(x509: X509, id: string): Answer {
  return {
    cert_issuer: opensslName(x509.issuer),
    cert_sign_alg: x509.publicKeyAlgorithm,
    cert_sn: opensslSerial(x509),
    cert_subject: opensslName(x509.subject),
    cert_valid_from: opensslTime(x509.notBefore),
    cert_valid_to: opensslTime(x509.notAfter),
    id,
  };
}

const EMPTY_CERTIFICATE = { cert_issuer: "", cert_sign_alg: "", cert_sn: "", cert_subject: "", cert_valid_from: "", cert_valid_to: "" };

function pem(der: Uint8Array, label: string): string {
  return `-----BEGIN ${label}-----\n${(base64Of(der).match(/.{1,64}/g) ?? []).join("\n")}\n-----END ${label}-----`;
}

function newHandle(context: Context, x509: X509): number {
  const handle = context.nextHandle++;
  context.handles.set(handle, x509);
  return handle;
}

function handleOf(context: Context, value: unknown): X509 {
  if (value === undefined || value === null || value === "") throw new IfcError(5);
  const x509 = context.handles.get(Number(value));
  if (!x509) throw new IfcError(9);
  return x509;
}

async function rawSignature(context: Context, deviceId: number, keyId: string, hash: Uint8Array): Promise<Uint8Array> {
  return bytesOfHexColon(await context.session.plugin.rawSign(deviceId, keyId, hexColonOf(hash), {}));
}

function guid(prefix: unknown): string {
  const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const random = crypto.getRandomValues(new Uint8Array(32));
  const chars = Array.from(random, (byte) => alphabet[byte % alphabet.length]).join("");
  return `${typeof prefix === "string" ? prefix : ""}${chars.slice(0, 8)}-${chars.slice(8, 12)}-${chars.slice(12, 16)}-${chars.slice(16, 20)}-${chars.slice(20, 32)}`;
}

type Handler = (context: Context, params: Params) => Promise<Answer>;

const handlers: Record<string, Handler> = {
  async version() {
    return { version: IFC_VERSION };
  },

  // The configuration is the extension's own: any file the site names is fine.
  async create() {
    return {};
  },

  async get_list_info(context, params) {
    if (params.cryptoType !== undefined) return { ifc_list: [], ifc_list_length: 0 };
    const list = (await tokens(context.session)).map((token) => ({
      alg: "gost2001",
      alias: ALIAS,
      description: token.reader,
      model: "Rutoken ECP",
      name: "Актив Рутокен ЭЦП",
      num: String(token.slot),
      path: libraryPath(),
      serial_number: serialHex(token.serial),
      skip_pkcs11_list: "",
      type: "pkcs11",
    }));
    return { ifc_list: list, ifc_list_length: list.length };
  },

  async get_list_certs(context, params) {
    const token = await tokenOf(context, params.cryptoID);
    return { cert_list: await certificateList(context, token) };
  },

  async get_list_certs_by_cryptoid_array(context, params) {
    const ids = Array.isArray(params.cryptoID_array) ? params.cryptoID_array : [];
    const lists: { certificates: Answer[]; id: string }[] = [];
    for (const id of ids) lists.push({ id: String(id), certificates: await certificateList(context, await tokenOf(context, id)) });
    const result_array = lists.map(({ id, certificates }) => ({ cert_list: certificates, crypto_id: id }));
    if (params.show_progress === true) {
      const count = lists.reduce((sum, list) => sum + list.certificates.length, 0);
      for (let counter = 0; counter <= count; counter++) context.progress({ certs_count: count, error_code: 0, intermediate: 1, progress_counter: counter });
      return { intermediate: 0, result_array };
    }
    return { result_array };
  },

  async get_list_keys(context, params) {
    const token = await tokenOf(context, params.cryptoID);
    const plugin = context.session.plugin;
    const request = pinRequest(context, "просит показать ключи на Рутокене.", [`Рутокен ${serialHex(token.serial)}.`], "Показать");
    const certificates = await tokenCertificates(context, token);
    const keys = await loggedIn(context, token, params.userPin, request, async () => {
      const byKey = new Map<string, TokenCertificate>();
      for (const certificate of certificates) {
        try {
          byKey.set(await plugin.getKeyByCertificate(token.deviceId, certificate.certId), certificate);
        } catch {
          // A certificate without its key is not listed with the keys.
        }
      }
      const [algorithmInfo, gost512] = await Promise.all([plugin.KEY_INFO_ALGORITHM, plugin.PUBLIC_KEY_ALGORITHM_GOST3410_2012_512]);
      const result: Answer[] = [];
      for (const keyId of await plugin.enumerateKeys(token.deviceId, "")) {
        const certificate = byKey.get(keyId);
        if (certificate) {
          result.push(certificateEntry(certificate.x509, nameOfKeyId(keyId)));
          continue;
        }
        const name = nameOfKeyId(keyId);
        let size: 256 | 512 = 256;
        try {
          if ((await plugin.getKeyInfo(token.deviceId, keyId, algorithmInfo)) === gost512) size = 512;
        } catch {
          // Its algorithm unknown, the key counts as 256-bit.
        }
        context.named.set(`${token.serial}/${name}`, { keyId, size });
        result.push({ ...EMPTY_CERTIFICATE, id: name });
      }
      return result;
    }, 5);
    return { keys_list: keys };
  },

  async load_x509_from_container(context, params) {
    const resolved = await resolve(context, params.containerId);
    if (!resolved.certificate) throw new IfcError(1);
    return { x509Handle: newHandle(context, resolved.certificate.x509) };
  },

  async load_x509_from_data(context, params) {
    if (params.cert_data_type === 1) throw new IfcError(17);
    if (params.cert_data_type !== 0 || typeof params.cert !== "string") throw new IfcError(5);
    let x509: X509;
    try {
      x509 = parseCertificate(pemToDer(params.cert));
    } catch {
      throw new IfcError(9);
    }
    return { x509Handle: newHandle(context, x509) };
  },

  async get_x509_info(context, params) {
    const x509 = handleOf(context, params.x509Handle);
    if (!x509.publicKeyAlgorithm.startsWith("1.2.643.")) throw new IfcError(1);
    return {
      cert_info: {
        base64: base64Of(x509.der),
        cert_issuer: opensslName(x509.issuer),
        cert_sign_alg: x509.publicKeyAlgorithm,
        cert_sn: opensslSerial(x509),
        cert_subject: opensslName(x509.subject),
        cert_valid_from: opensslTime(x509.notBefore),
        cert_valid_to: opensslTime(x509.notAfter),
        extensions: opensslExtensions(x509),
        pem: pem(x509.der, "CERTIFICATE"),
        version: String(x509.version),
      },
    };
  },

  async free_x509(context, params) {
    if (params.x509Handle === undefined) throw new IfcError(5);
    context.handles.delete(Number(params.x509Handle));
    return {};
  },

  async get_guid(_, params) {
    return { guid: guid(params.prefix) };
  },

  async hash(context, params) {
    if (params.containerId === undefined) throw new IfcError(5);
    const data = inputData(params);
    if (params.outDataType !== 1) throw new IfcError(17);
    const resolved = await resolve(context, params.containerId);
    if (resolved.keyId?.startsWith("?")) throw new IfcError(1);
    return { hashValue: base64Of(digest(resolved.digest, data)) };
  },

  async sign(context, params) {
    const type = Number(params.signType);
    if (!(type >= 1 && type <= 6)) throw new IfcError(14);
    const hashGiven = params.inDataType === 4;
    if (hashGiven && type > 2) throw new IfcError(1);
    const data = hashGiven ? bytesOfBase64(params.data) : inputData(params);
    if (params.outDataType !== 1) throw new IfcError(17);
    const resolved = await resolve(context, params.containerId);
    const plugin = context.session.plugin;
    const deviceId = resolved.token.deviceId;
    const kind = type <= 2 ? "подпись хеша без CMS" : type % 2 ? "присоединённая подпись" : "отсоединённая подпись";
    const request = pinRequest(context, "просит подписать данные.", [`${hashGiven ? "Хеш данных" : sizeText(data.length)}, ${kind}.`, ...(resolved.certificate ? certificateLines(resolved.certificate.x509) : [])], "Подписать");
    const signature = await loggedIn(context, resolved.token, params.userPin, request, async () => {
      const key = await keyOf(context, resolved);
      if (type <= 2) {
        const size = key.certificate ? keySize(key.certificate.x509) : resolved.size;
        const hash = hashGiven ? data : digest(key.certificate ? keyDigest(key.certificate.x509) : sizeDigest(size), data);
        const raw = await rawSignature(context, deviceId, key.keyId, hash);
        return type === 2 ? raw.reverse() : raw;
      }
      if (!key.certificate) throw new IfcError(9);
      const options = { detached: type % 2 === 0, addUserCertificate: true, addEssCert: type >= 5, addSignTime: true };
      const cms = await plugin.sign(deviceId, key.certificate.certId, base64Of(data), await plugin.DATA_FORMAT_BASE64, options);
      return bytesOfBase64(cms);
    });
    return { sign_value: base64Of(signature) };
  },

  async verify(context, params) {
    const certificate = handleOf(context, params.x509Handle);
    const type = Number(params.signType);
    if (!(type >= 1 && type <= 6)) throw new IfcError(14);
    const resolved = await resolve(context, params.containerId);
    const x509 = resolved.certificate?.x509 ?? certificate;
    const signature = bytesOfBase64(params.sign);
    let valid: boolean;
    if (type <= 2) {
      const hash = params.inDataType === 4 ? bytesOfBase64(params.data) : digest(keyDigest(x509), inputData(params));
      valid = verifyHash(x509, hash, type === 2 ? Uint8Array.from(signature).reverse() : signature);
    } else {
      try {
        const signed = parseSignedData(signature);
        const content = type % 2 ? signed.content : inputData(params);
        const info = signed.signers[0];
        const name = info && signerDigest(info);
        valid = Boolean(info && name && content && checkSigner(info, x509, digest(name, content)) === "valid");
      } catch (error) {
        if (error instanceof IfcError) throw error;
        valid = false;
      }
    }
    const code = valid ? 0 : 19;
    return { error_code: code, verify_result: code };
  },

  async sign_xml(context, params) {
    const resolved = await resolve(context, params.containerId);
    const text = new TextDecoder().decode(inputData(params));
    if (params.outDataType !== 1 && params.outDataType !== 2) throw new IfcError(17);
    const id = typeof params.wsu_id === "string" ? params.wsu_id : "";
    const doc = parseXml(text);
    const deviceId = resolved.token.deviceId;
    const request = pinRequest(context, "просит подписать XML-документ.", [`${sizeText(text.length)}, подпись WS-Security.`, ...(resolved.certificate ? certificateLines(resolved.certificate.x509) : [])], "Подписать");
    const signed = await loggedIn(context, resolved.token, params.userPin, request, async () => {
      const key = await keyOf(context, resolved);
      const name = key.certificate ? keyDigest(key.certificate.x509) : resolved.digest;
      return signTemplate(doc, id, (data) => digest(name, data), (hash) => rawSignature(context, deviceId, key.keyId, hash));
    });
    return { sign_value: params.outDataType === 2 ? signed : base64Of(new TextEncoder().encode(signed)) };
  },

  async verify_xml(context, params) {
    if (params.containerId === undefined) throw new IfcError(5);
    const id = typeof params.wsu_id === "string" ? params.wsu_id : "";
    let resolved: Resolved;
    try {
      resolved = await resolve(context, params.containerId);
    } catch (error) {
      if (error instanceof IfcError && error.code === 1) return { error_code: 1, verify_result: 1 };
      throw error;
    }
    if (params.inDataType !== 1 && params.inDataType !== 2) throw new IfcError(17);
    const text = params.inDataType === 2 ? new TextDecoder().decode(bytesOfBase64(params.sign)) : String(params.sign ?? "");
    const doc = parseXml(text);
    const token = securityToken(doc, id);
    if (!token) throw new IfcError(5);
    let x509: X509;
    try {
      x509 = parseCertificate(bytesOfBase64(token));
    } catch {
      throw new IfcError(5);
    }
    const code = verifyTemplate(doc, id, (data) => digest(resolved.digest, data), (hash, signature) => verifyHash(x509, hash, signature)) ? 0 : 19;
    return { error_code: code, verify_result: code };
  },

  async key_gen(context, params) {
    const { token, id } = await containerOf(context, params.containerId);
    const keyId = keyIdOfName(id);
    if (!keyId) throw new IfcError(5);
    const plugin = context.session.plugin;
    const request = pinRequest(context, "просит создать ключ на Рутокене.", [`Ключ ГОСТ Р 34.10-2012 256 бит «${id}».`, `Рутокен ${serialHex(token.serial)}.`], "Создать");
    await loggedIn(context, token, params.userPin, request, async () => {
      // A key with this id already: the core cannot store another.
      if ((await plugin.enumerateKeys(token.deviceId, "")).includes(keyId)) throw new IfcError(1);
      try {
        await plugin.generateKeyPair(token.deviceId, undefined, "", {
          publicKeyAlgorithm: await plugin.PUBLIC_KEY_ALGORITHM_GOST3410_2012_256,
          signatureSize: 512,
          keySpec: await plugin.KEY_SPEC_SIGN_AND_EXCHANGE,
          // The core's parameters (CryptoPro XchA) and its id: the name's bytes.
          paramset: "XA",
          id: keyId,
        });
      } catch {
        throw new IfcError(1);
      }
    });
    context.named.set(`${token.serial}/${id}`, { keyId, size: 256 });
    return { real_id: params.containerId };
  },

  async req_gen(context, params) {
    const format = params.req_format === undefined ? 2 : params.req_format;
    if (format !== 1 && format !== 2) throw new IfcError(17);
    const subject = subjectEntries(params.subject);
    const extensions = [KEY_USAGE];
    const list = (value: unknown) => (Array.isArray(value) ? value.map(String).filter(Boolean) : []);
    if (list(params.extendedKeyUsage).length) extensions.push(extendedKeyUsage(list(params.extendedKeyUsage)));
    if (list(params.certificatePolicies).length) extensions.push(certificatePolicies(list(params.certificatePolicies)));
    if (typeof params.signInstrument === "string" && params.signInstrument) extensions.push(signingTool(params.signInstrument));
    for (const [oid, value] of csrExtensions(params.csrExtensions)) {
      const encoded = nconfExtension(oid, value);
      if (!encoded) throw new IfcError(1);
      extensions.push(encoded);
    }
    const resolved = await resolve(context, params.containerId);
    const plugin = context.session.plugin;
    const deviceId = resolved.token.deviceId;
    const owner = subject.find((entry) => entry.oid === "2.5.4.3")?.value ?? "";
    const request = pinRequest(context, "просит создать запрос на сертификат.", [`Владелец: ${owner}`, `Рутокен ${serialHex(resolved.token.serial)}.`], "Создать");
    const der = await loggedIn(context, resolved.token, params.userPin, request, async () => {
      const key = await keyOf(context, resolved);
      const size = key.certificate ? keySize(key.certificate.x509) : (await plugin.getKeyInfo(deviceId, key.keyId, await plugin.KEY_INFO_ALGORITHM)) === (await plugin.PUBLIC_KEY_ALGORITHM_GOST3410_2012_512) ? 512 : 256;
      const hashType = size === 512 ? await plugin.HASH_TYPE_GOST3411_12_512 : await plugin.HASH_TYPE_GOST3411_12_256;
      let publicKey: Uint8Array;
      try {
        publicKey = requestPublicKey(pemToDer(await plugin.createPkcs10(deviceId, key.keyId, [{ rdn: "commonName", value: "key" }], {}, { hashAlgorithm: hashType })));
      } catch {
        throw new IfcError(1);
      }
      const info = requestInfo(encodeSubject(subject), publicKey, extensions);
      const signature = await rawSignature(context, deviceId, key.keyId, digest(sizeDigest(size), info));
      return signedRequest(info, size === 512 ? "1.2.643.7.1.1.3.3" : "1.2.643.7.1.1.3.2", signature);
    });
    if (format === 1) {
      const text = `${pem(der, "CERTIFICATE REQUEST")}\n`;
      return { req_pem: text, req_pem_length: text.length };
    }
    const text = base64Of(der);
    return { req_base64: text, req_base64_length: text.length };
  },

  async set_x509(context, params) {
    const x509 = handleOf(context, params.x509Handle);
    const { token } = await containerOf(context, params.containerId);
    const plugin = context.session.plugin;
    if ((await tokenCertificates(context, token)).some((certificate) => certificate.x509.thumbprint === x509.thumbprint)) throw new IfcError(1);
    const request = pinRequest(context, "просит записать сертификат на Рутокен.", certificateLines(x509), "Записать");
    await loggedIn(context, token, params.userPin, request, async () => {
      try {
        await plugin.importCertificate(token.deviceId, `${pem(x509.der, "CERTIFICATE")}\n`, await plugin.CERT_CATEGORY_USER);
      } catch {
        throw new IfcError(1);
      }
    });
    return {};
  },
};

// The subject of req_gen: {oids_count, oid_1, oid_type_1, value_1, …}, numbered from 1.
function subjectEntries(subject: unknown): SubjectEntry[] {
  if (!subject || typeof subject !== "object") throw new IfcError(5);
  const fields = subject as Record<string, unknown>;
  const count = fields.oids_count === undefined ? 0 : fields.oids_count;
  if (typeof count !== "number") throw new IfcError(5);
  const entries: SubjectEntry[] = [];
  for (let index = 1; index <= count; index++) {
    const oid = fields[`oid_${index}`];
    const type = fields[`oid_type_${index}`] ?? 0;
    const value = fields[`value_${index}`];
    if (typeof oid !== "string" || !/^\d+(\.\d+)+$/.test(oid) || typeof type !== "number" || typeof value !== "string") throw new IfcError(5);
    entries.push({ oid, type, value });
  }
  return entries;
}

function csrExtensions(value: unknown): [string, string][] {
  if (!value || typeof value !== "object") return [];
  const fields = value as Record<string, unknown>;
  const count = typeof fields.oids_count === "number" ? fields.oids_count : 0;
  const result: [string, string][] = [];
  for (let index = 1; index <= count; index++) {
    const oid = fields[`oid_${index}`];
    const text = fields[`value_${index}`];
    if (typeof oid !== "string" || typeof text !== "string") throw new IfcError(5);
    result.push([oid, text]);
  }
  return result;
}

// jsoncpp writes an object's members sorted by name.
function sorted(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sorted);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sorted((value as Record<string, unknown>)[key])]));
  }
  return value;
}

// The answer to one request: the handler's fields with error_code 0, or the error's code.
export async function answer(context: Context, request: unknown): Promise<Answer> {
  const { func_name: name, params } = (request ?? {}) as { func_name?: unknown; params?: unknown };
  const handler = typeof name === "string" && Object.hasOwn(handlers, name) ? handlers[name] : undefined;
  if (!handler) return { error_code: 17 };
  try {
    return sorted({ error_code: 0, ...(await handler(context, (params && typeof params === "object" ? params : {}) as Params)) }) as Answer;
  } catch (error) {
    if (error instanceof IfcError || error instanceof WsSecurityError) return { error_code: error.code };
    console.warn("Рутокен вместо IFCPlugin:", error);
    return { error_code: 1 };
  }
}

export function createContext(session: Session, settings: Promise<Settings>, progress: (frame: Answer) => void): Context {
  return { session, settings, handles: new Map(), nextHandle: 2, named: new Map(), progress };
}

// Plays IFCPlugin on the page: the markers once the document is parsed, and the answers, in order.
export function startIfcPlugin(win: Window & Record<string, unknown>, clock: Clock): void {
  let connected = true;
  let queue: Promise<unknown> = Promise.resolve();
  let context: Promise<Context> | undefined;
  const post = (message: unknown) => win.postMessage(JSON.stringify(message), "*");
  const getContext = () =>
    (context ??= pageSession(win, clock).then((session) => createContext(session, pageSettings(win, clock), (frame) => post({ type: FROM_IFC_EXT, msg_data: frame }))));
  const disconnect = () => {
    if (!connected) return;
    connected = false;
    post({ type: IFC_EXT_DISCONNECT });
    win.document.getElementById(PLUGIN_MARKER)?.remove();
  };

  win.addEventListener("message", (event: MessageEvent) => {
    if (event.source !== win || typeof event.data !== "string" || !connected) return;
    let message: { type?: unknown; msg_data?: unknown };
    try {
      message = JSON.parse(event.data);
    } catch {
      return;
    }
    if (message?.type !== TO_IFC_EXT) return;
    const request = message.msg_data;
    queue = queue.then(async () => {
      let ready: Context;
      try {
        ready = await getContext();
      } catch {
        disconnect();
        return;
      }
      if (connected) post({ type: FROM_IFC_EXT, msg_data: await answer(ready, request) });
    });
  });

  const mark = () => {
    const doc = win.document;
    for (const id of [EXTENSION_MARKER, PLUGIN_MARKER]) {
      const div = doc.createElement("div");
      div.id = id;
      doc.body?.appendChild(div);
    }
    // The original's port fails at once without its native host; without the Rutoken Plugin, so does this.
    getContext().catch(disconnect);
  };
  if (win.document.readyState === "loading") win.document.addEventListener("DOMContentLoaded", mark, { once: true });
  else mark();
}
