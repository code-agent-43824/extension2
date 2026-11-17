// The methods of Gosplugin's core (1.3.42) over the Rutoken Plugin, answering as the core answered on the stand
// (docs/JOURNAL.md, 2026-11-17). The PIN is asked in the extension's window, as the core asks it in its own.
import { children, decodeOid, read } from "../asn1.ts";
import { encodeCp1251 } from "../cp1251.ts";
import { CadesError } from "../errors.ts";
import { digest, GOST_2012_512, type DigestName } from "../gost.ts";
import { certificatePolicies, encodeSubject, extendedKeyUsage, identificationKind, keyUsage, requestInfo, requestPublicKey, signedRequest, signingTool } from "../ifc/request.ts";
import type { Session } from "../objects/session.ts";
import type { PinRequest } from "../pin-dialog.ts";
import { certificateLines, sizeText } from "../signing.ts";
import { pkcs11Serial, userCertificates, type TokenCertificate } from "../token.ts";
import { SCARD_W_CANCELLED_BY_USER, withLogin } from "../token-login.ts";
import { parseCertificate, pemToDer, type X509 } from "../x509.ts";
import { GosError, SUCCESS_MESSAGE } from "./messages.ts";
import { keyIdBytes } from "../key-ids.ts";
import { BUILT_IN_IDENTITIES, ipConfig, type FakeIdentity } from "../identity.ts";
import { smevTransform, SMEV_TRANSFORM } from "./smev-transform.ts";
import { signXml } from "./xmldsig.ts";
import { CORE_CONFIG } from "./config.ts";

interface Token {
  deviceId: number;
  // The Rutoken Plugin's, which the keys' ids are kept by (src/page/key-ids.ts).
  rawSerial: string;
  serial: string;
  label: string;
  model: string;
  // "Rutoken ECP <serial>": the core's provider and store name.
  name: string;
}

export interface CoreContext {
  session: Session;
  lastError: string;
  // The made-up user, computer and network (src/page/identity.ts), and the platform its interfaces are named for.
  identity: Promise<FakeIdentity>;
  platform: string;
}

const base64Of = (bytes: Uint8Array) => btoa(Array.from(bytes, (byte) => String.fromCharCode(byte)).join(""));

function bytesOf(text: unknown): Uint8Array {
  try {
    return Uint8Array.from(atob(String(text ?? "").replace(/\s+/g, "")), (char) => char.charCodeAt(0));
  } catch {
    throw new GosError(20001);
  }
}

async function tokens(session: Session): Promise<Token[]> {
  const plugin = session.plugin;
  const [serialInfo, labelInfo, modelInfo] = await Promise.all([plugin.TOKEN_INFO_SERIAL, plugin.TOKEN_INFO_LABEL, plugin.TOKEN_INFO_MODEL]);
  const result: Token[] = [];
  for (const deviceId of await plugin.enumerateDevices()) {
    const rawSerial = String(await plugin.getDeviceInfo(deviceId, serialInfo));
    const serial = pkcs11Serial(rawSerial);
    result.push({ deviceId, rawSerial, serial, label: String(await plugin.getDeviceInfo(deviceId, labelInfo)), model: String(await plugin.getDeviceInfo(deviceId, modelInfo)), name: `Rutoken ECP ${serial}` });
  }
  return result;
}

// The token certificates, each with its token.
async function tokenCertificates(session: Session): Promise<{ token: Token; certificate: TokenCertificate }[]> {
  const list = await tokens(session);
  return (await userCertificates(session.plugin)).flatMap((certificate) => {
    const token = list.find((candidate) => candidate.deviceId === certificate.deviceId);
    return token ? [{ token, certificate }] : [];
  });
}

const KEY_USAGE_NAMES = ["digitalsignature", "nonrepudiation", "keyencipherment", "dataencipherment", "keyagreement", "keycertsign", "crlsign", "encipheronly", "decipheronly"];

const nameText = (name: X509["subject"]) =>
  name
    .flat()
    .map((attribute) => `${attribute.oid}=${attribute.value}`)
    .join(";");

const seconds = (date: Date | null) => (date ? String(Math.floor(date.getTime() / 1000)) : "");

function extensionValue(x509: X509, oid: string): Uint8Array | undefined {
  return x509.extensions.find((extension) => extension.oid === oid)?.value;
}

// The core's name of a key container: the key's CKA_ID, its bytes as text (the core writes them into its JSON as they
// are, and the browser reads them as UTF-8).
const containerName = (keyId: string) => new TextDecoder().decode(keyIdBytes(keyId));

// The certificate's container once a login has told its key's id (src/page/key-ids.ts); until then, its thumbprint.
async function containerOf(session: Session, token: Token, x509: X509): Promise<string> {
  const keyId = (await session.keyIds())[token.rawSerial]?.certificates[x509.thumbprint];
  return keyId ? containerName(keyId) : x509.thumbprint;
}

// The core's fields of a certificate; `onToken` adds where its key is.
export function certificateFields(x509: X509, onToken?: { token: Token; container: string }): Record<string, string> {
  const ku = extensionValue(x509, "2.5.29.15");
  const bits = ku ? read(ku).value : new Uint8Array();
  const usage = KEY_USAGE_NAMES.filter((_, bit) => ((bits[1 + (bit >> 3)] ?? 0) & (0x80 >> (bit & 7))) !== 0).sort();
  const eku = extensionValue(x509, "2.5.29.37");
  const serial = x509.serialNumber.length > 2 && x509.serialNumber.startsWith("00") ? x509.serialNumber.slice(2) : x509.serialNumber;
  return {
    raw: base64Of(x509.der),
    version: `v${x509.version}`,
    serialNumber: serial,
    signatureAlgorithm: x509.signatureAlgorithm,
    thumbprint: x509.thumbprint,
    friendlyName: "",
    subject: nameText(x509.subject),
    issuer: nameText(x509.issuer),
    notBefore: seconds(x509.notBefore),
    notAfter: seconds(x509.notAfter),
    hasPrivateKey: onToken ? "true" : "false",
    keyUsage: usage.join(";"),
    enhancedKeyUsage: eku ? children(read(eku)).map((node) => decodeOid(node.value)).join(";") : "",
    privateKeyNotBefore: seconds(x509.privateKeyNotBefore),
    privateKeyNotAfter: seconds(x509.privateKeyNotAfter),
    provider: onToken ? onToken.token.name : "",
    container: onToken ? onToken.container : "",
  };
}

// certificateFields' answer: the asked fields, or all, sorted by name as the core writes them.
function only(fields: Record<string, string>, wanted: unknown): Record<string, string> {
  const names = Array.isArray(wanted) && wanted.length ? wanted.map(String).filter((name) => name in fields) : Object.keys(fields);
  return Object.fromEntries([...new Set(names)].sort().map((name) => [name, fields[name]!]));
}

interface FileInfo {
  content?: unknown;
  path?: unknown;
  contentEncoding?: unknown;
  id?: unknown;
  name?: unknown;
}

// A file's bytes: Base64 content, or text.
function fileBytes(file: FileInfo): Uint8Array {
  if (file.contentEncoding === "base64") return bytesOf(file.content);
  if (typeof file.content === "string") return new TextEncoder().encode(file.content);
  throw new GosError(20009);
}

function parseRequest(data: unknown): Record<string, unknown> {
  if (data && typeof data === "object") return data as Record<string, unknown>;
  try {
    const parsed = JSON.parse(String(data ?? ""));
    if (parsed && typeof parsed === "object") return parsed as Record<string, unknown>;
  } catch {
    // Below.
  }
  throw new GosError(20001);
}

function requestCertificate(request: Record<string, unknown>): X509 {
  const certificate = request.certificate as FileInfo | undefined;
  try {
    return parseCertificate(certificate?.contentEncoding === "base64" || !String(certificate?.content ?? "").includes("-----") ? bytesOf(certificate?.content) : pemToDer(String(certificate?.content)));
  } catch {
    throw new GosError(30045);
  }
}

async function onToken(session: Session, x509: X509): Promise<{ token: Token; certificate: TokenCertificate }> {
  const found = (await tokenCertificates(session)).find(({ certificate }) => certificate.x509.thumbprint === x509.thumbprint);
  if (!found) throw new GosError(30005);
  return found;
}

const keyDigest = (x509: X509): DigestName => (x509.publicKeyAlgorithm === GOST_2012_512 ? "streebog512" : "streebog256");

async function loggedIn<T>(session: Session, deviceId: number, request: PinRequest, work: () => Promise<T>): Promise<T> {
  try {
    return await withLogin(session, deviceId, request, work);
  } catch (error) {
    if (error instanceof CadesError && error.number === SCARD_W_CANCELLED_BY_USER) throw new GosError(20003);
    throw error;
  }
}

const pinRequest = (session: Session, action: string, details: string[], confirm: string): PinRequest => ({
  origin: session.origin,
  action,
  details: ["Запрос сайта к Госплагину.", ...details],
  confirm,
});

const HASHES: Record<string, DigestName> = {
  "1.2.643.7.1.1.2.2": "streebog256",
  "1.2.643.7.1.1.2.3": "streebog512",
  "1.2.643.2.2.9": "gost94",
  md5: "md5",
  sha1: "sha1",
  sha256: "sha256",
  sha384: "sha384",
  sha512: "sha512",
};
const OID_OF: Record<string, string> = { streebog256: "1.2.643.7.1.1.2.2", streebog512: "1.2.643.7.1.1.2.3" };

async function signature(session: Session, data: unknown, v2: boolean, files: (request: Record<string, unknown>) => Promise<FileInfo[]>): Promise<string> {
  const request = parseRequest(data);
  const type = String(request.type ?? "");
  if (!["attached", "detached", "xmldsig"].includes(type)) throw new GosError(30022, type);
  const x509 = requestCertificate(request);
  const { token, certificate } = await onToken(session, x509);
  const list = await files(request);
  if (!list.length) throw new GosError(20006);
  const contents = list.map(fileBytes);
  const plugin = session.plugin;
  const total = contents.reduce((sum, bytes) => sum + bytes.length, 0);
  const kind = type === "xmldsig" ? "подпись XMLDSig" : type === "attached" ? "присоединённая подпись" : "отсоединённая подпись";
  const pin = pinRequest(session, "просит подписать данные.", [`${list.length > 1 ? `${list.length} файла, ` : ""}${sizeText(total)}, ${kind}.`, ...certificateLines(x509)], "Подписать");
  const signatures = await loggedIn(session, token.deviceId, pin, async () => {
    const result: Uint8Array[] = [];
    for (const bytes of contents) {
      if (type === "xmldsig") {
        const keyId = await plugin.getKeyByCertificate(token.deviceId, certificate.certId);
        const name = keyDigest(x509);
        const signed = await signXml(new TextDecoder().decode(bytes), x509, (input) => digest(name, input), async (hash) => {
          const raw = await plugin.rawSign(token.deviceId, keyId, Array.from(hash, (byte) => byte.toString(16).padStart(2, "0")).join(":"), {});
          return Uint8Array.from(raw.split(":"), (pair) => parseInt(pair, 16));
        });
        result.push(new TextEncoder().encode(signed));
      } else {
        const options = { detached: type === "detached", addUserCertificate: true, addEssCert: true, addSignTime: true };
        result.push(bytesOf(await plugin.sign(token.deviceId, certificate.certId, base64Of(bytes), await plugin.DATA_FORMAT_BASE64, options)));
      }
    }
    return result;
  });
  const items = signatures.map((bytes, index) => ({
    id: typeof list[index]!.id === "string" ? list[index]!.id : "",
    name: typeof list[index]!.name === "string" ? list[index]!.name : "",
    path: typeof list[index]!.path === "string" ? list[index]!.path : "",
    content: base64Of(bytes),
    contentEncoding: "base64",
    contentFormat: "",
  }));
  return JSON.stringify(v2 ? { certificate: certificateFields(x509, { token, container: await containerOf(session, token, x509) }), signatures: items } : items);
}

// certificateRequest's key and request: the key "rt1-<uuid>" on the token, the request built in the page as the core
// builds it (src/page/ifc/request.ts): the subject in UTF8String, the asked extensions, the signing tool of the token.
async function certificateRequest(session: Session, data: unknown): Promise<string> {
  const request = parseRequest(data);
  const list = await tokens(session);
  const token = request.provider ? list.find((candidate) => candidate.name === request.provider) : list[0];
  if (!token) throw new GosError(30005);
  const subject = String(request.subject ?? "")
    .split(";")
    .filter(Boolean)
    .map((part) => {
      const equals = part.indexOf("=");
      return { oid: part.slice(0, equals).trim(), type: 12, value: part.slice(equals + 1) };
    });
  if (!subject.length || subject.some((entry) => !/^\d+(\.\d+)+$/.test(entry.oid))) throw new GosError(20001);
  const split = (value: unknown) => String(value ?? "").split(/[;,]/).map((item) => item.trim()).filter(Boolean);
  const paramSet = String(request.publicKeyAlgorithmParamSet ?? "");
  const size: 256 | 512 = paramSet.startsWith("1.2.643.7.1.2.1.2.") ? 512 : 256;
  const paramsets: Record<string, string> = {
    "1.2.643.2.2.35.1": "A",
    "1.2.643.2.2.35.2": "B",
    "1.2.643.2.2.35.3": "C",
    "1.2.643.2.2.36.0": "XA",
    "1.2.643.2.2.36.1": "XB",
    "1.2.643.7.1.2.1.2.1": "A",
    "1.2.643.7.1.2.1.2.2": "B",
    "1.2.643.7.1.2.1.2.3": "C",
  };
  const extensions: Uint8Array[] = [];
  const usage = split(request.keyUsage).map((name) => KEY_USAGE_NAMES.indexOf(name.toLowerCase())).filter((bit) => bit >= 0);
  if (usage.length) extensions.push(keyUsage(usage));
  if (split(request.extendedKeyUsageOids).length) extensions.push(extendedKeyUsage(split(request.extendedKeyUsageOids)));
  if (split(request.certificatePolicies).length) extensions.push(certificatePolicies(split(request.certificatePolicies)));
  extensions.push(signingTool(token.model.replace(/^Rutoken ECP/, "Рутокен ЭЦП")));
  if (/^\d+$/.test(String(request.identificationKind ?? ""))) extensions.push(identificationKind(Number(request.identificationKind)));
  const name = `rt1-${crypto.randomUUID()}`;
  const keyId = Array.from(encodeCp1251(name)!, (byte) => byte.toString(16).padStart(2, "0")).join(":");
  const plugin = session.plugin;
  const owner = subject.find((entry) => entry.oid === "2.5.4.3")?.value ?? "";
  const pin = pinRequest(session, "просит создать на Рутокене ключ и запрос на сертификат.", [`Владелец: ${owner}`, `Ключ: ГОСТ Р 34.10-2012 ${size} бит`, `Рутокен ${token.serial}`], "Создать");
  const der = await loggedIn(session, token.deviceId, pin, async () => {
    await plugin.generateKeyPair(token.deviceId, undefined, "", {
      publicKeyAlgorithm: size === 512 ? await plugin.PUBLIC_KEY_ALGORITHM_GOST3410_2012_512 : await plugin.PUBLIC_KEY_ALGORITHM_GOST3410_2012_256,
      signatureSize: size === 512 ? 1024 : 512,
      keySpec: await plugin.KEY_SPEC_SIGN_AND_EXCHANGE,
      paramset: paramsets[paramSet] ?? (size === 512 ? "A" : "XA"),
      id: keyId,
    });
    const hashType = size === 512 ? await plugin.HASH_TYPE_GOST3411_12_512 : await plugin.HASH_TYPE_GOST3411_12_256;
    const publicKey = requestPublicKey(pemToDer(await plugin.createPkcs10(token.deviceId, keyId, [{ rdn: "commonName", value: "key" }], {}, { hashAlgorithm: hashType })));
    const info = requestInfo(encodeSubject(subject), publicKey, extensions);
    const hash = digest(size === 512 ? "streebog512" : "streebog256", info);
    const raw = await plugin.rawSign(token.deviceId, keyId, Array.from(hash, (byte) => byte.toString(16).padStart(2, "0")).join(":"), {});
    return signedRequest(info, size === 512 ? "1.2.643.7.1.1.3.3" : "1.2.643.7.1.1.3.2", Uint8Array.from(raw.split(":"), (pair) => parseInt(pair, 16)), false);
  });
  const empty = { id: "", name: "", path: "", content: "", contentEncoding: "", contentFormat: "" };
  return JSON.stringify({ container: { ...empty, name, path: name }, request: { ...empty, content: base64Of(der), contentEncoding: "base64" }, exportable: "false" });
}

function pem(der: Uint8Array): string {
  return `-----BEGIN CERTIFICATE-----\n${(base64Of(der).match(/.{1,64}/g) ?? []).join("\n")}\n-----END CERTIFICATE-----\n`;
}

async function storeToken(session: Session, store: unknown): Promise<Token> {
  if (!store) throw new GosError(30013);
  const token = (await tokens(session)).find((candidate) => candidate.name === store);
  if (!token) throw new GosError(30005);
  return token;
}

export type Files = (request: Record<string, unknown>) => Promise<FileInfo[]>;

const defaultFiles: Files = async (request) => (Array.isArray(request.files) ? (request.files as FileInfo[]) : request.file ? [request.file as FileInfo] : []);

// One method of the core: its result, as the string the core puts in method.result.
export async function callCore(context: CoreContext, module: string, method: string, data: unknown, files: Files = defaultFiles): Promise<string> {
  const session = context.session;
  if (module === "system") {
    switch (method) {
      case "handshake":
        return "plugin handshake";
      case "echo":
        return typeof data === "string" ? data : JSON.stringify(data ?? "");
      case "cache":
      case "close":
        return "";
      case "lastError":
        return context.lastError;
      case "config":
        return JSON.stringify(CORE_CONFIG);
      // Made up, as the user and the computer (src/page/identity.ts).
      case "ipConfig":
        return JSON.stringify(ipConfig(await context.identity, context.platform));
    }
  }
  if (["esmart", "jacarta", "rutoken"].includes(module) && method === "test") return module;
  if (module !== "crypto") throw new GosError(20005, method);
  switch (method) {
    case "providers":
      return JSON.stringify((await tokens(session)).map((token) => ({ name: token.name, type: "0", version: "hardware version: 67.4 firmware version: 34.2", token: "true" })));
    case "tokens": {
      const all = await tokenCertificates(session);
      const known = await session.keyIds();
      const result = [];
      for (const token of await tokens(session)) {
        const own = all.filter((entry) => entry.token.deviceId === token.deviceId);
        const certificates = [];
        for (const { certificate } of own) certificates.push(certificateFields(certificate.x509, { token, container: await containerOf(session, token, certificate.x509) }));
        // Every key's container, once a login has listed them; until then, the certificates'.
        const keys = known[token.rawSerial]?.keys;
        const containers = keys?.length ? keys.map(containerName) : certificates.map((fields) => fields.container!);
        result.push({ store: token.name, provider: token.name, label: token.label, serial: token.serial, model: "Rutoken ECP", containers, certificates });
      }
      return JSON.stringify(result);
    }
    case "certificates": {
      const request = data === "" || data === undefined ? {} : parseRequest(data);
      const wanted = (request.fields && typeof request.fields === "object" ? request.fields : {}) as Record<string, unknown>;
      const list = [];
      for (const { token, certificate } of await tokenCertificates(session)) {
        if (!request.store || request.store === token.name) list.push(certificateFields(certificate.x509, { token, container: await containerOf(session, token, certificate.x509) }));
      }
      return JSON.stringify(list.filter((fields) => Object.entries(wanted).every(([name, value]) => String(fields[name] ?? "").toUpperCase() === String(value).toUpperCase())));
    }
    case "certificateFields": {
      const request = parseRequest(data);
      return JSON.stringify(only(certificateFields(requestCertificate(request)), request.fields));
    }
    case "hash": {
      const request = parseRequest(data);
      const [file] = await files({ ...request, files: request.file ? [request.file] : [] });
      if (!file) throw new GosError(20006);
      const algorithm = String(request.algorithm ?? "");
      let name: DigestName | undefined = HASHES[algorithm];
      if (!algorithm) {
        if (!request.certificate) throw new GosError(30015);
        name = keyDigest(requestCertificate(request));
      }
      if (!name) throw new GosError(30008);
      const hash = digest(name, fileBytes(file));
      const gost = name in OID_OF || name === "gost94";
      const token = gost ? (await tokens(session))[0] : undefined;
      return JSON.stringify({ hash: gost ? Array.from(hash, (byte) => byte.toString(16).padStart(2, "0")).join("").toUpperCase() : Array.from(hash, (byte) => byte.toString(16).padStart(2, "0")).join(""), provider: token?.name ?? "", algorithm: OID_OF[name] ?? (algorithm || name) });
    }
    case "signature":
      return signature(session, data, false, files);
    case "signatureV2":
      return signature(session, data, true, files);
    case "certificateRequest":
      return certificateRequest(session, data);
    case "addCertificate": {
      const request = parseRequest(data);
      const x509 = requestCertificate(request);
      const token = await storeToken(session, request.store);
      if ((await tokenCertificates(session)).some(({ certificate }) => certificate.x509.thumbprint === x509.thumbprint)) return "";
      const plugin = session.plugin;
      await loggedIn(session, token.deviceId, pinRequest(session, "просит записать сертификат на Рутокен.", certificateLines(x509), "Записать"), async () => {
        try {
          await plugin.importCertificate(token.deviceId, pem(x509.der), await plugin.CERT_CATEGORY_USER);
        } catch {
          throw new GosError(30005);
        }
      });
      return "";
    }
    case "deleteCertificate": {
      const request = parseRequest(data);
      const x509 = requestCertificate(request);
      const token = await storeToken(session, request.store);
      const found = (await tokenCertificates(session)).find(({ token: other, certificate }) => other.deviceId === token.deviceId && certificate.x509.thumbprint === x509.thumbprint);
      if (!found) throw new GosError(30019);
      const plugin = session.plugin;
      await loggedIn(session, token.deviceId, pinRequest(session, "просит удалить сертификат с Рутокена.", certificateLines(x509), "Удалить"), () => Promise.resolve(plugin.deleteCertificate(token.deviceId, found.certificate.certId)));
      return "true";
    }
    case "normalize": {
      const request = parseRequest(data);
      const algorithm = String(request.algorithm ?? "");
      if (!algorithm) throw new GosError(30015);
      if (algorithm !== SMEV_TRANSFORM) throw new GosError(30008);
      const [file] = await files({ ...request, files: request.file ? [request.file] : [] });
      if (!file) throw new GosError(20006);
      return smevTransform(new TextDecoder().decode(fileBytes(file)));
    }
    case "test":
      return "crypto";
  }
  throw new GosError(20005, method);
}

export function newCoreContext(session: Session, identity: Promise<FakeIdentity> = Promise.resolve(BUILT_IN_IDENTITIES[0]!), platform = ""): CoreContext {
  return { session, lastError: SUCCESS_MESSAGE, identity, platform };
}
