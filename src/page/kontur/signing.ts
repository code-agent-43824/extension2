// Kontur.Plugin's signatures over the Rutoken Plugin (docs/JOURNAL.md, 2026-11-19): crypto.sign, crypto.batch.sign and
// crypto.signHash with the plugin's sign() where it covers the request (CLAUDE.md), and the CMS of cms-sign.ts around
// rawSign where it does not (no signed attributes, a second signer); crypto.rawSign, the checks and the parsing in
// the page. Every operation with the key asks the PIN in the extension's window (the owner, 2026-11-19).
import { children, encode, expectTag, read } from "../asn1.ts";
import { validationChain } from "../chain.ts";
import { checkSigner, findSignerCertificate, parseSignedData, ATTRIBUTE_MESSAGE_DIGEST, type SignedData } from "../cms.ts";
import { keyDigest, signedAttributes, signerInfo, withCertificates } from "../cms-sign.ts";
import { digest, verifyHash } from "../gost.ts";
import type { PinRequest } from "../pin-dialog.ts";
import { certificateLines, sizeText } from "../signing.ts";
import { findDevice, userCertificates, type TokenCertificate } from "../token.ts";
import { withLogin } from "../token-login.ts";
import { parseCertificate, type X509 } from "../x509.ts";
import type { KonturContext } from "./commands.ts";
import { certificateNotFound, cryptoError, invalidStructure } from "./errors.ts";
import { fromBase64, fromHex, toBase64, wrongHashSize } from "./streams.ts";

const hexColons = (bytes: Uint8Array) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(":");
const bytesOfHex = (hex: string) => Uint8Array.from(hex.split(":"), (pair) => parseInt(pair, 16));

const isObject = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);

// A certificate as a request names it: by its SHA-1 in `hash`, or by its content (a cert.search entry has both).
function referencedThumbprint(reference: unknown): string | undefined {
  if (!isObject(reference)) return undefined;
  const hash = reference.hash;
  if (isObject(hash) && typeof hash.data === "string") {
    return (hash.type === "base64" ? Array.from(fromBase64(hash.data), (b) => b.toString(16).padStart(2, "0")).join("") : hash.data).toUpperCase();
  }
  const content = reference.content;
  if (isObject(content) && typeof content.data === "string") {
    try {
      return parseCertificate(content.type === "hex" ? fromHex(content.data) : fromBase64(content.data)).thumbprint;
    } catch {
      return undefined;
    }
  }
  return undefined;
}

// The certificate a request names, on a connected token: the host's error when it is on none.
export async function tokenCertificate(context: KonturContext, reference: unknown): Promise<TokenCertificate> {
  const thumbprint = referencedThumbprint(reference);
  if (!thumbprint) throw invalidStructure();
  const found = (await userCertificates(context.session.plugin)).find((certificate) => certificate.x509.thumbprint === thumbprint);
  if (!found) throw certificateNotFound();
  return found;
}

// The certificate a request names, wherever it is: its content, or one on a token.
export async function anyCertificate(context: KonturContext, reference: unknown): Promise<X509> {
  if (isObject(reference) && isObject(reference.content) && typeof reference.content.data === "string") {
    try {
      return parseCertificate(reference.content.type === "hex" ? fromHex(reference.content.data) : fromBase64(reference.content.data));
    } catch {
      throw cryptoError(1, "wrong ASN1 value structure");
    }
  }
  return (await tokenCertificate(context, reference)).x509;
}

async function deviceOf(context: KonturContext, token: TokenCertificate): Promise<number> {
  const deviceId = await findDevice(context.session.plugin, token.serial);
  if (deviceId === undefined) throw certificateNotFound();
  return deviceId;
}

function pinRequest(context: KonturContext, action: string, details: string[], token: TokenCertificate, confirm = "Подписать"): PinRequest {
  return { origin: context.session.origin, action, details: ["Запрос сайта к Контур.Плагину.", ...details, ...certificateLines(token.x509)], confirm };
}

export interface SignFlags {
  attached: boolean;
  includeAuthAttributes: boolean;
  includeSignCertificates: boolean;
  includeCertificateChain: boolean;
}

export function signFlags(request: Record<string, unknown>): SignFlags {
  return {
    attached: request.attached === true,
    includeAuthAttributes: request.includeAuthAttributes !== false,
    includeSignCertificates: request.includeSignCertificates !== false,
    includeCertificateChain: request.includeCertificateChain === true,
  };
}

// The issuers of the signer the extension's stores know, for includeCertificateChain.
async function chainOf(context: KonturContext, signer: X509): Promise<X509[]> {
  const stores = await context.session.storeCertificates();
  return validationChain(signer, stores.intermediates, stores.roots).certificates.slice(1);
}

// A SignedData whose one signer signs the content itself, without signed attributes (includeAuthAttributes: false):
// what sign() cannot make. The token signs the content's hash with rawSign.
async function bareSignedData(context: KonturContext, deviceId: number, token: TokenCertificate, content: Uint8Array, flags: SignFlags): Promise<Uint8Array> {
  const plugin = context.session.plugin;
  const signer = token.x509;
  const { name } = keyDigest(signer);
  const keyId = await plugin.getKeyByCertificate(deviceId, token.certId);
  const signature = bytesOfHex(await plugin.rawSign(deviceId, keyId, hexColons(digest(name, content)), {}));
  // signerInfo() puts the signed attributes it is given as [0]; an empty SET is dropped from what it builds below.
  const info = signerInfo({ signer, signedAttributes: new Uint8Array([0x31, 0x00]), signature, certificates: [] });
  const fields = children(read(info)).map((node) => node.der).filter((der) => !(der[0] === 0xa0 && der[1] === 0x00));
  return contentInfo(encode(0x30, ...fields), flags.attached ? content : undefined, flags.includeSignCertificates ? [signer] : []);
}

const DATA = Uint8Array.of(0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01);
const SIGNED_DATA = Uint8Array.of(0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02);

// The ContentInfo of a SignedData with the one SignerInfo given; its digest algorithm is the SignerInfo's.
function contentInfo(info: Uint8Array, content: Uint8Array | undefined, certificates: X509[]): Uint8Array {
  const algorithmDer = children(read(info))[2]!.der;
  const encapsulated = encode(0x30, DATA, ...(content ? [encode(0xa0, encode(0x04, content))] : []));
  const certs = certificates.length ? [encode(0xa0, ...certificates.map((certificate) => certificate.der))] : [];
  const body = encode(0x30, encode(0x02, Uint8Array.of(1)), encode(0x31, algorithmDer), encapsulated, ...certs, encode(0x31, info));
  return encode(0x30, SIGNED_DATA, encode(0xa0, body));
}

// One signature of `content` with the token's key, logged in already.
async function signOnce(context: KonturContext, deviceId: number, token: TokenCertificate, content: Uint8Array, flags: SignFlags): Promise<Uint8Array> {
  let cms: Uint8Array;
  if (!flags.includeAuthAttributes) {
    cms = await bareSignedData(context, deviceId, token, content, flags);
  } else {
    const plugin = context.session.plugin;
    const options = { detached: !flags.attached, addUserCertificate: flags.includeSignCertificates, addEssCert: true, addSignTime: true };
    cms = fromBase64(await plugin.sign(deviceId, token.certId, toBase64(content), await plugin.DATA_FORMAT_BASE64, options));
  }
  return flags.includeCertificateChain ? withCertificates(cms, await chainOf(context, token.x509)) : cms;
}

// crypto.sign and crypto.batch.sign: one PIN window for all the contents.
export async function signContents(context: KonturContext, reference: unknown, contents: Uint8Array[], flags: SignFlags): Promise<Uint8Array[]> {
  const token = await tokenCertificate(context, reference);
  const deviceId = await deviceOf(context, token);
  const size = contents.reduce((sum, content) => sum + content.length, 0);
  const kind = `${flags.attached ? "присоединённая" : "отсоединённая"} подпись`;
  const details = [contents.length > 1 ? `${contents.length} документа, всего ${sizeText(size)}, ${kind}.` : `${sizeText(size)}, ${kind}.`];
  return withLogin(context.session, deviceId, pinRequest(context, "просит подписать данные.", details, token), async () => {
    const result: Uint8Array[] = [];
    for (const content of contents) result.push(await signOnce(context, deviceId, token, content, flags));
    return result;
  });
}

// crypto.signHash: the hash of the key's algorithm from those given, signed by sign() as a detached CAdES-BES.
export async function signHash(context: KonturContext, reference: unknown, hashes: Map<string, Uint8Array>, flags: SignFlags): Promise<Uint8Array> {
  const token = await tokenCertificate(context, reference);
  const { name, oid } = keyDigest(token.x509);
  const hash = hashes.get(oid);
  if (!hash) throw cryptoError(36, "no hash value corresponding to algorithm");
  if (hash.length !== digest(name, new Uint8Array()).length) throw wrongHashSize();
  const deviceId = await deviceOf(context, token);
  return withLogin(context.session, deviceId, pinRequest(context, "просит подписать хеш данных.", ["Хеш данных, отсоединённая подпись."], token), async () => {
    const plugin = context.session.plugin;
    const options = { detached: true, addUserCertificate: flags.includeSignCertificates, addEssCert: true, addSignTime: true };
    const cms = fromBase64(await plugin.sign(deviceId, token.certId, hexColons(hash), await plugin.DATA_FORMAT_HASH, options));
    return flags.includeCertificateChain ? withCertificates(cms, await chainOf(context, token.x509)) : cms;
  });
}

// crypto.rawSign: the host hashes the data with the key's hash and answers the signature s||r with its bytes reversed
// (checked with the stand certificate's key, docs/JOURNAL.md, 2026-11-19), as CryptoPro's RawSignature has it.
export async function rawSign(context: KonturContext, reference: unknown, data: Uint8Array): Promise<Uint8Array> {
  const token = await tokenCertificate(context, reference);
  const deviceId = await deviceOf(context, token);
  const { name } = keyDigest(token.x509);
  return withLogin(context.session, deviceId, pinRequest(context, "просит подписать данные.", [`${sizeText(data.length)}, подпись без CMS.`], token), async () => {
    const plugin = context.session.plugin;
    const keyId = await plugin.getKeyByCertificate(deviceId, token.certId);
    return bytesOfHex(await plugin.rawSign(deviceId, keyId, hexColons(digest(name, data)), {})).reverse();
  });
}

export async function rawVerify(context: KonturContext, reference: unknown, data: Uint8Array, signature: Uint8Array): Promise<boolean> {
  const x509 = await anyCertificate(context, reference);
  let name;
  try {
    name = keyDigest(x509).name;
  } catch {
    return false;
  }
  return verifyHash(x509, digest(name, data), signature.slice().reverse());
}

const wrongMessage = () => cryptoError(32, "wrong pkcs7 message state");

function parsed(cms: Uint8Array): SignedData {
  try {
    return parseSignedData(cms);
  } catch {
    throw wrongMessage();
  }
}

// crypto.verify: the thumbprints of the signers whose signatures check out; none for a detached signature without its
// data. A signer's certificate comes from the signature or from the tokens.
export async function verifySignature(context: KonturContext, cms: Uint8Array, data: Uint8Array | undefined): Promise<string[]> {
  const signed = parsed(cms);
  const content = data ?? signed.content;
  if (!content) return [];
  const pool = [...signed.certificates, ...(await userCertificates(context.session.plugin)).map((certificate) => certificate.x509)];
  const result: string[] = [];
  for (const info of signed.signers) {
    const certificate = findSignerCertificate(info, pool);
    if (!certificate) continue;
    try {
      const { name } = keyDigest(certificate);
      if (checkSigner(info, certificate, digest(name, content)) === "valid") result.push(certificate.thumbprint);
    } catch {
      // A key this check does not know is not a valid signer.
    }
  }
  return result;
}

// crypto.signature.parse: the signature's certificates, as it carries them, and its content.
export function signatureParts(cms: Uint8Array): SignedData {
  return parsed(cms);
}

// crypto.signature.addSigner: one more signer of the same content, with signed attributes, and its certificate added
// again even when the signature has it: the host does so, and its check finds a certificate per signer (checked on the
// stand: our second signer without its own copy did not verify there). A detached signature without its data takes
// the first signer's message digest.
export async function addSigner(context: KonturContext, reference: unknown, cms: Uint8Array, data: Uint8Array | undefined): Promise<Uint8Array> {
  const signed = parsed(cms);
  const token = await tokenCertificate(context, reference);
  const signer = token.x509;
  const { name } = keyDigest(signer);
  const content = data ?? signed.content;
  let messageDigest: Uint8Array;
  if (content) {
    messageDigest = digest(name, content);
  } else {
    const given = signed.signers[0]?.signedAttributes.get(ATTRIBUTE_MESSAGE_DIGEST)?.[0]?.value;
    if (!given) throw wrongMessage();
    messageDigest = given;
  }
  const deviceId = await deviceOf(context, token);
  const info = await withLogin(context.session, deviceId, pinRequest(context, "просит добавить подпись к документу.", ["Ещё одна подпись того же документа."], token), async () => {
    const plugin = context.session.plugin;
    const attributes = signedAttributes({ signer, messageDigest, signingTime: new Date(), extra: [] });
    const keyId = await plugin.getKeyByCertificate(deviceId, token.certId);
    const signature = bytesOfHex(await plugin.rawSign(deviceId, keyId, hexColons(digest(name, attributes)), {}));
    return signerInfo({ signer, signedAttributes: attributes, signature, certificates: [] });
  });
  return withSigner(cms, info, signer);
}

// The SignedData with a SignerInfo, its certificate and its digest algorithm added.
function withSigner(cms: Uint8Array, info: Uint8Array, signer: X509): Uint8Array {
  const [type, explicit] = children(expectTag(read(cms), 0x30, "ContentInfo"));
  const fields = children(expectTag(children(expectTag(explicit, 0xa0, "content"))[0], 0x30, "SignedData"));
  const algorithmDer = children(read(info))[2]!.der;
  const digestAlgorithms = children(fields[1]!).map((node) => node.der);
  const sameBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((byte, i) => byte === b[i]);
  if (!digestAlgorithms.some((der) => sameBytes(der, algorithmDer))) digestAlgorithms.push(algorithmDer);
  const rebuilt: Uint8Array[] = [fields[0]!.der, encode(0x31, ...digestAlgorithms), fields[2]!.der];
  let certificatesDone = false;
  for (const field of fields.slice(3)) {
    if (field.tag === 0xa0) {
      rebuilt.push(encode(0xa0, ...children(field).map((node) => node.der), signer.der));
      certificatesDone = true;
    } else if (field.tag === 0x31) {
      if (!certificatesDone) rebuilt.push(encode(0xa0, signer.der));
      rebuilt.push(encode(0x31, ...children(field).map((node) => node.der), info));
    } else {
      rebuilt.push(field.der);
    }
  }
  return encode(0x30, type!.der, encode(0xa0, encode(0x30, ...rebuilt)));
}

// textualEncoding: the PEM text the host writes, CRLF and the Base64 in one line, no line break at the end.
export function pemText(cms: Uint8Array): Uint8Array {
  return new TextEncoder().encode(`-----BEGIN PKCS7-----\r\n${toBase64(cms)}\r\n-----END PKCS7-----`);
}
