// Kontur.Plugin's encryption (docs/PLAN.md, action 59; docs/JOURNAL.md, 2026-11-19): CMS EnvelopedData with GOST
// 28147-89, the only cipher the host has for PKCS#11 tokens, made as the host makes it on the stand's token: the
// content in CFB mode with CryptoPro's key meshing and parameter set A, the content key wrapped for each recipient as
// a GostR3410-KeyTransport (RFC 4490) on parameter set Z with a key-encryption key diversified on A, the token's
// CKD_CPDIVERSIFY_KDF. The host opens only that: it makes its key-encryption key so whatever the message says. The
// Rutoken Plugin's cmsEncrypt and cmsDecrypt follow RFC 4357 (diversified on Z) and so neither open the host's nor
// make what it opens; here the message is made in the page, without the token or a PIN, and opened with the token's
// VKO (the plugin's derive, after the PIN) and the rest in the page, either way.
import { children, decodeOid, encode, encodeOid, expectTag, octets, read, type Node } from "../asn1.ts";
import { envelopedRecipients, identifies, type CertificateId } from "../cms.ts";
import { parseName } from "../dn.ts";
import { decryptCfb, encryptCfb, newContentKey, PARAM_SET_A, PARAM_SET_Z, parseKeyTransport, unwrapContentKey, wrapContentKey } from "../gost28147.ts";
import { certificateLines, sizeText } from "../signing.ts";
import { findDevice, userCertificates } from "../token.ts";
import { withLogin } from "../token-login.ts";
import type { X509 } from "../x509.ts";
import { names, wanted } from "./certificate.ts";
import type { KonturContext } from "./commands.ts";
import { cryptoError, invalidStructure, KonturError } from "./errors.ts";
import { anyCertificate } from "./signing.ts";
import { fromBase64, writeStream, type Cache } from "./streams.ts";

export const GOST_28147 = "1.2.643.2.2.21";
// GOST R 34.12-2015's ciphers in CMS: the host has no PKCS#11 provider for them.
const GOST_R_3412 = new Set(["1.2.643.7.1.1.5.1.1", "1.2.643.7.1.1.5.1.2", "1.2.643.7.1.1.5.2.1", "1.2.643.7.1.1.5.2.2"]);
const DATA = "1.2.840.113549.1.7.1";
const ENVELOPED_DATA = "1.2.840.113549.1.7.3";

// The host's answer to encryptionAlgorithm: GOST 28147-89 by its OID or by default.
export function checkAlgorithm(algorithm: unknown): void {
  if (algorithm === undefined || algorithm === GOST_28147) return;
  if (typeof algorithm !== "string") throw invalidStructure();
  if (GOST_R_3412.has(algorithm)) throw cryptoError(10, "no suitable crypto provider");
  throw cryptoError(24, "unknown encryption algorithm");
}

const objectId = (oid: string) => encode(0x06, encodeOid(oid));

function serialInteger(x509: X509): Uint8Array {
  return encode(0x02, Uint8Array.from(x509.serialNumber.match(/../g) ?? [], (pair) => parseInt(pair, 16)));
}

// One KeyTransRecipientInfo: the recipient by issuer and serial number, its key's algorithm, the wrapped key.
function recipientInfo(recipient: X509, cek: Uint8Array): Uint8Array {
  return encode(
    0x30,
    encode(0x02, Uint8Array.of(0)),
    encode(0x30, recipient.issuerDer, serialInteger(recipient)),
    recipient.publicKeyAlgorithmDer,
    encode(0x04, wrapContentKey(recipient, cek, PARAM_SET_Z, PARAM_SET_A)),
  );
}

export async function encrypt(context: KonturContext, references: unknown[], content: Uint8Array): Promise<Uint8Array> {
  const recipients: X509[] = [];
  for (const reference of references) recipients.push(await anyCertificate(context, reference));
  const cek = newContentKey();
  const iv = crypto.getRandomValues(new Uint8Array(8));
  let infos: Uint8Array[];
  try {
    infos = recipients.map((recipient) => recipientInfo(recipient, cek));
  } catch {
    throw cryptoError(10, "no suitable crypto provider");
  }
  const algorithm = encode(0x30, objectId(GOST_28147), encode(0x30, encode(0x04, iv), objectId(PARAM_SET_A)));
  const encryptedContent = encode(0x80, encryptCfb(cek, iv, content, PARAM_SET_A));
  const enveloped = encode(0x30, encode(0x02, Uint8Array.of(0)), encode(0x31, ...infos), encode(0x30, objectId(DATA), algorithm, encryptedContent));
  return encode(0x30, objectId(ENVELOPED_DATA), encode(0xa0, enveloped));
}

// The message bytes: Base64 or binary as the host takes them, or the PEM text it writes with textualEncoding.
function messageBytes(bytes: Uint8Array): Uint8Array {
  const text = new TextDecoder("latin1").decode(bytes.subarray(0, 64));
  if (!text.startsWith("-----BEGIN")) return bytes;
  return fromBase64(new TextDecoder().decode(bytes).replace(/-----[^-]+-----/g, ""));
}

interface Enveloped {
  recipients: { id: CertificateId; transport?: Node }[];
  algorithm: string;
  iv?: Uint8Array;
  paramSet?: string;
  content: Uint8Array;
}

function parseEnvelopedData(message: Uint8Array): Enveloped {
  const [type, explicit] = children(expectTag(read(message), 0x30, "ContentInfo"));
  if (decodeOid(expectTag(type, 0x06, "contentType").value) !== ENVELOPED_DATA) throw new Error("CMS: not an EnvelopedData");
  const fields = children(expectTag(children(expectTag(explicit, 0xa0, "content"))[0], 0x30, "EnvelopedData"));
  const ids = envelopedRecipients(message);
  const infos = children(expectTag(fields.find((field) => field.tag === 0x31), 0x31, "recipientInfos"));
  const recipients = ids.map((id, index) => ({ id, transport: infos[index]?.tag === 0x30 ? children(infos[index]!)[3] : undefined }));
  const info = fields.find((field, index) => index > 0 && field.tag === 0x30)!;
  const [, algorithmNode, encrypted] = children(info);
  const [oid, parameters] = children(expectTag(algorithmNode, 0x30, "contentEncryptionAlgorithm"));
  const parts = parameters?.tag === 0x30 ? children(parameters) : [];
  return {
    recipients,
    algorithm: decodeOid(expectTag(oid, 0x06, "algorithm").value),
    iv: parts[0]?.tag === 0x04 ? parts[0].value : undefined,
    paramSet: parts[1]?.tag === 0x06 ? decodeOid(parts[1].value) : undefined,
    content: encrypted ? encryptedContent(encrypted) : new Uint8Array(),
  };
}

// encryptedContent [0] IMPLICIT OCTET STRING: primitive in DER, constructed of OCTET STRINGs in BER.
function encryptedContent(node: Node): Uint8Array {
  if (node.tag === 0x80) return node.value;
  return octets({ ...expectTag(node, 0xa0, "encryptedContent"), tag: 0x24 });
}

const hexColons = (bytes: Uint8Array) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(":");
const bytesOfHex = (hex: string) => Uint8Array.from(hex.split(":"), (pair) => parseInt(pair, 16));

// The host opens anything that is not an EnvelopedData as empty data (it answered "AAAA" so on the stand), and a
// message for no certificate on the tokens with its "certificate not found".
export async function decrypt(context: KonturContext, data: Uint8Array): Promise<Uint8Array> {
  let message: Enveloped;
  try {
    message = parseEnvelopedData(messageBytes(data));
  } catch {
    return new Uint8Array();
  }
  const plugin = context.session.plugin;
  const tokens = await userCertificates(plugin);
  let found;
  for (const recipient of message.recipients) {
    const token = tokens.find((candidate) => identifies(recipient.id, candidate.x509));
    if (token && recipient.transport) {
      found = { token, transport: recipient.transport };
      break;
    }
  }
  if (!found) throw cryptoError(41, "certificate not found");
  if (message.algorithm !== GOST_28147 || !message.iv || !message.paramSet) throw cryptoError(24, "unknown encryption algorithm");
  const { token } = found;
  const deviceId = await findDevice(plugin, token.serial);
  if (deviceId === undefined) throw cryptoError(41, "certificate not found");
  const transport = parseKeyTransport(octets(found.transport));
  const request = {
    origin: context.session.origin,
    action: "просит расшифровать данные.",
    details: ["Запрос сайта к Контур.Плагину.", `Зашифрованное сообщение, ${sizeText(data.length)}.`, ...certificateLines(token.x509)],
    confirm: "Расшифровать",
  };
  const kek = await withLogin(context.session, deviceId, request, async () => {
    const keyId = await plugin.getKeyByCertificate(deviceId, token.certId);
    return bytesOfHex(await plugin.derive(deviceId, keyId, hexColons(transport.ephemeralKey), { ukm: hexColons(transport.ukm) }));
  });
  let cek: Uint8Array;
  try {
    cek = unwrapContentKey(transport, kek);
  } catch {
    throw cryptoError(41, "certificate not found");
  }
  return decryptCfb(cek, message.iv, message.content, message.paramSet);
}

const isObject = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);

// crypto.encryption.parse: properties {recipient: {issuer: true, serialNumber: <a sink>}, encryptedContentInfo:
// {contentEncryptionAlgorithm: true}}; nothing asked, no result (the host's answer).
export function parseEnveloped(cache: Cache, data: Uint8Array, properties: unknown): Record<string, unknown> | undefined {
  if (!isObject(properties)) return undefined;
  const recipient = properties.recipient;
  const info = properties.encryptedContentInfo;
  if (recipient !== undefined && !isObject(recipient)) throw invalidStructure();
  if (isObject(recipient) && recipient.serialNumber !== undefined && !isObject(recipient.serialNumber)) throw invalidStructure();
  if (info !== undefined && !isObject(info)) throw invalidStructure();
  let recipients: CertificateId[];
  let algorithm: string;
  try {
    const message = parseEnvelopedData(messageBytes(data));
    recipients = message.recipients.map((recipient) => recipient.id);
    algorithm = message.algorithm;
  } catch {
    throw new KonturError({ type: "asn1", code: 12, context: "", message: "ASN1[0x0000000C] not enough data for encode ASN1 value" });
  }
  const result: Record<string, unknown> = {};
  if (isObject(info) && info.contentEncryptionAlgorithm === true) result.encryptedContentInfo = { contentEncryptionAlgorithm: { algorithm } };
  if (isObject(recipient)) {
    const asked = wanted(recipient);
    const sink = isObject(recipient.serialNumber) ? recipient.serialNumber : undefined;
    if (asked.has("issuer") || sink) {
      result.recipients = recipients.map((id) => ({
        ...(asked.has("issuer") && id.issuer ? { issuer: names(parseName(read(id.issuer))) } : {}),
        ...(sink && id.serial ? { serialNumber: writeStream(cache, sink, id.serial) } : {}),
      }));
    }
  }
  return Object.keys(result).length ? result : undefined;
}
