// Kontur.Plugin's certificate issuance (docs/PLAN.md, action 60; docs/JOURNAL.md, 2026-11-19), as its host answers on
// the stand's token: crypto.createCertRequest makes a key on the token named by the container's name (its CKA_ID, a
// UUID unless the site names it) and a PKCS#10 request with the site's subject, extensions and attributes as they
// come; crypto.installCert writes the issued certificate next to its key. CryptoAPI and its stores belong to
// CryptoPro, which the host under Linux does not have: those answer its "CryptoPro module not loaded".
import { encode, encodeOid, read } from "../asn1.ts";
import { parseName } from "../dn.ts";
import { digest } from "../gost.ts";
import { requestPublicKey, signedRequest } from "../ifc/request.ts";
import { RutokenError, rutokenErrorCode } from "../rutoken.ts";
import { certificateLines } from "../signing.ts";
import { userCertificates } from "../token.ts";
import { withLogin } from "../token-login.ts";
import { parseCertificate, pemToDer, type X509 } from "../x509.ts";
import type { KonturContext } from "./commands.ts";
import { cryptoError, invalidStructure, KonturError, pluginError } from "./errors.ts";
import { checkSink, readStream, toBase64, writeStream, type Cache } from "./streams.ts";

const isObject = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
const hexColons = (bytes: Uint8Array) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(":");
const bytesOfHex = (hex: string) => Uint8Array.from(hex.split(":"), (pair) => parseInt(pair, 16));
const seq = (...parts: Uint8Array[]) => encode(0x30, ...parts);
const oid = (dotted: string) => encode(0x06, encodeOid(dotted));

// A token as the provider's slot names it.
export interface SlotToken {
  deviceId: number;
  slot: string;
  serial: string;
}

const SIGNATURE_256 = "1.2.643.7.1.1.3.2";
const SIGNATURE_512 = "1.2.643.7.1.1.3.3";
// The other signature algorithms the host knows (GOST R 34.10-2001 and -94, RSA): the token makes no GOST R 34.10-2001
// key (the host's answer on the stand), and RSA is not done here (the agent's choice: Kontur's CAs issue GOST).
const GOST_2001 = new Set(["1.2.643.2.2.3", "1.2.643.2.2.4"]);
const EXTENSION_REQUEST = "1.2.840.113549.1.9.14";

const notLoaded = (context: string) =>
  new KonturError({ type: "system", code: 0x20002000, context, message: `WIN32[0x20002000]${context} CryptoPro module not loaded` });
const asn1Error = (code: number, text: string) =>
  new KonturError({ type: "asn1", code, context: "", message: `ASN1[0x${code.toString(16).toUpperCase().padStart(8, "0")}] ${text}` });
const noSlot = () => cryptoError(53, "unable to find a token for the specified slot");

// The token of a pkcs11 provider; a CryptoAPI provider's answer, from the host without CryptoPro.
function providerToken(provider: Record<string, unknown>, tokens: SlotToken[]): SlotToken {
  if (provider.type === "cryptoApi") throw notLoaded("CryptAcquireContext");
  if (provider.type !== "pkcs11") throw invalidStructure();
  const token = tokens.find((candidate) => candidate.slot === provider.slot);
  if (!token) throw noSlot();
  return token;
}

const sitePin = (provider: Record<string, unknown>) => (typeof provider.pin === "string" && provider.pin ? provider.pin : undefined);

// The host's container names: 8-4-4-4-12 random hex digits.
function newContainerName(): string {
  const hex = Array.from(crypto.getRandomValues(new Uint8Array(16)), (byte) => byte.toString(16).padStart(2, "0")).join("");
  return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20)].join("-");
}

function commonNameOf(subject: Uint8Array): string {
  return parseName(read(subject)).flat().find((attribute) => attribute.oid === "2.5.4.3")?.value ?? "";
}

// crypto.createCertRequest {cryptoProvider, sink, signatureAlgorithm, subject, extensions, attributes?, publicKey?}:
// subject is a DER Name, extensions the DER that goes into the extension request as it is (the host checks it not),
// attributes DER Attributes after it. The result: {path: "<slot>\<container>", request}.
export async function createCertRequest(context: KonturContext, request: Record<string, unknown>, cache: Cache, tokens: SlotToken[]): Promise<unknown> {
  const provider = request.cryptoProvider;
  if (!isObject(provider)) throw invalidStructure();
  checkSink(request.sink);
  if (request.publicKey !== undefined && !isObject(request.publicKey)) throw invalidStructure();
  const algorithm = request.signatureAlgorithm;
  if (typeof algorithm !== "string") throw invalidStructure();
  if (request.attributes !== undefined && !Array.isArray(request.attributes)) throw invalidStructure();
  const subject = readStream(cache, request.subject);
  const extensions = readStream(cache, request.extensions);
  const attributes = ((request.attributes as unknown[] | undefined) ?? []).map((attribute) => readStream(cache, attribute));
  if (provider.containerName !== undefined && typeof provider.containerName !== "string") throw invalidStructure();
  if (provider.type === "cryptoApi" && (typeof provider.id !== "number" || typeof provider.containerName !== "string")) throw invalidStructure();
  if (algorithm !== SIGNATURE_256 && algorithm !== SIGNATURE_512) {
    if (GOST_2001.has(algorithm)) throw new KonturError({ type: "cryptoki", code: 0x13, context: "C_GenerateKeyPair", message: "CRYPTOKI[0x00000013]C_GenerateKeyPair" });
    throw cryptoError(23, "unknown signature algorithm");
  }
  let owner: string;
  try {
    owner = commonNameOf(subject);
  } catch {
    throw asn1Error(17, "an error occurred while decoding asn.1 value");
  }
  const token = providerToken(provider, tokens);
  const size = algorithm === SIGNATURE_512 ? 512 : 256;
  const name = (provider.containerName as string | undefined) || newContainerName();
  const keyId = hexColons(new TextEncoder().encode(name));
  const plugin = context.session.plugin;
  const pin = {
    origin: context.session.origin,
    action: "просит создать на Рутокене ключ и запрос на сертификат.",
    details: ["Запрос сайта к Контур.Плагину.", ...(owner ? [`Владелец: ${owner}`] : []), `Ключ: ГОСТ Р 34.10-2012 ${size} бит`, `Рутокен ${token.serial}`],
    confirm: "Создать",
  };
  const der = await withLogin(
    context.session,
    token.deviceId,
    pin,
    async () => {
      await plugin.generateKeyPair(token.deviceId, undefined, "", {
        publicKeyAlgorithm: size === 512 ? await plugin.PUBLIC_KEY_ALGORITHM_GOST3410_2012_512 : await plugin.PUBLIC_KEY_ALGORITHM_GOST3410_2012_256,
        signatureSize: size === 512 ? 1024 : 512,
        keySpec: await plugin.KEY_SPEC_SIGN_AND_EXCHANGE,
        // The host's parameters: CryptoPro XchA, TC26's A for 512 bits.
        paramset: size === 512 ? "A" : "XA",
        id: keyId,
      });
      try {
        const hashType = size === 512 ? await plugin.HASH_TYPE_GOST3411_12_512 : await plugin.HASH_TYPE_GOST3411_12_256;
        const publicKey = requestPublicKey(pemToDer(await plugin.createPkcs10(token.deviceId, keyId, [{ rdn: "commonName", value: "key" }], {}, { hashAlgorithm: hashType })));
        const requested = encode(0xa0, seq(oid(EXTENSION_REQUEST), encode(0x31, extensions)), ...attributes);
        const info = seq(encode(0x02, Uint8Array.of(0)), subject, publicKey, requested);
        const hash = digest(size === 512 ? "streebog512" : "streebog256", info);
        const signature = bytesOfHex(await plugin.rawSign(token.deviceId, keyId, hexColons(hash), {}));
        return signedRequest(info, algorithm, signature, false);
      } catch (error) {
        // A key nobody can get a certificate for is only clutter on the token.
        try {
          await plugin.deleteKeyPair(token.deviceId, keyId);
        } catch {
          // The original failure is the answer.
        }
        throw error;
      }
    },
    sitePin(provider),
  );
  return { path: `${token.slot}\\${name}`, request: writeStream(cache, request.sink, der) };
}

// A certificate from data: what is not a SEQUENCE ("AAAA" on the host) and a SEQUENCE that is not a certificate (a
// Name) are the host's two answers.
function certificateOf(bytes: Uint8Array): X509 {
  let tag: number;
  try {
    tag = read(bytes).tag;
  } catch {
    tag = -1;
  }
  if (tag !== 0x30) throw cryptoError(1, "wrong ASN1 value structure");
  try {
    return parseCertificate(bytes);
  } catch {
    throw asn1Error(4, "required collection element not found");
  }
}

const toPem = (der: Uint8Array) => `-----BEGIN CERTIFICATE-----\n${toBase64(der)}\n-----END CERTIFICATE-----\n`;

// crypto.installCert {cryptoProvider, cert: <data>, force?}: onto the token, next to the certificate's key, found by
// the certificate; one already there is left as it is; no key, the host's 203. Nothing is answered.
export async function installCert(context: KonturContext, request: Record<string, unknown>, cache: Cache, tokens: SlotToken[]): Promise<undefined> {
  const provider = request.cryptoProvider;
  if (!isObject(provider)) throw invalidStructure();
  const certificate = certificateOf(readStream(cache, request.cert));
  const token = providerToken(provider, tokens);
  const plugin = context.session.plugin;
  // There already: nothing to write, no PIN to ask.
  if ((await userCertificates(plugin)).some((candidate) => candidate.serial === token.serial && candidate.x509.thumbprint === certificate.thumbprint)) return undefined;
  const pin = {
    origin: context.session.origin,
    action: "просит записать сертификат на Рутокен.",
    details: ["Запрос сайта к Контур.Плагину.", ...certificateLines(certificate), `Рутокен ${token.serial}`],
    confirm: "Записать",
  };
  await withLogin(
    context.session,
    token.deviceId,
    pin,
    async () => {
      let certId: string;
      try {
        certId = await plugin.importCertificate(token.deviceId, toPem(certificate.der), await plugin.CERT_CATEGORY_USER);
      } catch (error) {
        const code = rutokenErrorCode(error);
        if (code === RutokenError.CERTIFICATE_EXISTS) return;
        if (code === RutokenError.KEY_NOT_FOUND) throw pluginError(203, "can not find container corresponding to the certificate");
        throw error;
      }
      try {
        await plugin.getKeyByCertificate(token.deviceId, certId);
      } catch (error) {
        if (rutokenErrorCode(error) !== RutokenError.KEY_NOT_FOUND) throw error;
        await plugin.deleteCertificate(token.deviceId, certId);
        throw pluginError(203, "can not find container corresponding to the certificate");
      }
    },
    sitePin(provider),
  );
  return undefined;
}

// cert.store.install and cert.store.remove {cert: {content} or {hash}, store: {type, name?, location?}}: CryptoAPI's
// stores only, which are empty and cannot be opened without CryptoPro.
export function storeCommand(request: Record<string, unknown>, cache: Cache, install: boolean): never {
  const reference = request.cert;
  const store = request.store;
  if (!isObject(reference) || !isObject(store) || (reference.content === undefined && reference.hash === undefined)) throw invalidStructure();
  if (store.type !== "cryptoApi") throw pluginError(250, "cryptoprovider type unsupported");
  if (reference.content === undefined) throw pluginError(200, "certificate not found");
  certificateOf(readStream(cache, reference.content));
  throw notLoaded(install ? "CertCreateCertificateContext" : "CertOpenStore");
}
