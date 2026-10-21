// One signature: the PIN window, login, the Rutoken Plugin's sign(), logout; or, for a signature with the site's own
// signed attributes, the CMS made in the page (src/page/cms-sign.ts) around the token's rawSign.
import { keyDigest, signedAttributes, signedData } from "./cms-sign.ts";
import { formatName } from "./dn.ts";
import { CadesError } from "./errors.ts";
import { digest, type DigestName } from "./gost.ts";
import { bytesBinary } from "./objects/hashed-data.ts";
import type { Session } from "./objects/session.ts";
import { rutokenErrorCode, timestampErrors, type SignOptions } from "./rutoken.ts";
import { findDevice, type TokenCertificate } from "./token.ts";
import { SCARD_E_NO_SMARTCARD, withLogin } from "./token-login.ts";
import { timestampRequest, timestampToken } from "./tsp.ts";
import type { X509 } from "./x509.ts";

export { SCARD_E_NO_SMARTCARD, SCARD_W_CANCELLED_BY_USER, SCARD_W_CHV_BLOCKED } from "./token-login.ts";

const E_FAIL = 0x80004005;

export interface SignJob {
  token: TokenCertificate;
  // Base64 of the bytes to sign, or with `hash` the hash as hex.
  content: string;
  hash: boolean;
  options: SignOptions;
  // The signer's KeyPin.
  keyPin?: string;
}

export function commonName(name: TokenCertificate["x509"]["subject"]): string {
  const cn = name.flat().find((attribute) => attribute.oid === "2.5.4.3");
  return cn?.value ?? formatName(name);
}

// A data size for the PIN window.
export function sizeText(count: number): string {
  return count < 1024 ? `${count} байт` : `${(count / 1024).toFixed(1)} КБ`;
}

export function certificateLines(x509: TokenCertificate["x509"]): string[] {
  return [`Сертификат: ${commonName(x509.subject)}`, `Выдан: ${commonName(x509.issuer)}, действует до ${x509.notAfter.toLocaleDateString("ru-RU")}`];
}

async function deviceOf(session: Session, token: TokenCertificate): Promise<number> {
  const deviceId = await findDevice(session.plugin, token.serial);
  if (deviceId === undefined) throw new CadesError("Рутокен с этим сертификатом не подключён.", SCARD_E_NO_SMARTCARD);
  return deviceId;
}

// What the PIN window says about a signature: of a hash or of `size` bytes, attached or detached; the timestamp
// service gets the signature's hash, so the user sees where it goes.
function signRequest(session: Session, token: TokenCertificate, size: number | undefined, detached: boolean, tsa: string | undefined) {
  const kind = `${detached ? "отсоединённая" : "присоединённая"} подпись${tsa ? " со штампом времени" : ""}`;
  return {
    origin: session.origin,
    action: size === undefined ? "просит подписать хеш данных." : "просит подписать данные.",
    details: [`${size === undefined ? "Хеш данных" : sizeText(size)}, ${kind}.`, ...(tsa ? [`Служба штампов времени: ${new URL(tsa).host}`] : []), ...certificateLines(token.x509)],
    confirm: "Подписать",
  };
}

export async function signWithToken(session: Session, job: SignJob): Promise<string> {
  const deviceId = await deviceOf(session, job.token);
  const size = Math.floor((job.content.replace(/=+$/, "").length * 3) / 4);
  const tsp = job.options.tspOptions;
  const request = signRequest(session, job.token, job.hash ? undefined : size, Boolean(job.options.detached), tsp?.url);
  return withLogin(session, deviceId, request, async () => {
    try {
      if (job.hash) {
        // The hex form digest() returns, which sign() was checked to take (docs/JOURNAL.md, 2026-09-24).
        const hash = job.content.toLowerCase().replace(/(..)(?!$)/g, "$1:");
        return await session.plugin.sign(deviceId, job.token.certId, hash, await session.plugin.DATA_FORMAT_HASH, job.options);
      }
      return await session.plugin.sign(deviceId, job.token.certId, job.content, await session.plugin.DATA_FORMAT_BASE64, job.options);
    } catch (error) {
      const code = rutokenErrorCode(error);
      if (tsp && code !== undefined && timestampErrors.has(code)) {
        throw new CadesError(`Не удалось получить штамп времени от ${tsp.url}: ошибка Рутокен Плагина ${code}`, E_FAIL);
      }
      throw error;
    }
  }, job.keyPin);
}

// A timestamp of `hashed` (made with `hash`) from the service, through the extension (src/page/timestamps.ts), its
// answer checked against the request.
export async function requestTimestamp(session: Session, tsa: URL, hash: DigestName, hashed: Uint8Array): Promise<Uint8Array> {
  const request = timestampRequest(hash, hashed, crypto.getRandomValues(new Uint8Array(8)));
  try {
    return timestampToken(await session.timestamp(tsa.href, request.der), request);
  } catch (error) {
    // A CadesError of the extension carries its code at the end of the message already.
    const reason = (error instanceof Error ? error.message : String(error)).replace(/ \(0x[0-9A-F]{1,8}\)$/, "");
    throw new CadesError(`Не удалось получить штамп времени от ${tsa.href}: ${reason}`, error instanceof CadesError ? error.number : E_FAIL);
  }
}

export interface AssembledJob {
  token: TokenCertificate;
  // The data: signed, and in an attached signature carried; absent when the site gave the hash.
  content?: Uint8Array;
  // The content's hash, when the site gave it (SignHash).
  hash?: Uint8Array;
  detached: boolean;
  // The site's signed attributes, each a DER Attribute.
  attributes: Uint8Array[];
  certificates: X509[];
  // CAdES-T: the service the timestamp comes from, through the extension, as for XAdES-T.
  tsa?: URL;
  keyPin?: string;
}

// A signature with the site's signed attributes, which sign() cannot add: the CMS made in the page, the token signing
// the attributes' hash with rawSign. Base64 in one line, as sign() answers.
export async function signAssembled(session: Session, job: AssembledJob): Promise<string> {
  const deviceId = await deviceOf(session, job.token);
  const signer = job.token.x509;
  const { name } = keyDigest(signer);
  const messageDigest = job.hash ?? digest(name, job.content!);
  // Access to the timestamp service before the PIN: a refusal then costs the user nothing.
  if (job.tsa) await session.timestampAccess(job.tsa.href);
  const request = signRequest(session, job.token, job.hash ? undefined : job.content!.length, job.detached, job.tsa?.href);
  const plugin = session.plugin;
  const { attributes, signature } = await withLogin(
    session,
    deviceId,
    request,
    async () => {
      const attributes = signedAttributes({ signer, messageDigest, signingTime: new Date(), extra: job.attributes });
      const keyId = await plugin.getKeyByCertificate(deviceId, job.token.certId);
      const hash = digest(name, attributes);
      const raw = await plugin.rawSign(deviceId, keyId, Array.from(hash, (byte) => byte.toString(16).padStart(2, "0")).join(":"), {});
      return { attributes, signature: Uint8Array.from(raw.split(":"), (pair) => parseInt(pair, 16)) };
    },
    job.keyPin,
  );
  const timestamp = job.tsa ? await requestTimestamp(session, job.tsa, name, digest(name, signature)) : undefined;
  const cms = signedData({ signer, signedAttributes: attributes, signature, content: job.detached ? undefined : job.content, certificates: job.certificates, timestamp });
  return btoa(bytesBinary(cms));
}
