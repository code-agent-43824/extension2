// One signature: the PIN window, login, the Rutoken Plugin's sign(), logout.
import { formatName } from "./dn.ts";
import { CadesError } from "./errors.ts";
import type { Session } from "./objects/session.ts";
import { rutokenErrorCode, timestampErrors, type SignOptions } from "./rutoken.ts";
import { findDevice, type TokenCertificate } from "./token.ts";
import { SCARD_E_NO_SMARTCARD, withLogin } from "./token-login.ts";

export { SCARD_E_NO_SMARTCARD, SCARD_W_CANCELLED_BY_USER, SCARD_W_CHV_BLOCKED } from "./token-login.ts";

const E_FAIL = 0x80004005;

export interface SignJob {
  token: TokenCertificate;
  // Base64 of the bytes to sign, or with `hash` the hash as hex.
  content: string;
  hash: boolean;
  options: SignOptions;
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

export async function signWithToken(session: Session, job: SignJob): Promise<string> {
  const deviceId = await findDevice(session.plugin, job.token.serial);
  if (deviceId === undefined) throw new CadesError("Рутокен с этим сертификатом не подключён.", SCARD_E_NO_SMARTCARD);
  const size = Math.floor((job.content.replace(/=+$/, "").length * 3) / 4);
  const what = job.hash ? "Хеш данных" : sizeText(size);
  const tsp = job.options.tspOptions;
  const kind = `${job.options.detached ? "отсоединённая" : "присоединённая"} подпись${tsp ? " со штампом времени" : ""}`;
  const request = {
    origin: session.origin,
    action: job.hash ? "просит подписать хеш данных." : "просит подписать данные.",
    // The plugin sends the signature's hash to the timestamp service the site named: the user sees where.
    details: [`${what}, ${kind}.`, ...(tsp ? [`Служба штампов времени: ${new URL(tsp.url).host}`] : []), ...certificateLines(job.token.x509)],
    confirm: "Подписать",
  };
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
  });
}
