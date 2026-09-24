// One signature: the PIN window, login, the Rutoken Plugin's sign(), logout.
import { formatName } from "./dn.ts";
import { CadesError } from "./errors.ts";
import type { Session } from "./objects/session.ts";
import type { SignOptions } from "./rutoken.ts";
import { findDevice, type TokenCertificate } from "./token.ts";
import { SCARD_E_NO_SMARTCARD, withLogin } from "./token-login.ts";

export { SCARD_E_NO_SMARTCARD, SCARD_W_CANCELLED_BY_USER, SCARD_W_CHV_BLOCKED } from "./token-login.ts";

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

function bytes(count: number): string {
  return count < 1024 ? `${count} байт` : `${(count / 1024).toFixed(1)} КБ`;
}

export function certificateLines(x509: TokenCertificate["x509"]): string[] {
  return [`Сертификат: ${commonName(x509.subject)}`, `Выдан: ${commonName(x509.issuer)}, действует до ${x509.notAfter.toLocaleDateString("ru-RU")}`];
}

export async function signWithToken(session: Session, job: SignJob): Promise<string> {
  const deviceId = await findDevice(session.plugin, job.token.serial);
  if (deviceId === undefined) throw new CadesError("Рутокен с этим сертификатом не подключён.", SCARD_E_NO_SMARTCARD);
  const size = Math.floor((job.content.replace(/=+$/, "").length * 3) / 4);
  const what = job.hash ? "Хеш данных" : bytes(size);
  const request = {
    origin: session.origin,
    action: job.hash ? "просит подписать хеш данных." : "просит подписать данные.",
    details: [`${what}, ${job.options.detached ? "отсоединённая" : "присоединённая"} подпись.`, ...certificateLines(job.token.x509)],
    confirm: "Подписать",
  };
  return withLogin(session, deviceId, request, async () => {
    if (job.hash) {
      // The hex form digest() returns, which sign() was checked to take (docs/JOURNAL.md, 2026-09-24).
      const hash = job.content.toLowerCase().replace(/(..)(?!$)/g, "$1:");
      return session.plugin.sign(deviceId, job.token.certId, hash, await session.plugin.DATA_FORMAT_HASH, job.options);
    }
    return session.plugin.sign(deviceId, job.token.certId, job.content, await session.plugin.DATA_FORMAT_BASE64, job.options);
  });
}
