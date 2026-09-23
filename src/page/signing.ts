// One signature: the PIN window, login, the Rutoken Plugin's sign(), logout.
import { formatName } from "./dn.ts";
import { CadesError } from "./errors.ts";
import type { Session } from "./objects/session.ts";
import { RutokenError, rutokenErrorCode, type SignOptions } from "./rutoken.ts";
import { findDevice, type TokenCertificate } from "./token.ts";

// HRESULTs CryptoPro reports for the same situations.
export const SCARD_W_CANCELLED_BY_USER = 0x8010006e;
export const SCARD_W_CHV_BLOCKED = 0x8010006c;
export const SCARD_E_NO_SMARTCARD = 0x8010000c;

export interface SignJob {
  token: TokenCertificate;
  // Base64 of the bytes to sign.
  content: string;
  options: SignOptions;
}

function commonName(name: TokenCertificate["x509"]["subject"]): string {
  const cn = name.flat().find((attribute) => attribute.oid === "2.5.4.3");
  return cn?.value ?? formatName(name);
}

// The PIN window stays open until login succeeds, the user cancels or the PIN is locked.
async function login(session: Session, job: SignJob, deviceId: number): Promise<void> {
  const { x509 } = job.token;
  const dialog = session.pinDialog({
    origin: session.origin,
    owner: commonName(x509.subject),
    issuer: commonName(x509.issuer),
    validTo: x509.notAfter,
    dataSize: Math.floor((job.content.replace(/=+$/, "").length * 3) / 4),
    detached: job.options.detached,
  });
  try {
    let message: string | undefined;
    for (;;) {
      const pin = await dialog.ask(message);
      if (pin === null) throw new CadesError("Действие было отменено пользователем.", SCARD_W_CANCELLED_BY_USER);
      try {
        await session.plugin.login(deviceId, pin);
        return;
      } catch (error) {
        const code = rutokenErrorCode(error);
        if (code === RutokenError.ALREADY_LOGGED_IN) return;
        if (code === RutokenError.PIN_INCORRECT || code === RutokenError.PIN_LENGTH_INVALID) {
          message = "Неверный PIN-код. Попробуйте ещё раз.";
          continue;
        }
        if (code === RutokenError.PIN_LOCKED) throw new CadesError("PIN-код Рутокена заблокирован.", SCARD_W_CHV_BLOCKED);
        throw error;
      }
    }
  } finally {
    dialog.close();
  }
}

export async function signWithToken(session: Session, job: SignJob): Promise<string> {
  const deviceId = await findDevice(session.plugin, job.token.serial);
  if (deviceId === undefined) throw new CadesError("Рутокен с этим сертификатом не подключён.", SCARD_E_NO_SMARTCARD);
  await login(session, job, deviceId);
  try {
    const format = await session.plugin.DATA_FORMAT_BASE64;
    return await session.plugin.sign(deviceId, job.token.certId, job.content, format, job.options);
  } finally {
    // Leave no login behind for the page to reuse.
    try {
      await session.plugin.logout(deviceId);
    } catch {
      // The token may have been removed; nothing is left logged in then.
    }
  }
}
