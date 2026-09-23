// Logging in to a token through the PIN window, for one operation, and logging out after it.
import { CadesError } from "./errors.ts";
import type { Session } from "./objects/session.ts";
import type { PinRequest } from "./pin-dialog.ts";
import { RutokenError, rutokenErrorCode } from "./rutoken.ts";

// HRESULTs CryptoPro reports for the same situations.
export const SCARD_W_CANCELLED_BY_USER = 0x8010006e;
export const SCARD_W_CHV_BLOCKED = 0x8010006c;
export const SCARD_E_NO_SMARTCARD = 0x8010000c;

// The PIN window stays open until login succeeds, the user cancels or the PIN is locked.
async function login(session: Session, deviceId: number, request: PinRequest): Promise<void> {
  const dialog = session.pinDialog(request);
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

export async function withLogin<T>(session: Session, deviceId: number, request: PinRequest, work: () => Promise<T>): Promise<T> {
  await login(session, deviceId, request);
  try {
    return await work();
  } finally {
    // Leave no login behind for the page to reuse.
    try {
      await session.plugin.logout(deviceId);
    } catch {
      // The token may have been removed; nothing is left logged in then.
    }
  }
}

// The one connected token, for operations where the site names none (creating a key, writing a
// certificate). With several tokens the user is asked to leave one: guessing could write to the wrong one.
export async function singleDevice(session: Session): Promise<{ deviceId: number; serial: string }> {
  const devices = await session.plugin.enumerateDevices();
  if (devices.length === 0) throw new CadesError("Рутокен не подключён.", SCARD_E_NO_SMARTCARD);
  if (devices.length > 1) throw new CadesError("Подключено несколько Рутокенов: оставьте один.", SCARD_E_NO_SMARTCARD);
  const deviceId = devices[0]!;
  return { deviceId, serial: String(await session.plugin.getDeviceInfo(deviceId, await session.plugin.TOKEN_INFO_SERIAL)) };
}
