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

// The operations of a page that log in, chained: each starts once the one before it has logged out.
const queues = new WeakMap<Session, Promise<unknown>>();

// One operation at a time per page, its PIN window included. The Rutoken Plugin's login belongs to the token, not to
// an operation: a second operation's login finds it there (ALREADY_LOGGED_IN), and the first one's logout then ends
// it under the second one, which fails with error 19 — webtools.html lists the containers after the PIN as it loads,
// and a signature started meanwhile did (docs/JOURNAL.md, 2026-10-08).
export function withLogin<T>(session: Session, deviceId: number, request: PinRequest, work: () => Promise<T>): Promise<T> {
  const run = async () => {
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
  };
  const previous = queues.get(session) ?? Promise.resolve();
  const result = previous.then(run, run);
  queues.set(session, result.catch(() => undefined));
  return result;
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
