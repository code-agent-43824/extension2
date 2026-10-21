// Logging in to a token through the PIN window, for one operation, and logging out after it.
import { CadesError } from "./errors.ts";
import type { Session } from "./objects/session.ts";
import type { PinRequest } from "./pin-dialog.ts";
import { RutokenError, rutokenErrorCode } from "./rutoken.ts";

// HRESULTs CryptoPro reports for the same situations.
export const SCARD_W_CANCELLED_BY_USER = 0x8010006e;
export const SCARD_W_CHV_BLOCKED = 0x8010006c;
export const SCARD_E_NO_SMARTCARD = 0x8010000c;

// The PINs a page knows, per token serial, for as long as the page lives: given by the site (PrivateKey.KeyPin), or
// remembered after the user ticked "remember" (PrivateKey.CachePin ticks it in advance). Only page.js holds them: the
// login itself still ends with each operation, since a login left open would let any script of the page sign through
// the adapter without our window (docs/PLAN.md, action 35b).
interface PinState {
  given: Map<string, string>;
  remembered: Map<string, string>;
  tick: Set<string>;
}

const pinStates = new WeakMap<Session, PinState>();

function pinState(session: Session): PinState {
  let state = pinStates.get(session);
  if (!state) pinStates.set(session, (state = { given: new Map(), remembered: new Map(), tick: new Set() }));
  return state;
}

// PrivateKey.KeyPin: the PIN for the token's operations from now on; an empty one takes it back.
export function setKeyPin(session: Session, serial: string, pin: string): void {
  if (pin) pinState(session).given.set(serial, pin);
  else pinState(session).given.delete(serial);
}

// PrivateKey.CachePin and CacheKey: true ticks "remember" in advance. CacheKey(false), whose PIN CryptoPro's sample
// says is asked again, also forgets a remembered one; CachePin(false) only unticks, since Честный знак sets it before
// each signature and would undo the user's own choice (docs/JOURNAL.md).
export function setCachePin(session: Session, serial: string, on: boolean, forget = false): void {
  const state = pinState(session);
  if (on) state.tick.add(serial);
  else state.tick.delete(serial);
  if (!on && forget) state.remembered.delete(serial);
}

export function cachePinOf(session: Session, serial: string): boolean {
  return pinState(session).tick.has(serial);
}

const cancelled = () => new CadesError("Действие было отменено пользователем.", SCARD_W_CANCELLED_BY_USER);

// One login attempt: true when logged in, false for a wrong PIN; anything else is thrown.
async function tryLogin(session: Session, deviceId: number, pin: string): Promise<boolean> {
  try {
    await session.plugin.login(deviceId, pin);
    return true;
  } catch (error) {
    const code = rutokenErrorCode(error);
    if (code === RutokenError.ALREADY_LOGGED_IN) return true;
    if (code === RutokenError.PIN_INCORRECT || code === RutokenError.PIN_LENGTH_INVALID) return false;
    if (code === RutokenError.PIN_LOCKED) throw new CadesError("PIN-код Рутокена заблокирован.", SCARD_W_CHV_BLOCKED);
    throw error;
  }
}

// The window stays open until login succeeds, the user cancels or the PIN is locked. A PIN the page has (`keyPin` of
// the signer, the key's KeyPin, a remembered one) only needs the user's yes; a wrong one is forgotten, and the field
// comes back.
async function login(session: Session, deviceId: number, request: PinRequest, keyPin: string | undefined): Promise<void> {
  const state = pinState(session);
  const serial = String(await session.plugin.getDeviceInfo(deviceId, await session.plugin.TOKEN_INFO_SERIAL));
  const remembered = state.remembered.get(serial);
  const given = keyPin || state.given.get(serial);
  const dialog = session.pinDialog(request, remembered !== undefined || state.tick.has(serial));
  try {
    let message: string | undefined;
    const known = given ?? remembered;
    if (known !== undefined) {
      if (!(await dialog.confirm(given ? "PIN-код Рутокена передал сайт." : "PIN-код запомнен до закрытия страницы.", !given))) throw cancelled();
      if (await tryLogin(session, deviceId, known)) {
        if (!given && !dialog.remember) state.remembered.delete(serial);
        return;
      }
      if (given) state.given.delete(serial);
      else state.remembered.delete(serial);
      message = given ? "PIN-код, который передал сайт, не подошёл. Введите PIN-код." : "Запомненный PIN-код не подошёл. Введите PIN-код.";
    }
    for (;;) {
      const pin = await dialog.ask(message);
      if (pin === null) throw cancelled();
      if (await tryLogin(session, deviceId, pin)) {
        if (dialog.remember) state.remembered.set(serial, pin);
        else state.remembered.delete(serial);
        return;
      }
      message = "Неверный PIN-код. Попробуйте ещё раз.";
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
// `keyPin` is the signer's KeyPin, if the site set one.
export function withLogin<T>(session: Session, deviceId: number, request: PinRequest, work: () => Promise<T>, keyPin?: string): Promise<T> {
  const run = async () => {
    await login(session, deviceId, request, keyPin);
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
