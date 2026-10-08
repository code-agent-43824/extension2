import { constants } from "../constants.ts";
import { CadesError } from "../errors.ts";
import type { Session } from "./session.ts";

const E_NOTIMPL = 0x80004001;
const E_INVALIDARG = 0x80070057;
// What CryptoPro answers EnumContainers with when there are no containers; webtools.html then says so.
const ERROR_NO_MORE_ITEMS = 0x80070103;
// How often the list of connected tokens is compared while a page listens for tokeninserted.
export const TOKEN_POLL_MS = 2000;

// CAdESCOM's CReaderMode: a connected Rutoken as the reader holding it (docs/PLAN.md, action 24). How
// CryptoPro fills these fields for a Rutoken was not compared.
class ReaderMode {
  readonly #name: string;
  readonly #nickName: string;
  readonly #media: string;

  constructor(name: string, nickName: string, media: string) {
    this.#name = name;
    this.#nickName = nickName;
    this.#media = media;
  }

  get Name(): Promise<string> {
    return Promise.resolve(this.#name);
  }

  get NickName(): Promise<string> {
    return Promise.resolve(this.#nickName);
  }

  get Media(): Promise<string> {
    return Promise.resolve(this.#media);
  }

  // A token is a removable carrier with its own serial number.
  get CarrierFlags(): Promise<number> {
    return Promise.resolve(constants.CARRIER_FLAG_REMOVABLE | constants.CARRIER_FLAG_UNIQUE);
  }
}

// CReaderModes, indexed from 0 as webtools.html reads it.
class ReaderModes {
  readonly #items: ReaderMode[];

  constructor(items: ReaderMode[]) {
    this.#items = items;
  }

  get Count(): Promise<number> {
    return Promise.resolve(this.#items.length);
  }

  async ItemByIndex(index: number): Promise<ReaderMode> {
    const item = this.#items[Number(index)];
    if (!item) throw new CadesError("The parameter is incorrect.", E_INVALIDARG);
    return item;
  }
}

// X509Enrollment.CCspInformation. There is no CSP behind us: no settings and no CryptoPro containers, which
// the Rutoken Plugin cannot see; the readers are the connected Rutokens. The demo page creates it before reading
// the private key usage period and skips that part if creation fails.
export class CspInformation {
  readonly #session: Session;
  readonly #listeners = new Set<() => unknown>();
  #polling = false;

  constructor(session: Session) {
    this.#session = session;
  }

  InitializeFromName(_name: string): Promise<void> {
    return Promise.resolve();
  }

  // Undefined, as in plug-in versions without this property; the page then shows nothing about it.
  get ControlKeyTimeValidity(): Promise<undefined> {
    return Promise.resolve(undefined);
  }

  ContainerByName(name: string): Promise<never> {
    return Promise.reject(new CadesError(`Контейнер ${name} недоступен через Рутокен Плагин`, E_NOTIMPL));
  }

  EnumContainers(): Promise<never> {
    return Promise.reject(new CadesError("No more data is available.", ERROR_NO_MORE_ITEMS));
  }

  // A token that goes away while being read is left out.
  async GetReaderModes(_flags?: number): Promise<ReaderModes> {
    const plugin = this.#session.plugin;
    const [reader, label, model, serial] = await Promise.all([plugin.TOKEN_INFO_READER, plugin.TOKEN_INFO_LABEL, plugin.TOKEN_INFO_MODEL, plugin.TOKEN_INFO_SERIAL]);
    const items: ReaderMode[] = [];
    for (const deviceId of await plugin.enumerateDevices()) {
      try {
        const info = async (option: number) => String(await plugin.getDeviceInfo(deviceId, option));
        items.push(new ReaderMode(await info(reader), await info(label), `${await info(model)} ${await info(serial)}`));
      } catch (error) {
        console.warn(`Рутокен вместо КриптоПро: токен ${deviceId} пропущен`, error);
      }
    }
    return new ReaderModes(items);
  }

  // "tokeninserted": called whenever the set of connected tokens changes, removal included; webtools.html's
  // handler compares the reader lists itself. Other events never come.
  async addEventListener(type: unknown, listener: unknown): Promise<void> {
    if (type !== "tokeninserted" || typeof listener !== "function") return;
    this.#listeners.add(listener as () => unknown);
    this.#poll();
  }

  async removeEventListener(type: unknown, listener: unknown): Promise<void> {
    if (type === "tokeninserted") this.#listeners.delete(listener as () => unknown);
  }

  // The Rutoken Plugin's own tokenMonitor could not be checked to deliver events through the adapter (the fake
  // token on the stand cannot be unplugged), so the device list is compared on a timer while anyone listens.
  #poll(): void {
    if (this.#polling) return;
    this.#polling = true;
    let last: string | undefined;
    const tick = async () => {
      if (this.#listeners.size === 0) {
        this.#polling = false;
        return;
      }
      try {
        const devices = JSON.stringify(await this.#session.plugin.enumerateDevices());
        if (last !== undefined && devices !== last) {
          for (const listener of [...this.#listeners]) {
            try {
              listener();
            } catch (error) {
              console.error(error);
            }
          }
        }
        last = devices;
      } catch {
        // The adapter may be busy or gone; the next tick tries again.
      }
      setTimeout(tick, TOKEN_POLL_MS);
    };
    void tick();
  }
}
