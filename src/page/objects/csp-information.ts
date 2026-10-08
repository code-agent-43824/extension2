import { constants } from "../constants.ts";
import { CadesError } from "../errors.ts";
import { Container, containers, Containers, NTE_BAD_KEYSET } from "./containers.ts";
import type { Session } from "./session.ts";

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

// X509Enrollment.CCspInformation. There is no CSP behind us: no settings; the readers are the connected Rutokens and
// the containers their keys (src/page/objects/containers.ts), listed after each token's PIN. CryptoPro's own containers
// on a Rutoken the Rutoken Plugin cannot see. The demo page creates this before reading the private key usage period
// and skips that part if creation fails.
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

  // By its FQCN (\\.\<reader>\ID_…) or its name alone. Any other name is refused before the PIN: the demo page
  // looks up the certificate's UniqueContainerName (\\.\Rutoken <serial>\<certId>) while showing its card.
  async ContainerByName(name: unknown): Promise<Container> {
    const wanted = String(name ?? "").toLowerCase();
    const notFound = () => new CadesError(`Контейнер ${String(name)} не найден на подключённых Рутокенах`, NTE_BAD_KEYSET);
    if (!/^(\\\\\.\\[^\\]+\\)?id_[^\\]+$/.test(wanted)) throw notFound();
    const found = (await containers(this.#session)).find((container) => container.fqcn().toLowerCase() === wanted || container.name().toLowerCase() === wanted);
    if (!found) throw notFound();
    return found;
  }

  // No key on any token: the code CryptoPro answers without containers, which webtools.html reports as none.
  async EnumContainers(): Promise<Containers> {
    const items = await containers(this.#session);
    if (items.length === 0) throw new CadesError("No more data is available.", ERROR_NO_MORE_ITEMS);
    return new Containers(items);
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
