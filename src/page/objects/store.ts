import { constants } from "../constants.ts";
import { userCertificates } from "../token.ts";
import { Certificate, Certificates } from "./certificate.ts";
import type { Session } from "./session.ts";

// CAdESCOM.Store. The personal store ("My", also what Open() with no arguments opens) and the
// container store both list the user certificates on the connected Rutokens; the demo page drops
// duplicates by thumbprint. Other stores are empty: the Rutoken Plugin cannot see the OS stores.
export class Store {
  readonly #session: Session;
  #items: Certificate[] = [];

  constructor(session: Session) {
    this.#session = session;
  }

  async Open(location: number = constants.CAPICOM_CURRENT_USER_STORE, name: string = constants.CAPICOM_MY_STORE): Promise<void> {
    const tokenStore = Number(location) === constants.CADESCOM_CONTAINER_STORE || String(name).toLowerCase() === "my";
    const tokens = tokenStore ? await userCertificates(this.#session.plugin) : [];
    this.#items = tokens.map((token) => new Certificate(this.#session, token));
  }

  Close(): Promise<void> {
    this.#items = [];
    return Promise.resolve();
  }

  get Certificates(): Promise<Certificates> {
    return Promise.resolve(new Certificates(this.#items));
  }
}
