import { constants } from "../constants.ts";
import { userCertificates } from "../token.ts";
import { Certificate, Certificates } from "./certificate.ts";
import type { Session } from "./session.ts";

// CAdESCOM.Store. The personal store ("My", also what Open() with no arguments opens) and the
// container store both list the user certificates on the connected Rutokens; the demo page drops
// duplicates by thumbprint. "Root" lists the enabled certificates of the extension's root store, in any
// location, as CryptoPro's current-user Root store also shows the machine's (docs/JOURNAL.md). Other stores
// are empty: the Rutoken Plugin cannot see the OS stores.
export class Store {
  readonly #session: Session;
  #items: Certificate[] = [];

  constructor(session: Session) {
    this.#session = session;
  }

  async Open(location: number = constants.CAPICOM_CURRENT_USER_STORE, name: string = constants.CAPICOM_MY_STORE): Promise<void> {
    const store = String(name).toLowerCase();
    if (Number(location) === constants.CADESCOM_CONTAINER_STORE || store === "my") {
      this.#items = (await userCertificates(this.#session.plugin)).map((token) => new Certificate(this.#session, token));
    } else if (store === "root") {
      this.#items = (await this.#session.rootCertificates()).map((x509) => new Certificate(this.#session, x509));
    } else {
      this.#items = [];
    }
  }

  Close(): Promise<void> {
    this.#items = [];
    return Promise.resolve();
  }

  get Certificates(): Promise<Certificates> {
    return Promise.resolve(new Certificates(this.#items));
  }
}
