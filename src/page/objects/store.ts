import { constants } from "../constants.ts";
import { CadesError } from "../errors.ts";
import { userCertificates } from "../token.ts";
import { Certificate, Certificates, x509Of } from "./certificate.ts";
import type { Session } from "./session.ts";

// CAdESCOM.Store. The personal store ("My", also what Open() with no arguments opens) and the
// container store both list the user certificates on the connected Rutokens; the demo page drops
// duplicates by thumbprint. "Root" lists the enabled roots of the extension's certificate stores and "CA" its
// enabled intermediates, in any location, as CryptoPro's current-user stores also show the machine's
// (docs/JOURNAL.md). Other stores are empty: the Rutoken Plugin cannot see the OS stores.
// Calls on one store run in the order made, as CryptoPro's queue them: sites read Certificates without awaiting
// Open (the npm crypto-pro library, which lk.roseltorg.ru bundles, and markirovka.crpt.ru's XML signing do).
const E_INVALIDARG = 0x80070057;
const E_ACCESSDENIED = 0x80070005;
const E_NOTIMPL = 0x80004001;
// CAPICOM's, not among cadesplugin_api.js's constants.
const CAPICOM_STORE_OPEN_READ_ONLY = 0;

export class Store {
  readonly #session: Session;
  #items: Certificate[] = [];
  // What Open chose, for Add: the store's name in lower case, and whether it may be written to.
  #opened: { store: string; writable: boolean } | undefined;
  #pending: Promise<unknown> = Promise.resolve();

  constructor(session: Session) {
    this.#session = session;
  }

  #queue<T>(step: () => Promise<T>): Promise<T> {
    const run = this.#pending.then(step);
    this.#pending = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  Open(location: number = constants.CAPICOM_CURRENT_USER_STORE, name: string = constants.CAPICOM_MY_STORE, mode?: number): Promise<void> {
    return this.#queue(async () => {
      const container = Number(location) === constants.CADESCOM_CONTAINER_STORE;
      const store = container ? "my" : String(name).toLowerCase();
      // Without a mode the plug-in lets Add write, as with READ_WRITE (docs/JOURNAL.md, 2026-09-24).
      this.#opened = { store, writable: mode === undefined || Number(mode) !== CAPICOM_STORE_OPEN_READ_ONLY };
      if (store === "my") {
        this.#items = (await userCertificates(this.#session.plugin)).map((token) => new Certificate(this.#session, token));
      } else if (store === "root" || store === "ca") {
        const { roots, intermediates } = await this.#session.storeCertificates();
        this.#items = (store === "root" ? roots : intermediates).map((x509) => new Certificate(this.#session, x509));
      } else {
        this.#items = [];
      }
    });
  }

  Close(): Promise<void> {
    return this.#queue(async () => {
      this.#items = [];
      this.#opened = undefined;
    });
  }

  // Into "Root" or "CA": the certificate goes to the extension's second store, the one of certificates added from
  // files (src/extension/roots.ts); a root only after the user agrees in the extension's window. The errors are
  // plug-in 2.0.15700's (docs/JOURNAL.md, 2026-09-24): not open or not a certificate is E_INVALIDARG, read-only
  // E_ACCESSDENIED, and My, whose certificates are the token's, refuses one without a key with E_INVALIDARG.
  // The other stores are not kept by the extension.
  Add(certificate: unknown): Promise<void> {
    return this.#queue(async () => {
      const x509 = x509Of(certificate);
      if (!this.#opened || !x509) throw new CadesError("The parameter is incorrect.", E_INVALIDARG);
      if (!this.#opened.writable) throw new CadesError("Access is denied.", E_ACCESSDENIED);
      const { store } = this.#opened;
      if (store === "my") throw new CadesError("The parameter is incorrect.", E_INVALIDARG);
      if (store !== "root" && store !== "ca") throw new CadesError(`Добавление в хранилище ${store} не поддерживается расширением`, E_NOTIMPL);
      await this.#session.addCertificate(store, x509);
      if (!this.#items.some((item) => x509Of(item)?.thumbprint === x509.thumbprint)) this.#items.push(new Certificate(this.#session, x509));
    });
  }

  get Certificates(): Promise<Certificates> {
    return this.#queue(async () => new Certificates(this.#items));
  }
}
