import { constants } from "../constants.ts";
import { CadesError } from "../errors.ts";
import type { TokenCertificate } from "../token.ts";
import { tokenOf } from "./certificate.ts";

const E_INVALIDARG = 0x80070057;

// CADESCOM.CPAttribute. Kept so sites can build their attribute lists; what reaches the signature
// is decided in CadesSignedData (docs/PLAN.md of stage 4).
export class CPAttribute {
  #name: number = constants.CAPICOM_AUTHENTICATED_ATTRIBUTE_SIGNING_TIME;
  #value: unknown;

  get Name(): Promise<number> {
    return Promise.resolve(this.#name);
  }

  propset_Name(name: number): Promise<void> {
    this.#name = Number(name);
    return Promise.resolve();
  }

  get Value(): Promise<unknown> {
    return Promise.resolve(this.#value);
  }

  propset_Value(value: unknown): Promise<void> {
    this.#value = value;
    return Promise.resolve();
  }
}

// CAdESCOM.CPAttributes, the signer's AuthenticatedAttributes2 collection, indexed from 1.
export class CPAttributes {
  readonly #items: CPAttribute[] = [];

  get Count(): Promise<number> {
    return Promise.resolve(this.#items.length);
  }

  async Add(attribute: CPAttribute): Promise<void> {
    if (!(attribute instanceof CPAttribute)) throw new CadesError("Ожидается объект CADESCOM.CPAttribute", E_INVALIDARG);
    this.#items.push(attribute);
  }

  async Item(index: number): Promise<CPAttribute> {
    const item = this.#items[Number(index) - 1];
    if (!item) throw new CadesError("Неверный индекс атрибута", E_INVALIDARG);
    return item;
  }

  async Remove(index: number): Promise<void> {
    if (!this.#items[Number(index) - 1]) throw new CadesError("Неверный индекс атрибута", E_INVALIDARG);
    this.#items.splice(Number(index) - 1, 1);
  }

  Clear(): Promise<void> {
    this.#items.length = 0;
    return Promise.resolve();
  }
}

// CAdESCOM.CPSigner.
export class CPSigner {
  #certificate: object | undefined;
  #checkCertificate = false;
  #options: number = constants.CAPICOM_CERTIFICATE_INCLUDE_CHAIN_EXCEPT_ROOT;
  readonly #attributes = new CPAttributes();

  get Certificate(): Promise<object | undefined> {
    return Promise.resolve(this.#certificate);
  }

  async propset_Certificate(certificate: object): Promise<void> {
    if (!tokenOf(certificate)) throw new CadesError("Сертификат должен быть получен из хранилища", E_INVALIDARG);
    this.#certificate = certificate;
  }

  get CheckCertificate(): Promise<boolean> {
    return Promise.resolve(this.#checkCertificate);
  }

  propset_CheckCertificate(value: unknown): Promise<void> {
    this.#checkCertificate = Boolean(value);
    return Promise.resolve();
  }

  get Options(): Promise<number> {
    return Promise.resolve(this.#options);
  }

  propset_Options(value: number): Promise<void> {
    this.#options = Number(value);
    return Promise.resolve();
  }

  get AuthenticatedAttributes2(): Promise<CPAttributes> {
    return Promise.resolve(this.#attributes);
  }

  // For CadesSignedData: what the site configured, without going through the async surface.
  settings(): { token: TokenCertificate | undefined; checkCertificate: boolean; options: number } {
    return { token: tokenOf(this.#certificate), checkCertificate: this.#checkCertificate, options: this.#options };
  }
}
