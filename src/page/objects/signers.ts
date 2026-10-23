// The signers a verification found, as CryptoPro's plug-in 2.0.15700 reports them after VerifyCades,
// VerifyHash and SignedXML.Verify (docs/JOURNAL.md, 2026-09-24): the certificate, the signing time when
// the signature has one, and whether the signature and the certificate's chain passed; and its signed attributes.
import { CadesError } from "../errors.ts";
import type { X509 } from "../x509.ts";
import { Certificate } from "./certificate.ts";
import type { Session } from "./session.ts";
import { CPAttribute, CPAttributes } from "./signer.ts";

const E_INVALIDARG = 0x80070057;
const CRYPT_E_NOT_FOUND = 0x80092004;

export interface VerifiedSignature {
  certificate: X509;
  signingTime?: Date;
  valid: boolean;
  // The signed attributes in the signature's order, each with its first value as encoded; none for XMLDSig.
  attributes?: { oid: string; value: Uint8Array }[];
}

class SignatureStatus {
  readonly #valid: boolean;

  constructor(valid: boolean) {
    this.#valid = valid;
  }

  get IsValid(): Promise<boolean> {
    return Promise.resolve(this.#valid);
  }
}

// A signer of a verified signature; read-only, unlike the CPSigner a site signs with.
export class VerifiedSigner {
  readonly #session: Session;
  readonly #signature: VerifiedSignature;

  constructor(session: Session, signature: VerifiedSignature) {
    this.#session = session;
    this.#signature = signature;
  }

  get Certificate(): Promise<Certificate> {
    return Promise.resolve(new Certificate(this.#session, this.#signature.certificate));
  }

  // The real plug-in reports it only for a signature that passed.
  get SigningTime(): Promise<string> {
    const time = this.#signature.signingTime;
    if (!time || !this.#signature.valid) return Promise.reject(new CadesError("Cannot find object or property.", CRYPT_E_NOT_FOUND));
    return Promise.resolve(time.toISOString());
  }

  // CAdES-T and later are not verified here, so there is never a signature timestamp.
  get SignatureTimeStampTime(): Promise<never> {
    return Promise.reject(new CadesError("Cannot find object or property.", CRYPT_E_NOT_FOUND));
  }

  // The signature's signed attributes, the CAdES ones among them, as CPAttribute objects.
  get AuthenticatedAttributes2(): Promise<CPAttributes> {
    return Promise.resolve(new CPAttributes((this.#signature.attributes ?? []).map(({ oid, value }) => CPAttribute.fromSignature(oid, value))));
  }

  get SignatureStatus(): Promise<SignatureStatus> {
    return Promise.resolve(new SignatureStatus(this.#signature.valid));
  }
}

// CAdESCOM.Signers, indexed from 1.
export class Signers {
  readonly #items: VerifiedSigner[];

  constructor(session: Session, signatures: readonly VerifiedSignature[]) {
    this.#items = signatures.map((signature) => new VerifiedSigner(session, signature));
  }

  get Count(): Promise<number> {
    return Promise.resolve(this.#items.length);
  }

  async Item(index: number): Promise<VerifiedSigner> {
    const item = this.#items[Number(index) - 1];
    if (!item) throw new CadesError("The parameter is incorrect.", E_INVALIDARG);
    return item;
  }
}
