import { CadesError, REGDB_E_CLASSNOTREG } from "../errors.ts";
import { About } from "./about.ts";
import { CspInformation } from "./csp-information.ts";
import {
  CertificateRequestPkcs10,
  CspInformations,
  DistinguishedName,
  Enrollment,
  ExtensionEnhancedKeyUsage,
  ExtensionKeyUsage,
  ObjectId,
  ObjectIds,
  PrivateKey,
} from "./enrollment.ts";
import { HashedData } from "./hashed-data.ts";
import { CadesSignedData } from "./signed-data.ts";
import { SignedXML } from "./signed-xml.ts";
import { CPAttribute, CPSigner } from "./signer.ts";
import { Store } from "./store.ts";
import type { Session } from "./session.ts";

type Factory = (session: Session) => object;

// ProgIDs are case-insensitive in COM, and sites rely on it (the demo page asks for "cadescom.cplicense").
const factories = new Map<string, Factory>([
  ["cadescom.about", (session) => new About(session)],
  ["cadescom.cadessigneddata", (session) => new CadesSignedData(session)],
  ["cadescom.cpattribute", () => new CPAttribute()],
  ["cadescom.cpsigner", () => new CPSigner()],
  ["cadescom.hasheddata", (session) => new HashedData(session)],
  ["cadescom.signedxml", (session) => new SignedXML(session)],
  ["cadescom.store", (session) => new Store(session)],
  // The real plug-in also answers to CAPICOM's name for it (checked with 2.0.15700); lkfl2.nalog.ru uses it.
  ["capicom.store", (session) => new Store(session)],
  ["x509enrollment.ccspinformation", () => new CspInformation()],
  ["x509enrollment.ccspinformations", (session) => new CspInformations(session)],
  ["x509enrollment.cobjectid", () => new ObjectId()],
  ["x509enrollment.cobjectids", () => new ObjectIds()],
  ["x509enrollment.cx500distinguishedname", () => new DistinguishedName()],
  ["x509enrollment.cx509certificaterequestpkcs10", (session) => new CertificateRequestPkcs10(session)],
  ["x509enrollment.cx509enrollment", (session) => new Enrollment(session)],
  ["x509enrollment.cx509extensionenhancedkeyusage", () => new ExtensionEnhancedKeyUsage()],
  ["x509enrollment.cx509extensionkeyusage", () => new ExtensionKeyUsage()],
  ["x509enrollment.cx509privatekey", () => new PrivateKey()],
]);

export function createObject(name: string, session: Session): object {
  const factory = factories.get(String(name).toLowerCase());
  if (!factory) throw new CadesError(`Объект ${name} не поддерживается расширением`, REGDB_E_CLASSNOTREG);
  return factory(session);
}
