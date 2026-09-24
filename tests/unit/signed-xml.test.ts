// CAdESCOM.SignedXML up to the XML itself, which needs the browser's DOM: the whole signing runs on the
// stand (tests/stand/xml-signing.spec.ts). Codes as CryptoPro's plug-in 2.0.15700 answers (docs/JOURNAL.md, 2026-09-24).
import { describe, expect, it } from "vitest";
import { constants } from "../../src/page/constants.ts";
import type { Certificates } from "../../src/page/objects/certificate.ts";
import { createObject } from "../../src/page/objects/index.ts";
import type { Session } from "../../src/page/objects/session.ts";
import type { SignedXML, SignedXmlSigners } from "../../src/page/objects/signed-xml.ts";
import type { CPSigner } from "../../src/page/objects/signer.ts";
import type { Store } from "../../src/page/objects/store.ts";
import { fakePlugin, FakePinDialog, fakeSession } from "./fakes.ts";

const E_INVALIDARG = 0x80070057;
const E_NOTIMPL = 0x80004001;

function setup() {
  const plugin = fakePlugin();
  const dialog = new FakePinDialog([]);
  return { plugin, dialog, session: fakeSession(plugin, dialog) };
}

async function signer(session: Session): Promise<CPSigner> {
  const store = createObject("CAdESCOM.Store", session) as Store;
  await store.Open();
  const result = createObject("CAdESCOM.CPSigner", session) as CPSigner;
  await result.propset_Certificate(await (await (store.Certificates as Promise<Certificates>)).Item(1));
  return result;
}

function signedXml(session: Session): SignedXML {
  return createObject("CAdESCOM.SignedXML", session) as SignedXML;
}

describe("CAdESCOM.SignedXML", () => {
  it("keeps Content, and like the real plug-in has write-only type and methods and no Verify yet", async () => {
    const { session } = setup();
    const xml = signedXml(session);
    await xml.propset_Content("<r/>");
    expect(await xml.Content).toBe("<r/>");
    await expect(xml.SignatureType).rejects.toMatchObject({ number: E_NOTIMPL });
    await expect(xml.SignatureMethod).rejects.toMatchObject({ number: E_NOTIMPL });
    await expect(xml.DigestMethod).rejects.toMatchObject({ number: E_NOTIMPL });
    expect(await ((await xml.Signers) as SignedXmlSigners).Count).toBe(0);
    await expect(xml.Verify()).rejects.toMatchObject({ number: E_NOTIMPL });
  });

  it("answers an unknown signature type with an empty string, as the real plug-in", async () => {
    const { session } = setup();
    const xml = signedXml(session);
    await xml.propset_Content("<r/>");
    await xml.propset_SignatureType(7);
    expect(await xml.Sign(await signer(session))).toBe("");
  });

  it("refuses a missing signer, a signature method of another key and unknown methods, before the PIN", async () => {
    const { plugin, dialog, session } = setup();
    const sign = await signer(session);
    const xml = signedXml(session);
    await xml.propset_Content("<r/>");
    await expect(xml.Sign()).rejects.toMatchObject({ number: E_INVALIDARG });
    await xml.propset_SignatureMethod(constants.XmlDsigGost3410Url2012512);
    await expect(xml.Sign(sign)).rejects.toMatchObject({ number: 0x80090008 });
    await xml.propset_SignatureMethod("urn:unknown");
    await expect(xml.Sign(sign)).rejects.toMatchObject({ number: 0x80092004 });
    await xml.propset_SignatureMethod(constants.XmlDsigGost3410Url2012256);
    await xml.propset_DigestMethod("urn:unknown");
    await expect(xml.Sign(sign)).rejects.toMatchObject({ number: 0x80092004 });
    expect(dialog.requests).toHaveLength(0);
    expect(plugin.calls.login).toHaveLength(0);
  });
});
