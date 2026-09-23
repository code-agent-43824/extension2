import { afterEach, describe, expect, it, vi } from "vitest";
import { constants } from "../../src/page/constants.ts";
import { CadesError } from "../../src/page/errors.ts";
import type { Certificate, Certificates } from "../../src/page/objects/certificate.ts";
import { createObject } from "../../src/page/objects/index.ts";
import type { Session } from "../../src/page/objects/session.ts";
import type { CadesSignedData } from "../../src/page/objects/signed-data.ts";
import { ucs2leBase64 } from "../../src/page/objects/signed-data.ts";
import type { CPAttribute, CPAttributes, CPSigner } from "../../src/page/objects/signer.ts";
import type { Store } from "../../src/page/objects/store.ts";
import { SCARD_W_CANCELLED_BY_USER, SCARD_W_CHV_BLOCKED } from "../../src/page/signing.ts";
import { certId, fakePlugin, FakePinDialog, fakeSession, userPin, type FakePlugin } from "./fakes.ts";

const BES = constants.CADESCOM_CADES_BES | constants.CADES_USE_OCSP_AUTHORIZED_POLICY;

async function tokenCertificate(session: Session): Promise<Certificate> {
  const store = createObject("CAdESCOM.Store", session) as Store;
  await store.Open();
  return (await (store.Certificates as Promise<Certificates>)).Item(1);
}

// What the demo page does in SignCadesBES_Async.
async function signLikeDemoPage(session: Session, content: string, detached = false, type = BES) {
  const signer = createObject("CAdESCOM.CPSigner", session) as CPSigner;
  await signer.propset_Certificate(await tokenCertificate(session));
  await signer.propset_CheckCertificate(true);
  const attributes = await signer.AuthenticatedAttributes2;
  const time = createObject("CADESCOM.CPAttribute", session) as CPAttribute;
  await time.propset_Name(constants.CAPICOM_AUTHENTICATED_ATTRIBUTE_SIGNING_TIME);
  await time.propset_Value(new Date());
  await attributes.Add(time);
  const data = createObject("CAdESCOM.CadesSignedData", session) as CadesSignedData;
  await data.propset_ContentEncoding(constants.CADESCOM_BASE64_TO_BINARY);
  await data.propset_Content(content);
  await signer.propset_Options(constants.CAPICOM_CERTIFICATE_INCLUDE_END_ENTITY_ONLY);
  return data.SignCades(signer, type, detached);
}

function setup(answers: (string | null)[], plugin: FakePlugin = fakePlugin()) {
  const dialog = new FakePinDialog(answers);
  return { plugin, dialog, session: fakeSession(plugin, dialog) };
}

afterEach(() => {
  vi.useRealTimers();
});

describe("signing through the Rutoken Plugin", () => {
  it("asks for the PIN, signs with sign() and logs out", async () => {
    const { plugin, dialog, session } = setup([userPin]);
    expect(await signLikeDemoPage(session, "SGVsbG8gV29ybGQ=", true)).toBe("MIIsignature");
    expect(plugin.calls.login).toEqual([userPin]);
    expect(plugin.calls.sign).toEqual([
      {
        deviceId: 0,
        certId,
        data: "SGVsbG8gV29ybGQ=",
        format: 1,
        options: { detached: true, addUserCertificate: true, addEssCert: true, addSignTime: true },
      },
    ]);
    expect(plugin.calls.logout).toBe(1);
    expect(dialog.requests).toEqual([
      {
        origin: "https://site.example",
        action: "просит подписать данные.",
        details: ["11 байт, отсоединённая подпись.", "Сертификат: Stand User", expect.stringMatching(/^Выдан: Stand Test CA, действует до \d\d\.\d\d\.\d{4}$/)],
        confirm: "Подписать",
      },
    ]);
    expect(dialog.closed).toBe(1);
  });

  it("asks again after a wrong PIN, telling the user why", async () => {
    const { plugin, dialog, session } = setup(["0000", userPin]);
    await signLikeDemoPage(session, "SGVsbG8gV29ybGQ=");
    expect(plugin.calls.login).toEqual(["0000", userPin]);
    expect(dialog.errors).toEqual([undefined, expect.stringContaining("Неверный PIN-код")]);
    expect(plugin.calls.sign).toHaveLength(1);
  });

  it("rejects with CryptoPro's cancelled-by-user code when the user cancels, without signing", async () => {
    const { plugin, dialog, session } = setup([null]);
    const error = await signLikeDemoPage(session, "SGVsbG8gV29ybGQ=").catch((e: unknown) => e);
    expect(error).toBeInstanceOf(CadesError);
    expect((error as CadesError).number).toBe(SCARD_W_CANCELLED_BY_USER);
    expect(plugin.calls.sign).toHaveLength(0);
    expect(dialog.closed).toBe(1);
  });

  it("stops on a locked PIN", async () => {
    const plugin = fakePlugin(undefined, {
      login: async () => {
        throw new Error("18");
      },
    });
    const { session } = setup([userPin], plugin);
    const error = await signLikeDemoPage(session, "SGVsbG8gV29ybGQ=").catch((e: unknown) => e);
    expect((error as CadesError).number).toBe(SCARD_W_CHV_BLOCKED);
  });

  it("logs out even when sign() fails, and passes its error on", async () => {
    const plugin = fakePlugin(undefined, {
      sign: async () => {
        throw new Error("5");
      },
    });
    const { session } = setup([userPin], plugin);
    await expect(signLikeDemoPage(session, "SGVsbG8gV29ybGQ=")).rejects.toThrow("5");
    expect(plugin.calls.logout).toBe(1);
  });

  it("signs a string as UTF-16LE by default, as CryptoPro does", async () => {
    const { plugin, session } = setup([userPin]);
    const signer = createObject("CAdESCOM.CPSigner", session) as CPSigner;
    await signer.propset_Certificate(await tokenCertificate(session));
    const data = createObject("CAdESCOM.CadesSignedData", session) as CadesSignedData;
    await data.propset_Content("Привет");
    await data.SignCades(signer, constants.CADESCOM_CADES_BES);
    expect(Buffer.from(plugin.calls.sign[0]!.data, "base64")).toEqual(Buffer.from("Привет", "utf16le"));
    expect(ucs2leBase64("A")).toBe(Buffer.from("A", "utf16le").toString("base64"));
  });

  it("makes a plain PKCS#7 signature without CAdES attributes and without the certificate when asked", async () => {
    const { plugin, session } = setup([userPin]);
    const signer = createObject("CAdESCOM.CPSigner", session) as CPSigner;
    await signer.propset_Certificate(await tokenCertificate(session));
    await signer.propset_Options(constants.CAPICOM_CERTIFICATE_INCLUDE_NONE);
    const data = createObject("CAdESCOM.CadesSignedData", session) as CadesSignedData;
    await data.propset_Content("x");
    await data.SignCades(signer, constants.CADESCOM_PKCS7_TYPE);
    expect(plugin.calls.sign[0]!.options).toEqual({ detached: false, addUserCertificate: false, addEssCert: false, addSignTime: false });
  });

  it("refuses types it cannot make, a signer without a certificate and, with CheckCertificate, an expired one", async () => {
    const { plugin, session } = setup([userPin, userPin]);
    await expect(signLikeDemoPage(session, "eA==", false, constants.CADESCOM_CADES_T)).rejects.toMatchObject({ number: 0x80004001 });
    const data = createObject("CAdESCOM.CadesSignedData", session) as CadesSignedData;
    await data.propset_Content("x");
    const bare = createObject("CAdESCOM.CPSigner", session) as CPSigner;
    await expect(data.SignCades(bare, BES)).rejects.toMatchObject({ number: 0x80070057 });
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2040-01-01T00:00:00Z"));
    await expect(signLikeDemoPage(session, "eA==")).rejects.toMatchObject({ number: 0x800b0101 });
    expect(plugin.calls.sign).toHaveLength(0);
  });

  it("keeps the attributes a site adds, indexed from 1", async () => {
    const session = fakeSession(fakePlugin());
    const signer = createObject("CAdESCOM.CPSigner", session) as CPSigner;
    const attributes: CPAttributes = await signer.AuthenticatedAttributes2;
    const name = createObject("CADESCOM.CPAttribute", session) as CPAttribute;
    await name.propset_Name(constants.CADESCOM_AUTHENTICATED_ATTRIBUTE_DOCUMENT_NAME);
    await name.propset_Value("Document Name");
    await attributes.Add(name);
    expect(await attributes.Count).toBe(1);
    expect(await (await attributes.Item(1)).Value).toBe("Document Name");
    await expect(attributes.Item(2)).rejects.toBeInstanceOf(CadesError);
    await attributes.Clear();
    expect(await attributes.Count).toBe(0);
  });
});
