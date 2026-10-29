import { afterEach, describe, expect, it, vi } from "vitest";
import { constants } from "../../src/page/constants.ts";
import { CadesError, getLastError } from "../../src/page/errors.ts";
import type { Certificate, Certificates } from "../../src/page/objects/certificate.ts";
import { createObject } from "../../src/page/objects/index.ts";
import type { Session } from "../../src/page/objects/session.ts";
import type { CadesSignedData } from "../../src/page/objects/signed-data.ts";
import { ucs2leBase64 } from "../../src/page/objects/signed-data.ts";
import type { CPAttribute, CPAttributes, CPSigner } from "../../src/page/objects/signer.ts";
import type { Store } from "../../src/page/objects/store.ts";
import { SCARD_W_CANCELLED_BY_USER, SCARD_W_CHV_BLOCKED } from "../../src/page/signing.ts";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { repoRoot } from "../../scripts/fetch-vendor.ts";
import { children, read } from "../../src/page/asn1.ts";
import { signedAttributes, signedData } from "../../src/page/cms-sign.ts";
import { parseSignedData, signingTime } from "../../src/page/cms.ts";
import { digest } from "../../src/page/gost.ts";
import type { HashedData } from "../../src/page/objects/hashed-data.ts";
import { parseCertificate, pemToDer } from "../../src/page/x509.ts";
import { certId, fakePlugin, FakePinDialog, fakeSession, pem, userPin, type FakePlugin } from "./fakes.ts";

const BES = constants.CADESCOM_CADES_BES | constants.CADES_USE_OCSP_AUTHORIZED_POLICY;

async function tokenCertificate(session: Session): Promise<Certificate> {
  const store = createObject("CAdESCOM.Store", session) as Store;
  await store.Open();
  return (await (store.Certificates as Promise<Certificates>)).Item(1);
}

// What the demo page does in SignCadesBES_Async; its signing time and document name only `withAttributes`, since they
// take the signature off sign() to the CMS made in the page (tested below).
async function signLikeDemoPage(session: Session, content: string, detached = false, type = BES, withAttributes = false) {
  const signer = createObject("CAdESCOM.CPSigner", session) as CPSigner;
  await signer.propset_Certificate(await tokenCertificate(session));
  await signer.propset_CheckCertificate(true);
  if (withAttributes) {
    const attributes = await signer.AuthenticatedAttributes2;
    const time = createObject("CADESCOM.CPAttribute", session) as CPAttribute;
    await time.propset_Name(constants.CAPICOM_AUTHENTICATED_ATTRIBUTE_SIGNING_TIME);
    await time.propset_Value(new Date(Date.UTC(2026, 9, 21, 9, 30, 0)));
    await attributes.Add(time);
    const name = createObject("CADESCOM.CPAttribute", session) as CPAttribute;
    await name.propset_Name(constants.CADESCOM_AUTHENTICATED_ATTRIBUTE_DOCUMENT_NAME);
    await name.propset_Value("Document Name");
    await attributes.Add(name);
  }
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
    await expect(signLikeDemoPage(session, "eA==", false, constants.CADESCOM_CADES_X_LONG_TYPE_1)).rejects.toMatchObject({ number: 0x80004001 });
    const data = createObject("CAdESCOM.CadesSignedData", session) as CadesSignedData;
    await data.propset_Content("x");
    const bare = createObject("CAdESCOM.CPSigner", session) as CPSigner;
    await expect(data.SignCades(bare, BES)).rejects.toMatchObject({ number: 0x80070057 });
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2040-01-01T00:00:00Z"));
    await expect(signLikeDemoPage(session, "eA==")).rejects.toMatchObject({ number: 0x800b0101 });
    expect(plugin.calls.sign).toHaveLength(0);
  });

  // webtools.html: the TSA field's value, empty unless filled in, set before every signature.
  it("keeps the timestamp service address and signs CAdES-BES with it set, without asking it for a timestamp", async () => {
    const { plugin, session } = setup([userPin]);
    const signer = createObject("CAdESCOM.CPSigner", session) as CPSigner;
    expect(await signer.TSAAddress).toBe("");
    await signer.propset_TSAAddress("http://testca2012.cryptopro.ru/tsp/tsp.srf");
    expect(await signer.TSAAddress).toBe("http://testca2012.cryptopro.ru/tsp/tsp.srf");
    await signer.propset_TSAAddress("");
    await signer.propset_Certificate(await tokenCertificate(session));
    const data = createObject("CAdESCOM.CadesSignedData", session) as CadesSignedData;
    await data.propset_Content("x");
    expect(await data.SignCades(signer, BES)).toBe("MIIsignature");
    expect(plugin.calls.sign[0]!.options).toEqual({ detached: false, addUserCertificate: true, addEssCert: true, addSignTime: true });
  });

  // webtools.html with CAdES-T chosen and the TSA field filled in (docs/PLAN.md, action 25).
  it("signs CAdES-T with a timestamp from the TSAAddress service, unchecked, naming the service in the PIN window", async () => {
    const { plugin, dialog, session } = setup([userPin]);
    const signer = createObject("CAdESCOM.CPSigner", session) as CPSigner;
    await signer.propset_Certificate(await tokenCertificate(session));
    await signer.propset_TSAAddress(" http://tsa.example:8080/tsp ");
    const data = createObject("CAdESCOM.CadesSignedData", session) as CadesSignedData;
    await data.propset_Content("x");
    expect(await data.SignCades(signer, constants.CADESCOM_CADES_T | constants.CADES_USE_OCSP_AUTHORIZED_POLICY)).toBe("MIIsignature");
    expect(plugin.calls.sign[0]!.options).toEqual({
      detached: false,
      addUserCertificate: true,
      addEssCert: true,
      addSignTime: true,
      tspOptions: { url: "http://tsa.example:8080/tsp", digestAlg: 5, cert: true, verifyTsToken: false },
    });
    expect(dialog.requests[0]!.details.slice(0, 2)).toEqual(["2 байт, присоединённая подпись со штампом времени.", "Служба штампов времени: tsa.example:8080"]);
  });

  it("refuses CAdES-T without a timestamp service, with CryptoPro's code, and with one the plugin cannot reach, before the PIN", async () => {
    const { plugin, dialog, session } = setup([]);
    const signer = createObject("CAdESCOM.CPSigner", session) as CPSigner;
    await signer.propset_Certificate(await tokenCertificate(session));
    const data = createObject("CAdESCOM.CadesSignedData", session) as CadesSignedData;
    await data.propset_Content("x");
    const error = await data.SignCades(signer, constants.CADESCOM_CADES_T).catch((e: unknown) => e);
    expect(getLastError(error)).toBe("The URL of TSP service is not specified (0xC2100121)");
    for (const address of ["https://tsa.example/tsp", "tsa.example/tsp"]) {
      await signer.propset_TSAAddress(address);
      await expect(data.SignCades(signer, constants.CADESCOM_CADES_T)).rejects.toMatchObject({ number: 0x80070057 });
    }
    expect(dialog.requests).toHaveLength(0);
    expect(plugin.calls.sign).toHaveLength(0);
  });

  it("says which timestamp service failed, and logs out", async () => {
    const plugin = fakePlugin(undefined, {
      sign: async () => {
        throw new Error("192");
      },
    });
    const { session } = setup([userPin], plugin);
    const signer = createObject("CAdESCOM.CPSigner", session) as CPSigner;
    await signer.propset_Certificate(await tokenCertificate(session));
    await signer.propset_TSAAddress("http://tsa.example/tsp");
    const data = createObject("CAdESCOM.CadesSignedData", session) as CadesSignedData;
    await data.propset_Content("x");
    const error = await data.SignCades(signer, constants.CADESCOM_CADES_T).catch((e: unknown) => e);
    expect(getLastError(error)).toBe("Не удалось получить штамп времени от http://tsa.example/tsp: ошибка Рутокен Плагина 192 (0x80004005)");
    expect(plugin.calls.logout).toBe(1);
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

const DOCUMENT_NAME = "1.3.6.1.4.1.311.88.2.1";
const standCa = parseCertificate(pemToDer(readFileSync(join(repoRoot, "tests", "fixtures", "stand-ca.pem"), "utf8")));
const standUser = parseCertificate(pemToDer(pem));

function decoded(signature: string) {
  return parseSignedData(Uint8Array.from(Buffer.from(signature, "base64")));
}

async function signerWith(session: Session, ...attributes: CPAttribute[]): Promise<CPSigner> {
  const signer = createObject("CAdESCOM.CPSigner", session) as CPSigner;
  await signer.propset_Certificate(await tokenCertificate(session));
  for (const attribute of attributes) await (await signer.AuthenticatedAttributes2).Add(attribute);
  return signer;
}

async function attributeOf(session: Session, name: number, value: unknown, encoding?: number, oid?: string): Promise<CPAttribute> {
  const attribute = createObject("CADESCOM.CPAttribute", session) as CPAttribute;
  await attribute.propset_Name(name);
  if (oid) await (await attribute.OID).propset_Value(oid);
  if (encoding !== undefined) await attribute.propset_ValueEncoding(encoding);
  await attribute.propset_Value(value);
  return attribute;
}

describe("signing with the site's attributes (the CMS made in the page)", () => {
  it("signs the attributes' hash with rawSign: the demo page's signing time and document name are in the signature", async () => {
    const plugin = fakePlugin();
    const signed: string[] = [];
    const rawSign = plugin.rawSign;
    plugin.rawSign = async (device, key, data, options) => {
      signed.push(data);
      return rawSign(device, key, data, options);
    };
    const { dialog, session } = setup([userPin], plugin);
    const signature = await signLikeDemoPage(session, "SGVsbG8gV29ybGQ=", false, BES, true);
    expect(plugin.calls.sign).toEqual([]);
    expect(plugin.calls.logout).toBe(1);
    expect(signature).toMatch(/^[A-Za-z0-9+/]+=*$/);
    const cms = decoded(signature);
    expect(Buffer.from(cms.content!).toString()).toBe("Hello World");
    expect(cms.certificates.map((certificate) => certificate.thumbprint)).toEqual([standUser.thumbprint]);
    const info = cms.signers[0]!;
    expect(signingTime(info)).toEqual(new Date(Date.UTC(2026, 9, 21, 9, 30, 0)));
    const name = info.signedAttributes.get(DOCUMENT_NAME)![0]!;
    expect([name.tag, Buffer.from(name.value).toString("utf16le")]).toEqual([0x04, "Document Name\0"]);
    expect(Buffer.from(info.signedAttributes.get("1.2.840.113549.1.9.4")![0]!.value)).toEqual(Buffer.from(digest("streebog256", Buffer.from("Hello World"))));
    // The token signed the hash of exactly these attributes; the fake answers it twice over.
    const hash = Buffer.from(digest("streebog256", info.signedAttributesDer!)).toString("hex");
    expect(signed).toEqual([hash.replace(/(..)(?!$)/g, "$1:")]);
    expect(Buffer.from(info.signature).toString("hex")).toBe(hash + hash);
    expect(dialog.requests[0]!.details[0]).toBe("11 байт, присоединённая подпись.");
  });

  it("takes other attributes by OID with their DER value in Base64, and refuses them as text", async () => {
    const { session } = setup([userPin, userPin]);
    const other = await attributeOf(session, constants.CADESCOM_ATTRIBUTE_OTHER, "DAVIZWxsbw==", constants.CADESCOM_ENCODE_BASE64, "1.2.643.100.113.1");
    expect(await other.Name).toBe(constants.CADESCOM_ATTRIBUTE_OTHER);
    expect(await (await other.OID).Value).toBe("1.2.643.100.113.1");
    const data = createObject("CAdESCOM.CadesSignedData", session) as CadesSignedData;
    await data.propset_Content("x");
    const cms = decoded(await data.SignCades(await signerWith(session, other), constants.CADESCOM_CADES_BES, true));
    const value = cms.signers[0]!.signedAttributes.get("1.2.643.100.113.1")![0]!;
    expect([value.tag, Buffer.from(value.value).toString()]).toEqual([0x0c, "Hello"]);
    expect(cms.content).toBeUndefined();
    const text = await attributeOf(session, constants.CADESCOM_ATTRIBUTE_OTHER, "Hello", undefined, "1.2.643.100.113.1");
    await expect(data.SignCades(await signerWith(session, text), constants.CADESCOM_CADES_BES)).rejects.toMatchObject({ number: 0x80070057 });
    const notDer = await attributeOf(session, constants.CADESCOM_ATTRIBUTE_OTHER, "SGVsbG8=", constants.CADESCOM_ENCODE_BASE64, "1.2.643.100.113.1");
    await expect(data.SignCades(await signerWith(session, notDer), constants.CADESCOM_CADES_BES)).rejects.toMatchObject({ number: 0x80070057 });
    // Naming a known OID names the attribute.
    await (await other.OID).propset_Value(DOCUMENT_NAME);
    expect(await other.Name).toBe(constants.CADESCOM_AUTHENTICATED_ATTRIBUTE_DOCUMENT_NAME);
    await expect(attributeOf(session, 256, "")).rejects.toMatchObject({ number: 0x80004001 });
  });

  it("signs a hash: the message digest is the site's hash, the signature detached", async () => {
    const { plugin, session } = setup([userPin]);
    const hashed = createObject("CAdESCOM.HashedData", session) as HashedData;
    await hashed.propset_Algorithm(constants.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256);
    await hashed.Hash("данные");
    const description = await attributeOf(session, constants.CADESCOM_AUTHENTICATED_ATTRIBUTE_DOCUMENT_DESCRIPTION, "Описание");
    const data = createObject("CAdESCOM.CadesSignedData", session) as CadesSignedData;
    const cms = decoded(await data.SignHash(hashed, await signerWith(session, description), constants.CADESCOM_CADES_BES));
    expect(plugin.calls.sign).toEqual([]);
    expect(cms.content).toBeUndefined();
    const info = cms.signers[0]!;
    expect(Buffer.from(info.signedAttributes.get("1.2.840.113549.1.9.4")![0]!.value).toString("hex").toUpperCase()).toBe(await hashed.Value);
    expect(Buffer.from(info.signedAttributes.get("1.3.6.1.4.1.311.88.2.2")![0]!.value).toString("utf16le")).toBe("Описание\0");
  });

  it("asks for access to the timestamp service before the PIN for CAdES-T, and says when the service fails", async () => {
    const plugin = fakePlugin();
    const dialog = new FakePinDialog([userPin]);
    const tsaAccess: string[] = [];
    const session = fakeSession(plugin, dialog, [], [], { tsaAccess, tsa: async () => Promise.reject(new Error("нет связи")) });
    const signer = await signerWith(session, await attributeOf(session, constants.CADESCOM_AUTHENTICATED_ATTRIBUTE_DOCUMENT_NAME, "Документ"));
    await signer.propset_TSAAddress("https://tsa.example/tsp");
    const data = createObject("CAdESCOM.CadesSignedData", session) as CadesSignedData;
    await data.propset_Content("x");
    const error = await data.SignCades(signer, constants.CADESCOM_CADES_T).catch((e: unknown) => e);
    expect(getLastError(error)).toBe("Не удалось получить штамп времени от https://tsa.example/tsp: нет связи (0x80004005)");
    expect(tsaAccess).toEqual(["https://tsa.example/tsp"]);
    expect(dialog.requests[0]!.details).toContain("Служба штампов времени: tsa.example");
  });
});

describe("the certificate chain in a signature", () => {
  // sign() of the fake makes real CMS here, so that the chain has somewhere to go.
  function chainSetup(roots = [standCa]) {
    const plugin = fakePlugin(undefined, {
      sign: async () => {
        const attributes = signedAttributes({ signer: standUser, messageDigest: new Uint8Array(32), signingTime: new Date(), extra: [] });
        return Buffer.from(signedData({ signer: standUser, signedAttributes: attributes, signature: new Uint8Array(64), certificates: [standUser] })).toString("base64");
      },
    });
    const dialog = new FakePinDialog([userPin, userPin]);
    return { plugin, session: fakeSession(plugin, dialog, roots) };
  }

  async function sign(session: Session, options?: number, attributes: CPAttribute[] = []) {
    const signer = await signerWith(session, ...attributes);
    if (options !== undefined) await signer.propset_Options(options);
    const data = createObject("CAdESCOM.CadesSignedData", session) as CadesSignedData;
    await data.propset_Content("x");
    return decoded(await data.SignCades(signer, constants.CADESCOM_CADES_BES)).certificates.map((certificate) => certificate.thumbprint);
  }

  it("goes to the root of the extension's stores with WHOLE_CHAIN, and stops below it by default, as CryptoPro", async () => {
    const { session } = chainSetup();
    expect(await sign(session, constants.CAPICOM_CERTIFICATE_INCLUDE_WHOLE_CHAIN)).toEqual([standUser.thumbprint, standCa.thumbprint]);
    expect(await sign(session)).toEqual([standUser.thumbprint]);
  });

  it("goes in the CMS made in the page too, and as far as it is found when it reaches no root", async () => {
    const { session } = chainSetup([]);
    const name = await attributeOf(session, constants.CADESCOM_AUTHENTICATED_ATTRIBUTE_DOCUMENT_NAME, "Документ");
    expect(await sign(session, constants.CAPICOM_CERTIFICATE_INCLUDE_WHOLE_CHAIN, [name])).toEqual([standUser.thumbprint]);
    const withRoot = chainSetup();
    const again = await attributeOf(withRoot.session, constants.CADESCOM_AUTHENTICATED_ATTRIBUTE_DOCUMENT_NAME, "Документ");
    expect(await sign(withRoot.session, constants.CAPICOM_CERTIFICATE_INCLUDE_WHOLE_CHAIN, [again])).toEqual([standUser.thumbprint, standCa.thumbprint]);
    expect(await sign(withRoot.session, constants.CAPICOM_CERTIFICATE_INCLUDE_NONE, [again])).toEqual([]);
  });
});

describe("an attribute read from a signature", () => {
  it("gives a document's name as text, and its DER in Base64 when asked", async () => {
    const { CPAttribute } = await import("../../src/page/objects/signer.ts");
    const value = Uint8Array.from([0x04, 18, ...Buffer.from("Договор\0", "utf16le").subarray(0, 16), 0, 0]);
    const name = CPAttribute.fromSignature(DOCUMENT_NAME, value);
    expect([await name.Name, await name.Value]).toEqual([constants.CADESCOM_AUTHENTICATED_ATTRIBUTE_DOCUMENT_NAME, "Договор"]);
    await name.propset_ValueEncoding(constants.CADESCOM_ENCODE_BASE64);
    expect(await name.Value).toBe(Buffer.from(value).toString("base64"));
    // A value that does not parse as its name says comes as Base64 too.
    expect(await CPAttribute.fromSignature(DOCUMENT_NAME, Uint8Array.of(0x30, 0x00)).Value).toBe("MAA=");
  });

  it("gives the signing time and any other attribute as the contents of the value read as UTF-8, as CryptoPro does", async () => {
    const { CPAttribute } = await import("../../src/page/objects/signer.ts");
    const time = CPAttribute.fromSignature("1.2.840.113549.1.9.5", Uint8Array.from([0x17, 13, ...Buffer.from("261028193617Z")]));
    expect([await time.Name, await time.Value]).toEqual([constants.CADESCOM_AUTHENTICATED_ATTRIBUTE_SIGNING_TIME, "261028193617Z"]);
    const other = CPAttribute.fromSignature("1.2.3.4", Uint8Array.of(0x04, 6, 0xef, 0xbb, 0xbf, 0x41, 0xd0, 0x94));
    // A byte order mark stays, "Д" is two bytes of UTF-8.
    expect([await other.Name, await other.Value]).toEqual([constants.CADESCOM_ATTRIBUTE_OTHER, "\uFEFFAД"]);
  });
});
