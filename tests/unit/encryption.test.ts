// CAdESCOM.CPEnvelopedData on the Rutoken Plugin's cmsEncrypt and cmsDecrypt, as webtools.html and CryptoPro's
// decrypt demo call it (docs/PLAN.md, action 24). The CMS itself is the plugin's: the stand checks it end to end.
import { describe, expect, it } from "vitest";
import { constants } from "../../src/page/constants.ts";
import type { Certificate, Certificates } from "../../src/page/objects/certificate.ts";
import type { CPEnvelopedData } from "../../src/page/objects/enveloped-data.ts";
import { createObject } from "../../src/page/objects/index.ts";
import type { Session } from "../../src/page/objects/session.ts";
import type { Store } from "../../src/page/objects/store.ts";
import { parseCertificate, pemToDer } from "../../src/page/x509.ts";
import { fakePlugin, FakePinDialog, fakeSession, pem, userPin, type FakePlugin } from "./fakes.ts";

const E_INVALIDARG = 0x80070057;
const NTE_BAD_DATA = 0x80090005;
const NTE_BAD_ALGID = 0x80090008;
const CRYPT_E_INVALID_MSG_TYPE = 0x80091004;
const CRYPT_E_NO_DECRYPT_CERT = 0x8009200c;
const SCARD_E_NO_SMARTCARD = 0x8010000c;

function setup(answers: (string | null)[] = [userPin], plugin: FakePlugin = fakePlugin()) {
  const dialog = new FakePinDialog(answers);
  return { plugin, dialog, session: fakeSession(plugin, dialog) };
}

function envelopedData(session: Session): CPEnvelopedData {
  return createObject("CAdESCOM.CPEnvelopedData", session) as CPEnvelopedData;
}

async function tokenCertificate(session: Session): Promise<Certificate> {
  const store = createObject("CAdESCOM.Store", session) as Store;
  await store.Open();
  return (await (store.Certificates as Promise<Certificates>)).Item(1);
}

const base64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64");
const text = (value: string) => Buffer.from(value).toString("base64");
const withoutSpace = (value: string) => value.replace(/\s+/g, "");

// Just enough DER (and BER with indefinite lengths, as the Rutoken Plugin writes) to name recipients.
function concat(parts: Uint8Array[]): number[] {
  return parts.flatMap((part) => Array.from(part));
}

function tlv(tag: number, ...parts: Uint8Array[]): Uint8Array {
  const body = concat(parts);
  const length = body.length < 0x80 ? [body.length] : body.length < 0x100 ? [0x81, body.length] : [0x82, body.length >> 8, body.length & 0xff];
  return Uint8Array.from([tag, ...length, ...body]);
}

function indefinite(tag: number, ...parts: Uint8Array[]): Uint8Array {
  return Uint8Array.from([tag, 0x80, ...concat(parts), 0, 0]);
}

const oid = (...bytes: number[]) => tlv(0x06, Uint8Array.from(bytes));
const ENVELOPED_DATA = oid(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x03);
const SIGNED_DATA = oid(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02);
const DATA = oid(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01);
// GOST R 34.10-2012 256 bit, as the key transport algorithm.
const GOST_KEY = tlv(0x30, oid(0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x01, 0x01));
const integer = (value: number) => tlv(0x02, Uint8Array.of(value));

const user = parseCertificate(pemToDer(pem));

function issuerAndSerial(serialHex = user.serialNumber): Uint8Array {
  return tlv(0x30, user.issuerDer, tlv(0x02, Uint8Array.from(Buffer.from(serialHex, "hex"))));
}

function keyTransport(rid: Uint8Array): Uint8Array {
  return tlv(0x30, integer(0), rid, GOST_KEY, tlv(0x04, new Uint8Array(32)));
}

function keyAgreement(rid: Uint8Array): Uint8Array {
  return tlv(0xa1, integer(3), tlv(0xa0, tlv(0x80, new Uint8Array(8))), GOST_KEY, tlv(0x30, tlv(0x30, rid, tlv(0x04, new Uint8Array(32)))));
}

function message(type: Uint8Array, ...recipients: Uint8Array[]): Uint8Array {
  const content = tlv(0x30, DATA, tlv(0x30, DATA), tlv(0x80, new Uint8Array(16)));
  return indefinite(0x30, type, indefinite(0xa0, indefinite(0x30, integer(0), tlv(0x31, ...recipients), content)));
}

const forUser = message(ENVELOPED_DATA, keyTransport(issuerAndSerial()));

describe("CAdESCOM.CPEnvelopedData encryption", () => {
  it("encrypts like webtools.html, after the PIN of the recipient's token, with the chosen GOST cipher", async () => {
    const { plugin, dialog, session } = setup();
    const data = envelopedData(session);
    const algorithm = await data.Algorithm;
    expect(await algorithm.Name).toBe(constants.CADESCOM_ENCRYPTION_ALGORITHM_GOST_28147_89);
    await algorithm.propset_Name(constants.CADESCOM_ENCRYPTION_ALGORITHM_GOST_KUZNYECHIK);
    const recipients = await data.Recipients;
    await recipients.Add(await tokenCertificate(session));
    expect(await recipients.Count).toBe(1);

    expect(await data.StreamEncrypt(text("hello"), true)).toBe("MIAGCSqGSIb3DQEHA6CAenveloped\nAAAA\n");
    expect(plugin.calls.cmsEncrypt).toEqual([{ deviceId: 0, recipients: [expect.any(String)], data: text("hello"), options: { base64: true, cipherAlgorithm: 256 } }]);
    expect(withoutSpace(plugin.calls.cmsEncrypt[0]!.recipients[0]!)).toBe(withoutSpace(pem));
    expect(plugin.calls.logout).toBe(1);
    expect(dialog.requests).toEqual([
      {
        origin: "https://site.example",
        action: "просит зашифровать данные.",
        details: ["5 байт, «Кузнечик».", "Получатель: Stand User", "Рутокен Плагин шифрует только после ввода PIN-кода токена."],
        confirm: "Зашифровать",
      },
    ]);
  });

  it("maps CryptoPro's GOST algorithms to the Rutoken Plugin's ciphers", async () => {
    const expected = new Map([
      [constants.CADESCOM_ENCRYPTION_ALGORITHM_GOST_28147_89, 32],
      [constants.CADESCOM_ENCRYPTION_ALGORITHM_GOST_MAGMA, 64],
      [constants.CADESCOM_ENCRYPTION_ALGORITHM_GOST_MAGMA_OMAC, 128],
      [constants.CADESCOM_ENCRYPTION_ALGORITHM_GOST_KUZNYECHIK, 256],
      [constants.CADESCOM_ENCRYPTION_ALGORITHM_GOST_KUZNYECHIK_OMAC, 512],
    ]);
    const { plugin, session } = setup([...expected.keys()].map(() => userPin));
    for (const name of expected.keys()) {
      const data = envelopedData(session);
      await (await data.Algorithm).propset_Name(name);
      await (await data.Recipients).Add(await tokenCertificate(session));
      await data.StreamEncrypt(text("x"), true);
    }
    expect(plugin.calls.cmsEncrypt.map((call) => call.options.cipherAlgorithm)).toEqual([...expected.values()]);
  });

  it("gathers StreamEncrypt's pieces until the last one; Encrypt takes Content as ContentEncoding says", async () => {
    const { plugin, session } = setup([userPin, userPin, userPin]);
    const data = envelopedData(session);
    await (await data.Recipients).Add(await tokenCertificate(session));
    expect(await data.StreamEncrypt(text("ab"), false)).toBe("");
    expect(plugin.calls.login).toEqual([]);
    await data.StreamEncrypt(text("cd"), true);
    await data.propset_Content("Привет");
    await data.Encrypt();
    await data.propset_ContentEncoding(constants.CADESCOM_BASE64_TO_BINARY);
    await data.propset_Content(text("binary"));
    await data.Encrypt(constants.CADESCOM_ENCODE_BASE64);
    expect(plugin.calls.cmsEncrypt.map((call) => call.data)).toEqual([text("abcd"), Buffer.from("Привет", "utf16le").toString("base64"), text("binary")]);
    await expect(data.Encrypt(constants.CADESCOM_ENCODE_BINARY)).rejects.toMatchObject({ number: E_INVALIDARG });
  });

  it("refuses without a recipient, without data and with an algorithm that is not GOST, before the PIN", async () => {
    const { plugin, dialog, session } = setup();
    const data = envelopedData(session);
    await expect(data.StreamEncrypt(text("x"), true)).rejects.toMatchObject({ number: E_INVALIDARG });
    const recipients = await data.Recipients;
    await expect(recipients.Add("not a certificate")).rejects.toMatchObject({ number: E_INVALIDARG });
    await recipients.Add(await tokenCertificate(session));
    await expect(data.Encrypt()).rejects.toMatchObject({ number: E_INVALIDARG });
    await (await data.Algorithm).propset_Name(constants.CADESCOM_ENCRYPTION_ALGORITHM_AES);
    await expect(data.StreamEncrypt(text("x"), true)).rejects.toMatchObject({ number: NTE_BAD_ALGID });
    expect(dialog.requests).toEqual([]);
    expect(plugin.calls.login).toEqual([]);
    await recipients.Remove(1);
    expect(await recipients.Count).toBe(0);
  });

  it("encrypts for a certificate from a file on the only connected token, and asks to leave one of several", async () => {
    const { plugin, session } = setup();
    const certificate = createObject("CAdESCOM.Certificate", session) as Certificate;
    await certificate.Import(pem);
    const data = envelopedData(session);
    await (await data.Recipients).Add(certificate);
    await data.StreamEncrypt(text("x"), true);
    expect(plugin.calls.cmsEncrypt[0]!.deviceId).toBe(0);

    const two = setup([], fakePlugin(undefined, { enumerateDevices: async () => [0, 1] }));
    const other = envelopedData(two.session);
    await (await other.Recipients).Add(certificate);
    await expect(other.StreamEncrypt(text("x"), true)).rejects.toMatchObject({ number: SCARD_E_NO_SMARTCARD });
  });
});

describe("CAdESCOM.CPEnvelopedData decryption", () => {
  it("decrypts a message for the token's certificate after its PIN, giving Content as ContentEncoding says", async () => {
    const { plugin, dialog, session } = setup([userPin, userPin]);
    const data = envelopedData(session);
    await data.propset_ContentEncoding(constants.CADESCOM_BASE64_TO_BINARY);
    await data.Decrypt(base64(forUser));
    expect(await data.Content).toBe("0J/RgNC40LLQtdGC");
    expect(plugin.calls.cmsDecrypt).toEqual([{ deviceId: 0, keyId: "ke:y1", cms: base64(forUser), options: { base64: true } }]);
    expect(plugin.calls.logout).toBe(1);
    expect(dialog.requests[0]).toEqual({
      origin: "https://site.example",
      action: "просит расшифровать данные.",
      details: [`Зашифрованное сообщение, ${forUser.length} байт.`, "Сертификат: Stand User", expect.stringMatching(/^Выдан: Stand Test CA, действует до /)],
      confirm: "Расшифровать",
    });

    const utf16 = setup([userPin], fakePlugin(undefined, { cmsDecrypt: async () => Buffer.from("Привет", "utf16le").toString("base64") }));
    const strings = envelopedData(utf16.session);
    await strings.Decrypt(base64(forUser));
    expect(await strings.Content).toBe("Привет");
  });

  it("StreamDecrypt decrypts a whole message without isFinal, as webtools.html passes it, and one given in pieces", async () => {
    const { plugin, session } = setup([userPin, userPin]);
    const data = envelopedData(session);
    await data.propset_ContentEncoding(constants.CADESCOM_BASE64_TO_BINARY);
    expect(await data.StreamDecrypt(base64(forUser))).toBe("0J/RgNC40LLQtdGC");
    expect(await data.StreamDecrypt(base64(forUser.subarray(0, 40)), false)).toBe("");
    expect(await data.StreamDecrypt(base64(forUser.subarray(40)), false)).toBe("0J/RgNC40LLQtdGC");
    expect(plugin.calls.cmsDecrypt.map((call) => call.cms)).toEqual([base64(forUser), base64(forUser)]);
    await expect(data.StreamDecrypt(base64(forUser.subarray(0, 40)), true)).rejects.toMatchObject({ number: CRYPT_E_INVALID_MSG_TYPE });
  });

  it("finds the token's certificate among key agreement recipients and next to other recipients", async () => {
    const { plugin, session } = setup([userPin, userPin]);
    const data = envelopedData(session);
    await data.Decrypt(base64(message(ENVELOPED_DATA, keyAgreement(issuerAndSerial()))));
    await data.Decrypt(base64(message(ENVELOPED_DATA, keyTransport(tlv(0x80, Uint8Array.of(1, 2, 3))), keyTransport(issuerAndSerial()))));
    expect(plugin.calls.cmsDecrypt).toHaveLength(2);
  });

  it("refuses what is not an encrypted message, and one for nobody on the token, before the PIN", async () => {
    const { plugin, dialog, session } = setup();
    const data = envelopedData(session);
    await expect(data.Decrypt(base64(message(SIGNED_DATA, keyTransport(issuerAndSerial()))))).rejects.toMatchObject({ number: CRYPT_E_INVALID_MSG_TYPE });
    await expect(data.StreamDecrypt(text("MIAGCSqGSIb3DQEHA6CA"))).rejects.toMatchObject({ number: CRYPT_E_INVALID_MSG_TYPE });
    await expect(data.Decrypt("not base64!")).rejects.toMatchObject({ number: E_INVALIDARG });
    const forOther = message(ENVELOPED_DATA, keyTransport(issuerAndSerial("01")), keyAgreement(tlv(0xa0, tlv(0x04, Uint8Array.of(9)))));
    await expect(data.Decrypt(base64(forOther))).rejects.toMatchObject({ number: CRYPT_E_NO_DECRYPT_CERT });
    expect(dialog.requests).toEqual([]);
    expect(plugin.calls.login).toEqual([]);
  });

  it("reports the Rutoken Plugin's failure with its code, logged out after it", async () => {
    const { plugin, session } = setup([userPin], fakePlugin(undefined, { cmsDecrypt: async () => Promise.reject(new Error("147")) }));
    const data = envelopedData(session);
    await expect(data.Decrypt(base64(forUser))).rejects.toMatchObject({ number: NTE_BAD_DATA, message: expect.stringContaining("ошибка 147") });
    expect(plugin.calls.logout).toBe(1);
  });
});
