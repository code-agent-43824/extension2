// CAdESCOM.HashedData and CadesSignedData.SignHash, against the behaviour of CryptoPro's plug-in 2.0.15700
// (docs/JOURNAL.md, 2026-09-24).
import { describe, expect, it } from "vitest";
import { constants } from "../../src/page/constants.ts";
import type { Certificates } from "../../src/page/objects/certificate.ts";
import type { HashedData } from "../../src/page/objects/hashed-data.ts";
import { createObject } from "../../src/page/objects/index.ts";
import type { Session } from "../../src/page/objects/session.ts";
import type { CadesSignedData } from "../../src/page/objects/signed-data.ts";
import type { CPSigner } from "../../src/page/objects/signer.ts";
import type { Store } from "../../src/page/objects/store.ts";
import { certId, fakePlugin, FakePinDialog, fakeSession, userPin } from "./fakes.ts";

const E_INVALIDARG = 0x80070057;
const GOST_256 = constants.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256;
// The fake digest() answers with the hash type, then the hashed bytes (tests/unit/fakes.ts).
const fakeHash = (type: number, bytes: number[]) => [type, ...bytes].map((b) => b.toString(16).padStart(2, "0").toUpperCase()).join("");
const HASH_256 = "B28D48D33F6715C3DC4E9C2B574D26D07FD172FAF00361C29C3B9083546909E0";

function setup(answers: (string | null)[] = [userPin]) {
  const plugin = fakePlugin();
  const dialog = new FakePinDialog(answers);
  return { plugin, dialog, session: fakeSession(plugin, dialog) };
}

function hashed(session: Session): HashedData {
  return createObject("CAdESCOM.HashedData", session) as HashedData;
}

async function signer(session: Session): Promise<CPSigner> {
  const store = createObject("CAdESCOM.Store", session) as Store;
  await store.Open();
  const result = createObject("CAdESCOM.CPSigner", session) as CPSigner;
  await result.propset_Certificate(await (await (store.Certificates as Promise<Certificates>)).Item(1));
  return result;
}

describe("CAdESCOM.HashedData", () => {
  it("starts with GOST R 34.11-94 and UCS2LE, as CryptoPro's plug-in", async () => {
    const { session } = setup();
    const hash = hashed(session);
    expect(await hash.Algorithm).toBe(constants.CADESCOM_HASH_ALGORITHM_CP_GOST_3411);
    expect(await hash.DataEncoding).toBe(constants.CADESCOM_STRING_TO_UCS2LE);
  });

  it("hashes strings as UTF-16LE and pieces as one, with the Rutoken Plugin's digest()", async () => {
    const { plugin, session } = setup();
    const hash = hashed(session);
    await hash.propset_Algorithm(GOST_256);
    await hash.Hash("a");
    await hash.Hash("Ж");
    expect(await hash.Value).toBe(fakeHash(5, [0x61, 0, 0x16, 0x04]));
    expect(plugin.calls.digest).toEqual([{ deviceId: 0, hashType: 5, data: Buffer.from("aЖ", "utf16le").toString("base64"), options: { base64: true } }]);
  });

  it("decodes each Base64 piece separately under BASE64_TO_BINARY", async () => {
    const { session } = setup();
    const hash = hashed(session);
    await hash.propset_Algorithm(GOST_256);
    await hash.propset_DataEncoding(constants.CADESCOM_BASE64_TO_BINARY);
    await hash.Hash("YWI=");
    await hash.Hash("Yw==\r\n");
    expect(await hash.Value).toBe(fakeHash(5, [0x61, 0x62, 0x63]));
    await expect(hash.Hash("!!!")).rejects.toMatchObject({ number: E_INVALIDARG });
  });

  it("ends the hash when Value is read: Value repeats, the next Hash() starts anew", async () => {
    const { plugin, session } = setup();
    const hash = hashed(session);
    await hash.propset_Algorithm(GOST_256);
    await hash.Hash("a");
    const first = await hash.Value;
    expect(await hash.Value).toBe(first);
    await hash.Hash("b");
    expect(await hash.Value).toBe(fakeHash(5, [0x62, 0]));
    expect(plugin.calls.digest).toHaveLength(2);
  });

  it("takes a ready hash in SetHashValue, of the algorithm's size", async () => {
    const { plugin, session } = setup();
    const hash = hashed(session);
    await hash.propset_Algorithm(GOST_256);
    await hash.SetHashValue(HASH_256.toLowerCase());
    expect(await hash.Value).toBe(HASH_256);
    await expect(hash.SetHashValue("abababab")).rejects.toMatchObject({ number: E_INVALIDARG });
    await hash.propset_Algorithm(constants.CADESCOM_HASH_ALGORITHM_SHA1);
    await expect(hash.SetHashValue(HASH_256)).rejects.toMatchObject({ number: E_INVALIDARG });
    expect(plugin.calls.digest).toHaveLength(0);
  });

  it("refuses Value before any data, non-string data and algorithms the plugin lacks", async () => {
    const { session } = setup();
    const hash = hashed(session);
    await expect(hash.Value).rejects.toMatchObject({ number: E_INVALIDARG });
    await expect(hash.Hash(5)).rejects.toMatchObject({ number: E_INVALIDARG });
    await hash.propset_Algorithm(999);
    await expect(hash.Hash("a")).rejects.toMatchObject({ number: E_INVALIDARG });
    await expect(hash.propset_DataEncoding(7)).rejects.toMatchObject({ number: E_INVALIDARG });
  });

  it("needs a connected token, since the hash is computed there", async () => {
    const plugin = fakePlugin(undefined, { enumerateDevices: async () => [] });
    const hash = hashed(fakeSession(plugin, new FakePinDialog([])));
    await hash.propset_Algorithm(GOST_256);
    await hash.Hash("a");
    await expect(hash.Value).rejects.toMatchObject({ number: 0x8010000c });
  });
});

describe("CadesSignedData.SignHash", () => {
  it("signs the hash detached with CAdES-BES attributes, for the PKCS#7 type too", async () => {
    const { plugin, dialog, session } = setup([userPin, userPin]);
    const hash = hashed(session);
    await hash.propset_Algorithm(GOST_256);
    await hash.SetHashValue(HASH_256);
    const sign = await signer(session);
    for (const type of [constants.CADESCOM_CADES_BES, constants.CADESCOM_PKCS7_TYPE]) {
      const data = createObject("CAdESCOM.CadesSignedData", session) as CadesSignedData;
      expect(await data.SignHash(hash, sign, type)).toBe("MIIsignature");
    }
    const colons = HASH_256.toLowerCase().match(/../g)!.join(":");
    const call = { deviceId: 0, certId, data: colons, format: 2, options: { detached: true, addUserCertificate: true, addEssCert: true, addSignTime: true } };
    expect(plugin.calls.sign).toEqual([call, call]);
    expect(dialog.requests[0]).toMatchObject({ action: "просит подписать хеш данных.", details: ["Хеш данных, отсоединённая подпись.", "Сертификат: Stand User", expect.any(String)] });
  });

  it("refuses a hash of another algorithm than the key's, other types and binary output, before the PIN", async () => {
    const { plugin, dialog, session } = setup();
    const sign = await signer(session);
    const data = createObject("CAdESCOM.CadesSignedData", session) as CadesSignedData;
    const hash512 = hashed(session);
    await hash512.propset_Algorithm(constants.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_512);
    await hash512.Hash("a");
    await expect(data.SignHash(hash512, sign, constants.CADESCOM_CADES_BES)).rejects.toMatchObject({ number: E_INVALIDARG });
    const hash = hashed(session);
    await hash.propset_Algorithm(GOST_256);
    await hash.Hash("a");
    await expect(data.SignHash(hash, sign)).rejects.toMatchObject({ number: 0x80004001 });
    await expect(data.SignHash(hash, sign, constants.CADESCOM_CADES_BES, constants.CADESCOM_ENCODE_BINARY)).rejects.toMatchObject({ number: E_INVALIDARG });
    await expect(data.SignHash("hash", sign, constants.CADESCOM_CADES_BES)).rejects.toMatchObject({ number: E_INVALIDARG });
    const unhashed = hashed(session);
    await unhashed.propset_Algorithm(GOST_256);
    await expect(data.SignHash(unhashed, sign, constants.CADESCOM_CADES_BES)).rejects.toMatchObject({ number: E_INVALIDARG });
    expect(plugin.calls.sign).toHaveLength(0);
    expect(dialog.requests).toHaveLength(0);
  });
});
