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
const HASH_256 = "B28D48D33F6715C3DC4E9C2B574D26D07FD172FAF00361C29C3B9083546909E0";

// Value for "abc" and "" (as UTF-16LE) by algorithm, as CryptoPro's plug-in 2.0.15700 answered (docs/JOURNAL.md).
const cryptopro: [number, string, string][] = [
  [constants.CADESCOM_HASH_ALGORITHM_CP_GOST_3411, "2CB07926EBD3C4DC0092DA7301E169AD1323068849FC6A4423CF7C4CEAAB298A", "981E5F3CA30C841487830F84FB433E13AC1101569B9C13584AC483234CD656C0"],
  [GOST_256, HASH_256, "3F539A213E97C802CC229D474C6AA32A825A360B2A933A949FD925208D9CE1BB"],
  [
    constants.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_512,
    "6F6FD77B4AB83D7E3B0754634B3B56626B03FA643609B293BC54B480F6CF34C8632DE2E4F0FD1A948D8AC43AD9C66984234A124D259B3BBD8705C9034DC97E52",
    "8E945DA209AA869F0455928529BCAE4679E9873AB707B55315F56CEB98BEF0A7362F715528356EE83CDA5F2AAC4C6AD2BA3A715C1BCD81CB8E9F90BF4C1C1A8A",
  ],
  [constants.CADESCOM_HASH_ALGORITHM_MD5, "CE1473CF80C6B3FDA8E3DFC006ADC315", "D41D8CD98F00B204E9800998ECF8427E"],
  [constants.CADESCOM_HASH_ALGORITHM_SHA1, "9F04F41A848514162050E3D68C1A7ABB441DC2B5", "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"],
  [constants.CADESCOM_HASH_ALGORITHM_SHA_256, "13E228567E8249FCE53337F25D7970DE3BD68AB2653424C7B8F9FD05E33CAEDF", "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"],
  [
    constants.CADESCOM_HASH_ALGORITHM_SHA_384,
    "9B7CE7C7AF46E400A37C8099CB4BBB5D0408061DD74CDB5DAC7661BED1E53724BD07F299E265F400802A48D2E0B2092C",
    "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B",
  ],
  [
    constants.CADESCOM_HASH_ALGORITHM_SHA_512,
    "ADD8B8154DF7A734D2947A981F4E61C5366710D610040E5B54894D1006E89283CBA082287ED5DD4C25CDAA5AF56D24AB9FBEDC56897130B0B5F3E50C7F9EE6DF",
    "CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E",
  ],
];

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

  it("hashes strings as UTF-16LE in the page, with the values of CryptoPro's plug-in and no token", async () => {
    const plugin = fakePlugin(undefined, { enumerateDevices: async () => [] });
    const session = fakeSession(plugin, new FakePinDialog([]));
    for (const [algorithm, abc, empty] of cryptopro) {
      const hash = hashed(session);
      await hash.propset_Algorithm(algorithm);
      await hash.Hash("a");
      await hash.Hash("bc");
      expect(await hash.Value).toBe(abc);
      await hash.Hash("");
      expect(await hash.Value).toBe(empty);
    }
  });

  it("decodes each Base64 piece separately under BASE64_TO_BINARY", async () => {
    const { session } = setup();
    const hash = hashed(session);
    await hash.propset_Algorithm(GOST_256);
    await hash.propset_DataEncoding(constants.CADESCOM_BASE64_TO_BINARY);
    await hash.Hash("YWI=");
    await hash.Hash("Yw==\r\n");
    // Streebog-256 of the bytes "abc".
    expect(await hash.Value).toBe("4E2919CF137ED41EC4FB6270C61826CC4FFFB660341E0AF3688CD0626D23B481");
    await expect(hash.Hash("!!!")).rejects.toMatchObject({ number: E_INVALIDARG });
  });

  it("ends the hash when Value is read: Value repeats, the next Hash() starts anew", async () => {
    const { session } = setup();
    const hash = hashed(session);
    await hash.propset_Algorithm(GOST_256);
    await hash.Hash("abc");
    expect(await hash.Value).toBe(HASH_256);
    expect(await hash.Value).toBe(HASH_256);
    await hash.Hash("a");
    await hash.Hash("bc");
    expect(await hash.Value).toBe(HASH_256);
  });

  it("takes a ready hash in SetHashValue, of the algorithm's size", async () => {
    const { session } = setup();
    const hash = hashed(session);
    await hash.propset_Algorithm(GOST_256);
    await hash.SetHashValue(HASH_256.toLowerCase());
    expect(await hash.Value).toBe(HASH_256);
    await expect(hash.SetHashValue("abababab")).rejects.toMatchObject({ number: E_INVALIDARG });
    await hash.propset_Algorithm(constants.CADESCOM_HASH_ALGORITHM_SHA1);
    await expect(hash.SetHashValue(HASH_256)).rejects.toMatchObject({ number: E_INVALIDARG });
  });

  it("refuses Value before any data, non-string data and unknown algorithms", async () => {
    const { session } = setup();
    const hash = hashed(session);
    await expect(hash.Value).rejects.toMatchObject({ number: E_INVALIDARG });
    await expect(hash.Hash(5)).rejects.toMatchObject({ number: E_INVALIDARG });
    await hash.propset_Algorithm(999);
    await expect(hash.Hash("a")).rejects.toMatchObject({ number: E_INVALIDARG });
    await expect(hash.propset_DataEncoding(7)).rejects.toMatchObject({ number: E_INVALIDARG });
  });
});

// HMAC on GOST hashes: RFC 7836's examples (appendix B), and for GOST R 34.11-94 what OpenSSL's GOST engine 3.0.2
// answers (`openssl dgst -engine gost -md_gost94 -mac hmac -macopt hexkey:…`; docs/JOURNAL.md, 2026-10-16).
describe("CAdESCOM.HashedData with HMAC", () => {
  const key32 = Array.from({ length: 32 }, (_, i) => i.toString(16).padStart(2, "0")).join("");
  const key64 = Array.from({ length: 64 }, (_, i) => i.toString(16).padStart(2, "0")).join("");
  const message = btoa(String.fromCharCode(...[0x01, 0x26, 0xbd, 0xb8, 0x78, 0x00, 0xaf, 0x21, 0x43, 0x41, 0x45, 0x65, 0x63, 0x78, 0x01, 0x00]));
  const vectors: [number, string, string][] = [
    [constants.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256_HMAC, key32, "A1AA5F7DE402D7B3D323F2991C8D4534013137010A83754FD0AF6D7CD4922ED9"],
    [
      constants.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_512_HMAC,
      key32,
      "A59BAB22ECAE19C65FBDE6E5F4E9F5D8549D31F037F9DF9B905500E171923A773D5F1530F2ED7E964CB2EEDC29E9AD2F3AFE93B2814F79F5000FFC0366C251E6",
    ],
    [constants.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_HMAC, key32, "BAD70B61C41095BC47E1141CFAED42726A5CEEBD62CE75DBBB9AD76CDA9F72F7"],
    // Longer than GOST R 34.11-94's 32-byte block: the key is hashed first.
    [constants.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_HMAC, key64, "64CFF770386B1A0B35008299390368D3B3984EF3575B616E686F544480CB006F"],
    [constants.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256_HMAC, key64, "4D362E942F50F37AA24696BB2CB79D53122FDD6F73FA93EF5EC2EDFAC58BECA8"],
  ];

  async function hmacOf(session: Session, algorithm: number, key?: string): Promise<HashedData> {
    const hash = hashed(session);
    await hash.propset_Algorithm(algorithm);
    await hash.propset_DataEncoding(constants.CADESCOM_BASE64_TO_BINARY);
    if (key !== undefined) await hash.propset_Key(key);
    await hash.Hash(message);
    return hash;
  }

  it("computes the HMAC with the key set in Key", async () => {
    const { session } = setup();
    for (const [algorithm, key, value] of vectors) {
      const hash = await hmacOf(session, algorithm, key);
      expect(await hash.Value).toBe(value);
      expect(await hash.Key).toBe(key.toUpperCase());
    }
  });

  it("makes a random 64-byte key when none is set, and gives it in Key", async () => {
    const { session } = setup();
    const algorithm = constants.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256_HMAC;
    const hash = await hmacOf(session, algorithm);
    const key = await hash.Key;
    expect(key).toMatch(/^[0-9A-F]{128}$/);
    expect(await hash.Value).toBe(await (await hmacOf(session, algorithm, key)).Value);
    expect(await (await hmacOf(session, algorithm)).Key).not.toBe(key);
  });

  it("refuses a key for a plain hash, a short or spaced one, and one set while data waits to be hashed", async () => {
    const { session } = setup();
    const plain = hashed(session);
    await expect(plain.propset_Key(key32)).rejects.toMatchObject({ number: E_INVALIDARG });
    const hash = hashed(session);
    await hash.propset_Algorithm(constants.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_512_HMAC);
    await expect(hash.propset_Key(key32.slice(2))).rejects.toMatchObject({ number: E_INVALIDARG });
    await expect(hash.propset_Key(`${key32.slice(0, 32)} ${key32.slice(32)}`)).rejects.toMatchObject({ number: E_INVALIDARG });
    await hash.Hash("a");
    await expect(hash.propset_Key(key64)).rejects.toMatchObject({ number: 0x8000ffff });
    await hash.Value;
    await hash.propset_Key(key64);
    expect(await hash.Key).toBe(key64.toUpperCase());
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

  it("signs the hash as CAdES-T with the signer's timestamp service", async () => {
    const { plugin, session } = setup();
    const hash = hashed(session);
    await hash.propset_Algorithm(GOST_256);
    await hash.SetHashValue(HASH_256);
    const sign = await signer(session);
    await sign.propset_TSAAddress("http://tsa.example/tsp");
    const data = createObject("CAdESCOM.CadesSignedData", session) as CadesSignedData;
    expect(await data.SignHash(hash, sign, constants.CADESCOM_CADES_T)).toBe("MIIsignature");
    expect(plugin.calls.sign[0]!.options).toEqual({
      detached: true,
      addUserCertificate: true,
      addEssCert: true,
      addSignTime: true,
      tspOptions: { url: "http://tsa.example/tsp", digestAlg: 5, cert: true, verifyTsToken: false },
    });
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
    const mac = hashed(session);
    await mac.propset_Algorithm(constants.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256_HMAC);
    await mac.Hash("a");
    await expect(data.SignHash(mac, sign, constants.CADESCOM_CADES_BES)).rejects.toMatchObject({ number: E_INVALIDARG });
    expect(plugin.calls.sign).toHaveLength(0);
    expect(dialog.requests).toHaveLength(0);
  });
});
