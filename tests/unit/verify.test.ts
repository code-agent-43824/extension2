// Signature verification in the page: CadesSignedData.VerifyCades and VerifyHash on signatures CryptoPro's
// plug-in 2.0.15700 made and on crafted ones, with the answers the real plug-in gave for them
// (tests/fixtures/verify.json, docs/JOURNAL.md 2026-09-24); the GOST code on the built-in root certificates.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { repoRoot } from "../../scripts/fetch-vendor.ts";
import { BUILTIN_ROOTS } from "../../src/extension/builtin-roots.ts";
import { chainError } from "../../src/page/chain.ts";
import { parseSignedData } from "../../src/page/cms.ts";
import { constants } from "../../src/page/constants.ts";
import { isGostKey, verifyCertificate } from "../../src/page/gost.ts";
import type { Certificate, Certificates } from "../../src/page/objects/certificate.ts";
import type { HashedData } from "../../src/page/objects/hashed-data.ts";
import { createObject } from "../../src/page/objects/index.ts";
import type { CadesSignedData } from "../../src/page/objects/signed-data.ts";
import type { Signers, VerifiedSigner } from "../../src/page/objects/signers.ts";
import { parseCertificate, type X509 } from "../../src/page/x509.ts";
import { fakePlugin, FakePinDialog, fakeSession } from "./fakes.ts";

interface Fixtures {
  made: string;
  ca: string;
  content: string;
  cryptopro: Record<"bes" | "detached" | "pkcs7" | "hash_abc" | "xml", string>;
  crafted: Record<string, string>;
}

const fixtures = JSON.parse(readFileSync(join(repoRoot, "tests", "fixtures", "verify.json"), "utf8")) as Fixtures;
const der = (base64: string) => Uint8Array.from(Buffer.from(base64, "base64"));
const ca = parseCertificate(der(fixtures.ca));

const BES = constants.CADESCOM_CADES_BES;
const PKCS7 = constants.CADESCOM_PKCS7_TYPE;
const E_INVALIDARG = 0x80070057;
const E_NOTIMPL = 0x80004001;
const NTE_BAD_SIGNATURE = 0x80090006;
const CRYPT_E_HASH_VALUE = 0x80091007;
const CRYPT_E_SIGNER_NOT_FOUND = 0x8009100e;
const CRYPT_E_ATTRIBUTES_MISSING = 0x8009100f;
const CRYPT_E_NO_SIGNER = 0x8009200e;
const TRUST_E_NOSIGNATURE = 0x800b0100;
const CERT_E_EXPIRED = 0x800b0101;
const CERT_E_CHAINING = 0x800b010a;
const CERT_E_WRONG_USAGE = 0x800b0110;

// No token at all: verification must not need one.
function signedData(roots: X509[] = [ca]): CadesSignedData {
  const plugin = fakePlugin([], { enumerateDevices: async () => [] });
  return createObject("CAdESCOM.CadesSignedData", fakeSession(plugin, new FakePinDialog([]), roots)) as CadesSignedData;
}

async function firstSigner(data: CadesSignedData): Promise<VerifiedSigner> {
  return (await (data.Signers as Promise<Signers>)).Item(1);
}

// The fixtures' certificates were valid when they were made; checks run as of that moment.
beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(new Date(fixtures.made));
});

afterEach(() => {
  vi.useRealTimers();
});

describe("GOST signatures in the page", () => {
  it("checks the built-in root certificates' own signatures: 2001 with GOST 94, 2012 with 256 and 512 bits", () => {
    const roots = BUILTIN_ROOTS.map((base64) => parseCertificate(der(base64)));
    const gost = roots.filter(isGostKey);
    expect(new Set(gost.map((root) => root.publicKeyAlgorithm))).toEqual(new Set(["1.2.643.2.2.19", "1.2.643.7.1.1.1.1", "1.2.643.7.1.1.1.2"]));
    for (const root of gost) expect(verifyCertificate(root, root)).toBe(true);
    const tampered = { ...gost[0]!, tbs: Uint8Array.from(gost[0]!.tbs) };
    tampered.tbs[20]! ^= 1;
    expect(verifyCertificate(tampered, gost[0]!)).toBe(false);
  });

  it("builds a chain through the signature's certificates to a root of the store", () => {
    const intermediate = parseSignedData(der(fixtures.crafted.intermediate!));
    const [leaf, issuer] = intermediate.certificates as [X509, X509];
    expect(chainError(leaf, [issuer], [ca])).toBeNull();
    expect(chainError(leaf, [], [ca])).toBe(CERT_E_CHAINING);
    expect(chainError(leaf, [issuer], [])).toBe(CERT_E_CHAINING);
    expect(chainError(leaf, [issuer], [ca], leaf.notAfter.getTime() + 1)).toBe(CERT_E_EXPIRED);
  });

  it("reads BER with indefinite lengths and the content in pieces", () => {
    const ber = parseSignedData(der(fixtures.crafted.ber!));
    expect(Buffer.from(ber.content!).toString("utf16le")).toBe(fixtures.content);
  });
});

describe("CadesSignedData.VerifyCades", () => {
  it("verifies CryptoPro's attached signature, then reports the content, the signer and the certificates", async () => {
    for (const type of [BES, PKCS7]) {
      const data = signedData();
      await data.VerifyCades(fixtures.cryptopro.bes, type);
      expect(await data.Content).toBe(fixtures.content);
      const signer = await firstSigner(data);
      expect(await (await signer.SignatureStatus).IsValid).toBe(true);
      expect(await ((await signer.Certificate) as Certificate).SubjectName).toBe("C=RU, O=Проверка, CN=КриптоПро на стенде");
      expect(await signer.SigningTime).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.000Z$/);
      await expect(signer.SignatureTimeStampTime).rejects.toMatchObject({ number: 0x80092004 });
      expect(await ((await data.Certificates) as Certificates).Count).toBe(1);
    }
    const pkcs7 = signedData();
    await pkcs7.VerifyCades(fixtures.cryptopro.pkcs7, BES);
  });

  it("verifies a detached signature of Content, in either encoding, and BER", async () => {
    const data = signedData();
    await data.propset_Content(fixtures.content);
    await data.VerifyCades(fixtures.cryptopro.detached, BES, true);
    const base64 = signedData();
    await base64.propset_ContentEncoding(constants.CADESCOM_BASE64_TO_BINARY);
    await base64.propset_Content(Buffer.from(fixtures.content, "utf16le").toString("base64"));
    await base64.VerifyCades(fixtures.crafted.detached, BES, true);
    const ber = signedData();
    await ber.VerifyCades(fixtures.crafted.ber, BES);
    expect(await ber.Content).toBe(fixtures.content);
  });

  it("refuses changed content and a detached signature without it, and then has no signers", async () => {
    const changed = signedData();
    await changed.propset_Content("Привеп");
    await expect(changed.VerifyCades(fixtures.cryptopro.detached, BES, true)).rejects.toMatchObject({ number: NTE_BAD_SIGNATURE });
    await expect(changed.Signers).rejects.toMatchObject({ number: TRUST_E_NOSIGNATURE });
    await expect(signedData().VerifyCades(fixtures.cryptopro.detached, BES, true)).rejects.toMatchObject({ number: NTE_BAD_SIGNATURE });
    const tampered = der(fixtures.cryptopro.bes);
    tampered[tampered.length - 5]! ^= 1;
    await expect(signedData().VerifyCades(Buffer.from(tampered).toString("base64"), BES)).rejects.toMatchObject({ number: NTE_BAD_SIGNATURE });
    await expect(signedData().VerifyCades(fixtures.crafted.wrong_message_digest, PKCS7)).rejects.toMatchObject({ number: NTE_BAD_SIGNATURE });
  });

  it("needs the signing-certificate attribute for CAdES-BES, and a matching one for either type", async () => {
    await expect(signedData().VerifyCades(fixtures.crafted.no_signing_certificate, BES)).rejects.toMatchObject({ number: CRYPT_E_NO_SIGNER });
    await expect(signedData().VerifyCades(fixtures.crafted.no_attributes, BES)).rejects.toMatchObject({ number: CRYPT_E_NO_SIGNER });
    await signedData().VerifyCades(fixtures.crafted.no_signing_certificate, PKCS7);
    const noAttributes = signedData();
    await noAttributes.VerifyCades(fixtures.crafted.no_attributes, PKCS7);
    await expect((await firstSigner(noAttributes)).SigningTime).rejects.toMatchObject({ number: 0x80092004 });
    await expect(signedData().VerifyCades(fixtures.crafted.wrong_signing_certificate, PKCS7)).rejects.toMatchObject({ number: CRYPT_E_NO_SIGNER });
  });

  it("checks the certificate after the signature: chain to the store, validity now, key usage; signers stay, not valid", async () => {
    const cases: [string, number, X509[]][] = [
      ["bes", CERT_E_CHAINING, []],
      ["self_signed", CERT_E_CHAINING, [ca]],
      ["intermediate_missing", CERT_E_CHAINING, [ca]],
      ["expired", CERT_E_EXPIRED, [ca]],
      ["no_digital_signature", CERT_E_WRONG_USAGE, [ca]],
    ];
    for (const [name, code, roots] of cases) {
      const data = signedData(roots);
      await expect(data.VerifyCades(fixtures.crafted[name], BES), name).rejects.toMatchObject({ number: code });
      expect(await (await (await firstSigner(data)).SignatureStatus).IsValid).toBe(false);
      expect(await data.Content).toBe("");
    }
    await signedData().VerifyCades(fixtures.crafted.intermediate, BES);
  });

  it("answers the types it cannot check yet, unknown types and non-signatures as the real plug-in", async () => {
    for (const type of [constants.CADESCOM_CADES_DEFAULT, constants.CADESCOM_CADES_T, constants.CADESCOM_CADES_X_LONG_TYPE_1]) {
      await expect(signedData().VerifyCades(fixtures.cryptopro.bes, type)).rejects.toMatchObject({ number: CRYPT_E_ATTRIBUTES_MISSING });
    }
    await expect(signedData().VerifyCades(fixtures.cryptopro.bes)).rejects.toMatchObject({ number: CRYPT_E_ATTRIBUTES_MISSING });
    await expect(signedData().VerifyCades(fixtures.crafted.timestamped, constants.CADESCOM_CADES_T)).rejects.toMatchObject({ number: E_NOTIMPL });
    await expect(signedData().VerifyCades(fixtures.cryptopro.bes, 2)).rejects.toMatchObject({ number: E_INVALIDARG });
    await expect(signedData().VerifyCades("", BES)).rejects.toMatchObject({ number: E_INVALIDARG });
    await expect(signedData().VerifyCades("not base64 !!!", BES)).rejects.toMatchObject({ number: CRYPT_E_SIGNER_NOT_FOUND });
    await expect(signedData().VerifyCades("MAMCAQA=", BES)).rejects.toMatchObject({ number: CRYPT_E_SIGNER_NOT_FOUND });
    await expect(signedData().Signers).rejects.toMatchObject({ number: TRUST_E_NOSIGNATURE });
    await expect(signedData().Certificates).rejects.toMatchObject({ number: TRUST_E_NOSIGNATURE });
  });
});

describe("CadesSignedData.VerifyHash", () => {
  async function hash(algorithm: number, text: string): Promise<HashedData> {
    const plugin = fakePlugin([], { enumerateDevices: async () => [] });
    const result = createObject("CAdESCOM.HashedData", fakeSession(plugin)) as HashedData;
    await result.propset_Algorithm(algorithm);
    await result.Hash(text);
    return result;
  }

  it("verifies CryptoPro's signature of a hash, and signatures of data by their message digest", async () => {
    const data = signedData();
    await data.VerifyHash(await hash(constants.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256, "abc"), fixtures.cryptopro.hash_abc, BES);
    expect(await (await (await firstSigner(data)).SignatureStatus).IsValid).toBe(true);
    expect(await data.Content).toBe("");
    for (const signature of [fixtures.cryptopro.detached, fixtures.cryptopro.bes]) {
      const other = signedData();
      await other.VerifyHash(await hash(constants.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256, fixtures.content), signature, PKCS7);
    }
  });

  it("answers a hash that is not the signed one with CRYPT_E_HASH_VALUE, whatever its algorithm", async () => {
    for (const [algorithm, text] of [
      [constants.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256, "abd"],
      [constants.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_512, "abc"],
    ] as const) {
      const data = signedData();
      await expect(data.VerifyHash(await hash(algorithm, text), fixtures.cryptopro.hash_abc, BES)).rejects.toMatchObject({ number: CRYPT_E_HASH_VALUE });
      await expect(data.Signers).rejects.toMatchObject({ number: TRUST_E_NOSIGNATURE });
    }
    const data = signedData();
    await expect(data.VerifyHash(await hash(constants.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256, "abc"), fixtures.cryptopro.hash_abc)).rejects.toMatchObject({
      number: CRYPT_E_ATTRIBUTES_MISSING,
    });
    await expect(data.VerifyHash("hash", fixtures.cryptopro.hash_abc, BES)).rejects.toMatchObject({ number: E_INVALIDARG });
  });
});
