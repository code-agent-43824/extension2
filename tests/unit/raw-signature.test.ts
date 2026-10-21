import { gost256B } from "@li0ard/gost/gost3410.js";
import { describe, expect, it } from "vitest";
import { constants } from "../../src/page/constants.ts";
import { CadesError } from "../../src/page/errors.ts";
import type { Certificate, Certificates } from "../../src/page/objects/certificate.ts";
import type { HashedData } from "../../src/page/objects/hashed-data.ts";
import { createObject } from "../../src/page/objects/index.ts";
import type { RawSignature } from "../../src/page/objects/raw-signature.ts";
import type { Session } from "../../src/page/objects/session.ts";
import type { Store } from "../../src/page/objects/store.ts";
import { derToBase64, parseCertificate, pemToDer } from "../../src/page/x509.ts";
import { fakePlugin, FakePinDialog, fakeSession, pem, userPin } from "./fakes.ts";

const hex = (bytes: Uint8Array) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
const reversed = (bytes: Uint8Array) => Uint8Array.from(bytes).reverse();

// The stand user's certificate with a key of the test's own on the same curve (1.2.643.2.2.35.1, gost256B), so that
// the fake plugin's rawSign can sign for real: the certificate's own signature no longer matters here.
function certificateWithKey(): { pem: string; secretKey: Uint8Array } {
  const der = pemToDer(pem);
  const old = parseCertificate(der).publicKey.subarray(2);
  const { secretKey } = gost256B.keygen();
  const point = gost256B.getPublicKey(secretKey, false);
  const xy = new Uint8Array(64);
  xy.set(reversed(point.subarray(1, 33)), 0);
  xy.set(reversed(point.subarray(33)), 32);
  const at = hex(der).indexOf(hex(old)) / 2;
  const replaced = Uint8Array.from(der);
  replaced.set(xy, at);
  return { pem: `-----BEGIN CERTIFICATE-----\n${derToBase64(replaced)}\n-----END CERTIFICATE-----\n`, secretKey };
}

function setup(answers: (string | null)[] = [userPin]) {
  const { pem: certificate, secretKey } = certificateWithKey();
  const signed: string[] = [];
  // As the plugin answers (docs/JOURNAL.md, 2026-09-24): the hash as colon hex in, s||r big-endian out.
  const plugin = fakePlugin([certificate], {
    rawSign: async (_device, _key, data) => {
      signed.push(data);
      const rs = gost256B.sign(secretKey, reversed(Uint8Array.from(data.split(":"), (pair) => parseInt(pair, 16))));
      return Array.from([...rs.subarray(32), ...rs.subarray(0, 32)], (byte) => byte.toString(16).padStart(2, "0")).join(":");
    },
  });
  const dialog = new FakePinDialog(answers);
  return { plugin, dialog, signed, session: fakeSession(plugin, dialog) };
}

async function tokenCertificate(session: Session): Promise<Certificate> {
  const store = createObject("CAdESCOM.Store", session) as Store;
  await store.Open();
  return (await (store.Certificates as Promise<Certificates>)).Item(1);
}

async function hashOf(session: Session, value: string, algorithm: number = constants.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256): Promise<HashedData> {
  const hashed = createObject("CAdESCOM.HashedData", session) as HashedData;
  await hashed.propset_Algorithm(algorithm);
  await hashed.SetHashValue(value);
  return hashed;
}

const HASH = "92CD0CB36B10BFB88DEF198F80B7D2E667DBDA064D346405C25EEF77FFE375D7";

describe("CAdESCOM.RawSignature", () => {
  it("signs a hash on the token after the PIN: CMS's s||r reversed, hex pairs with spaces, and verifies it", async () => {
    const { plugin, dialog, signed, session } = setup();
    const certificate = await tokenCertificate(session);
    const hashed = await hashOf(session, HASH);
    const raw = createObject("CAdESCOM.RawSignature", session) as RawSignature;
    const signature = await raw.SignHash(hashed, certificate);
    expect(signature).toMatch(/^[0-9A-F]{2}( [0-9A-F]{2}){63}$/);
    expect(signed).toEqual([HASH.toLowerCase().replace(/(..)(?!$)/g, "$1:")]);
    expect(plugin.calls.login).toEqual([userPin]);
    expect(plugin.calls.logout).toBe(1);
    expect(dialog.requests[0]).toMatchObject({ action: "просит подписать хеш данных.", confirm: "Подписать" });
    await (createObject("CAdESCOM.RawSignature", session) as RawSignature).VerifyHash(hashed, certificate, signature);
    // Without the spaces too, as CryptoPro's sample says a hash may come.
    await (createObject("CAdESCOM.RawSignature", session) as RawSignature).VerifyHash(hashed, certificate, signature.replace(/ /g, "").toLowerCase());
  });

  it("refuses a signature of another hash, or one in CMS's byte order, with NTE_BAD_SIGNATURE", async () => {
    const { session } = setup();
    const certificate = await tokenCertificate(session);
    const raw = createObject("CAdESCOM.RawSignature", session) as RawSignature;
    const signature = await raw.SignHash(await hashOf(session, HASH), certificate);
    const other = await hashOf(session, `${HASH.slice(0, -2)}D8`);
    await expect(raw.VerifyHash(other, certificate, signature)).rejects.toMatchObject({ number: 0x80090006 });
    const cmsOrder = signature.split(" ").reverse().join(" ");
    await expect(raw.VerifyHash(await hashOf(session, HASH), certificate, cmsOrder)).rejects.toMatchObject({ number: 0x80090006 });
  });

  it("needs a token certificate and a hash of the key's algorithm; the PIN window's cancel signs nothing", async () => {
    const { plugin, session } = setup([null]);
    const certificate = await tokenCertificate(session);
    const raw = createObject("CAdESCOM.RawSignature", session) as RawSignature;
    const hashed = await hashOf(session, HASH);
    await expect(raw.SignHash(hashed, undefined)).rejects.toMatchObject({ number: 0x80070057 });
    const imported = createObject("CAdESCOM.Certificate", session) as Certificate;
    await imported.Import(await certificate.Export(constants.CADESCOM_ENCODE_BASE64));
    await expect(raw.SignHash(hashed, imported)).rejects.toMatchObject({ number: 0x80070057 });
    const wrongAlgorithm = await hashOf(session, HASH, constants.CADESCOM_HASH_ALGORITHM_CP_GOST_3411);
    await expect(raw.SignHash(wrongAlgorithm, certificate)).rejects.toMatchObject({ number: 0x80070057 });
    const cancelled = await raw.SignHash(hashed, certificate).catch((error: unknown) => error);
    expect(cancelled).toBeInstanceOf(CadesError);
    expect(plugin.calls.login).toEqual([]);
  });

  it("verifies with a certificate the site imported, without a token", async () => {
    const { session } = setup();
    const certificate = await tokenCertificate(session);
    const hashed = await hashOf(session, HASH);
    const signature = await (createObject("CAdESCOM.RawSignature", session) as RawSignature).SignHash(hashed, certificate);
    const imported = createObject("CAdESCOM.Certificate", session) as Certificate;
    await imported.Import(await certificate.Export(constants.CADESCOM_ENCODE_BASE64));
    await (createObject("CAdESCOM.RawSignature", session) as RawSignature).VerifyHash(hashed, imported, signature);
    await expect((createObject("CAdESCOM.RawSignature", session) as RawSignature).VerifyHash(hashed, imported, "not hex")).rejects.toMatchObject({
      number: 0x80070057,
    });
  });
});
