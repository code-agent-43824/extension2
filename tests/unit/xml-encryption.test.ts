// GOST 28147-89 encryption for XML (src/page/gost28147.ts) and VKO (src/page/gost.ts): the parts that need no browser
// DOM. Interoperability with OpenSSL's GOST engine is the opt-in tests/stand/openssl-gost.spec.ts.
import { gost256B } from "@li0ard/gost/gost3410.js";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { repoRoot } from "../../scripts/fetch-vendor.ts";
import { children, read } from "../../src/page/asn1.ts";
import { vko256 } from "../../src/page/gost.ts";
import { decryptContent, encryptContent, newContentKey, parseKeyTransport, PARAM_SET_Z, unwrapContentKey, wrapContentKey } from "../../src/page/gost28147.ts";
import { parseCertificate, pemToDer } from "../../src/page/x509.ts";

const bytes = (hex: string) => Uint8Array.from(hex.replace(/\s+/g, "").match(/../g) ?? [], (byte) => parseInt(byte, 16));
const hex = (value: Uint8Array) => Buffer.from(value).toString("hex");
const reversed = (value: Uint8Array) => Uint8Array.from(value).reverse();

// The stand CA's certificate: a GOST R 34.10-2012 256-bit key on the CryptoPro-A curve (1.2.643.2.2.35.1).
const ca = parseCertificate(pemToDer(readFileSync(join(repoRoot, "tests", "fixtures", "stand-ca.pem"), "utf8")));

// What the Rutoken Plugin's cmsEncrypt (GOST 28147-89) put into its KeyTransRecipientInfo for a stand CA's
// certificate (docs/JOURNAL.md, 2026-10-08).
const rutokenTransport = bytes(
  "3081a93028042005752cdf26780c1db95ad84a5d49cb1f4e01ab3300cbe89d691f68d44b2c4bc60404aa9cdc15a07d06092a8503070102050101a066301f06082a85030701010101301306072a85030202230106082a8503070101020203430004406395d0ef77acbd2274fd8b7236735e4a77aca5f1171ba65a24fe7972eedc61ccc6f8f14c50efc112f8e042f96d17a19ec69924a507cbfd43a07b8fa651cc296f040888dac64c6cd0b158",
);

// The fixed parts of a GostR3410-KeyTransport: tags, lengths and OIDs, with the key, MAC, ephemeral key and UKM blanked.
function shape(der: Uint8Array): string {
  const transport = parseKeyTransport(der);
  let text = hex(der);
  for (const part of [transport.encryptedKey, transport.mac, transport.ephemeralKey, transport.ukm]) text = text.replace(hex(part), "_".repeat(part.length * 2));
  return text;
}

describe("VKO GOST R 34.10-2012", () => {
  // RFC 7836, Appendix B, example 7: id-tc26-gost-3410-12-512-paramSetA, written there as here, little-endian.
  const ukm = bytes("1d 80 60 3c 85 44 c7 27");
  const x = bytes(
    "c9 90 ec d9 72 fc e8 4e c4 db 02 27 78 f5 0f ca c7 26 f4 67 08 38 4b 8d 45 83 04 96 2d 71 47 f8 c2 db 41 ce f2 2c 90 b1 02 f2 96 84 04 f9 b9 be 6d 47 c7 96 92 d8 18 26 b3 2b 8d ac a4 3c b6 67",
  );
  const yP = bytes(
    "19 2f e1 83 b9 71 3a 07 72 53 c7 2c 87 35 de 2e a4 2a 3d bc 66 ea 31 78 38 b6 5f a3 25 23 cd 5e fc a9 74 ed a7 c8 63 f4 95 4d 11 47 f1 f2 b2 5c 39 5f ce 1c 12 91 75 e8 76 d1 32 e9 4e d5 a6 51" +
      "04 88 3b 41 4c 9b 59 2e c4 dc 84 82 6f 07 d0 b6 d9 00 6d da 17 6c e4 8c 39 1e 3f 97 d1 02 e0 3b b5 98 bf 13 2a 22 8a 45 f7 20 1a ba 08 fc 52 4a 2d 77 e4 3a 36 2a b0 22 ad 40 28 f7 5b de 3b 79",
  );

  it("gives RFC 7836's KEK for its test keys", () => {
    expect(hex(vko256("1.2.643.7.1.2.1.2.1", x, yP, ukm))).toBe("c9a9a77320e2cc559ed72dce6f47e2192ccea95fa648670582c054c0ef36c221");
  });
});

describe("the content key for a recipient (GostR3410-KeyTransport)", () => {
  it("is laid out as the Rutoken Plugin lays it out, and the recipient's VKO unwraps it", () => {
    // A recipient key the test holds, on the CA's curve, in a copy of the CA's certificate.
    const { secretKey } = gost256B.keygen();
    const point = gost256B.getPublicKey(secretKey, false);
    const publicKey = new Uint8Array([...reversed(point.subarray(1, 33)), ...reversed(point.subarray(33))]);
    const recipient = { ...ca, publicKey: Uint8Array.of(0x04, 0x40, ...publicKey) };
    const cek = newContentKey();
    const der = wrapContentKey(recipient, cek);
    expect(shape(der)).toBe(shape(rutokenTransport));
    const transport = parseKeyTransport(der);
    expect(transport.paramSet).toBe(PARAM_SET_Z);
    const kek = vko256(ca.publicKeyParameters!, reversed(secretKey), transport.ephemeralKey, transport.ukm);
    expect(hex(unwrapContentKey(transport, kek))).toBe(hex(cek));
    expect(() => unwrapContentKey(transport, newContentKey())).toThrow();
  });

  it("reads the Rutoken Plugin's", () => {
    const transport = parseKeyTransport(rutokenTransport);
    expect(transport).toMatchObject({ paramSet: PARAM_SET_Z });
    expect([transport.encryptedKey.length, transport.mac.length, transport.ephemeralKey.length, transport.ukm.length]).toEqual([32, 4, 64, 8]);
    // The ephemeral key carries the recipient key's algorithm identifier.
    const ephemeral = children(children(children(read(rutokenTransport))[1]!)[1]!)[0]!;
    expect(hex(ephemeral.der)).toBe(hex(ca.publicKeyAlgorithmDer));
  });

  it("refuses a recipient whose key is not GOST R 34.10-2012", () => {
    expect(() => wrapContentKey({ ...ca, publicKeyAlgorithm: "1.2.840.113549.1.1.1" }, newContentKey())).toThrow();
  });
});

describe("GOST 28147-89 in CBC mode for XML", () => {
  // Made with OpenSSL's GOST engine: CRYPT_PARAMS=id-tc26-gost-28147-param-Z openssl enc -gost89-cbc -K … -iv …
  // (its PKCS#7 padding is ISO 10126 padding with fixed bytes).
  const key = bytes("0123456789abcdeffedcba98765432100011223344556677889900aabbccddee");
  const plain = "Пример для ГОСТ 28147-89 CBC: двадцать девять байт и ещё.";
  const openssl = bytes(
    "1122334455667788" +
      "63fa558d2a7a3c5ce2a9b32eb5266ef387d2273224c80c42933ffc13dae404f57b567c9ebf7ac3c207283c383ff41337abac75b0db5adac0bc6fc7bd0ebcd570075007f01c62f9512043d256c2ca8ef8cafc98ddb79639a82f81678b92e5dae1",
  );

  it("decrypts what OpenSSL encrypts with the TC26 Z parameter set", () => {
    expect(new TextDecoder().decode(decryptContent(key, openssl))).toBe(plain);
    expect(new TextDecoder().decode(decryptContent(key, openssl, "1.2.643.2.2.31.1"))).not.toBe(plain);
  });

  it("puts the IV first and pads to whole blocks with 1 to 8 bytes", () => {
    const cek = newContentKey();
    for (const length of [0, 1, 7, 8, 9, 15, 16, 17, 3000]) {
      const data = crypto.getRandomValues(new Uint8Array(length));
      const message = encryptContent(cek, data);
      expect(message.length).toBe(8 + 8 * (Math.floor(length / 8) + 1));
      expect(hex(decryptContent(cek, message))).toBe(hex(data));
    }
    expect(hex(encryptContent(cek, Uint8Array.of(1)).subarray(0, 8))).not.toBe(hex(encryptContent(cek, Uint8Array.of(1)).subarray(0, 8)));
    expect(() => decryptContent(cek, new Uint8Array(12))).toThrow();
  });
});
