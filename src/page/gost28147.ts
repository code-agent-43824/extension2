// GOST 28147-89 encryption in the page, for XML encryption the way CryptoPro does it (docs/JOURNAL.md, 2026-10-08):
// the content in CBC mode with ISO 10126 padding behind an 8-byte IV, the content key wrapped for each recipient as
// a GostR3410-KeyTransport (RFC 4490, 4.2.1): VKO GOST R 34.10-2012 with an ephemeral key and CryptoPro's key wrap
// (RFC 4357, 6.3). The parameter set is TC26's Z, as in the Rutoken Plugin's and OpenSSL's CMS for 2012 keys.
// Unwrapping needs the recipient's private key, so there the key-encryption key comes from the token.
import { Magma, magmaSboxes } from "@li0ard/gost/magma.js";
import { cbc, kwp } from "@li0ard/gost/modes.js";
import { children, decodeOid, encode, encodeOid, expectTag, read } from "./asn1.ts";
import { ephemeralAgreement } from "./gost.ts";
import type { X509 } from "./x509.ts";

export const PARAM_SET_Z = "1.2.643.7.1.2.5.1.1";

// GOST 28147-89 parameter sets (RFC 4357, RFC 7836) by OID: the S-box each one names.
const sboxes = new Map<string, Uint8Array>([
  [PARAM_SET_Z, magmaSboxes.ID_TC26_GOST_28147_PARAM_Z],
  ["1.2.643.2.2.31.1", magmaSboxes.ID_GOST_28147_89_CRYPTO_PRO_A_PARAM_SET],
  ["1.2.643.2.2.31.2", magmaSboxes.ID_GOST_28147_89_CRYPTO_PRO_B_PARAM_SET],
  ["1.2.643.2.2.31.3", magmaSboxes.ID_GOST_28147_89_CRYPTO_PRO_C_PARAM_SET],
  ["1.2.643.2.2.31.4", magmaSboxes.ID_GOST_28147_89_CRYPTO_PRO_D_PARAM_SET],
]);

function sbox(paramSet: string): Uint8Array {
  const value = sboxes.get(paramSet);
  if (!value) throw new Error(`GOST 28147-89: unknown parameter set ${paramSet}`);
  return value;
}

function random(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

// A GostR3410-KeyTransport taken apart.
export interface KeyTransport {
  encryptedKey: Uint8Array;
  mac: Uint8Array;
  paramSet: string;
  // The sender's ephemeral public key as x||y, each little-endian, as in a certificate.
  ephemeralKey: Uint8Array;
  ukm: Uint8Array;
}

// The content key `cek` wrapped for the recipient's GOST R 34.10-2012 key, as DER; laid out as the Rutoken Plugin
// lays it out in CMS: the ephemeral key with the recipient key's own algorithm identifier.
export function wrapContentKey(recipient: X509, cek: Uint8Array, paramSet = PARAM_SET_Z): Uint8Array {
  let ukm = random(8);
  // A zero UKM is replaced by 1 (RFC 7836, 4.3.1).
  if (ukm.every((byte) => byte === 0)) ukm = Uint8Array.of(1, 0, 0, 0, 0, 0, 0, 0);
  const agreement = ephemeralAgreement(recipient, ukm);
  if (!agreement) throw new Error("GOST 28147-89: the recipient's key is not GOST R 34.10-2012");
  const wrapped = kwp(agreement.kek, true, sbox(paramSet)).wrap(ukm, cek);
  const ephemeral = encode(0xa0, recipient.publicKeyAlgorithmDer, encode(0x03, Uint8Array.of(0), encode(0x04, agreement.publicKey)));
  return encode(
    0x30,
    encode(0x30, encode(0x04, wrapped.subarray(8, 40)), encode(0x04, wrapped.subarray(40))),
    encode(0xa0, encode(0x06, encodeOid(paramSet)), ephemeral, encode(0x04, ukm)),
  );
}

export function parseKeyTransport(der: Uint8Array): KeyTransport {
  const [sessionKey, parameters] = children(expectTag(read(der), 0x30, "GostR3410-KeyTransport"));
  const keyFields = children(expectTag(sessionKey, 0x30, "Gost28147-89-EncryptedKey"));
  const [paramSet, ephemeral, ukm] = children(expectTag(parameters, 0xa0, "transportParameters"));
  if (ephemeral?.tag !== 0xa0) throw new Error("DER: ephemeralPublicKey expected");
  const keyBits = expectTag(children(ephemeral)[1], 0x03, "subjectPublicKey").value.subarray(1);
  return {
    encryptedKey: expectTag(keyFields[0], 0x04, "encryptedKey").value,
    mac: expectTag(keyFields.at(-1), 0x04, "macKey").value,
    paramSet: decodeOid(expectTag(paramSet, 0x06, "encryptionParamSet").value),
    ephemeralKey: expectTag(read(keyBits), 0x04, "public key").value,
    ukm: expectTag(ukm, 0x04, "ukm").value,
  };
}

// The content key, given the key-encryption key VKO made from the recipient's private key and the ephemeral key.
// Throws when the key's MAC does not match: a wrong key, or a damaged message.
export function unwrapContentKey(transport: KeyTransport, kek: Uint8Array): Uint8Array {
  const wrapped = new Uint8Array(44);
  wrapped.set(transport.ukm, 0);
  wrapped.set(transport.encryptedKey, 8);
  wrapped.set(transport.mac, 40);
  return kwp(kek, true, sbox(transport.paramSet)).unwrap(wrapped);
}

export function newContentKey(): Uint8Array {
  return random(32);
}

// IV || CBC(data with ISO 10126 padding: random bytes, the last one their count, 1 to 8).
export function encryptContent(cek: Uint8Array, data: Uint8Array, paramSet = PARAM_SET_Z): Uint8Array {
  const iv = random(8);
  const count = 8 - (data.length % 8);
  const padded = new Uint8Array(data.length + count);
  padded.set(data);
  padded.set(random(count - 1), data.length);
  padded[padded.length - 1] = count;
  const encrypted = cbc(new Magma(cek, sbox(paramSet), true), iv).encrypt(padded);
  const result = new Uint8Array(8 + encrypted.length);
  result.set(iv);
  result.set(encrypted, 8);
  return result;
}

export function decryptContent(cek: Uint8Array, message: Uint8Array, paramSet = PARAM_SET_Z): Uint8Array {
  if (message.length < 16 || message.length % 8 !== 0) throw new Error("GOST 28147-89: the ciphertext is not whole blocks");
  const padded = cbc(new Magma(cek, sbox(paramSet), true), message.subarray(0, 8)).decrypt(message.subarray(8));
  const count = padded[padded.length - 1]!;
  if (count < 1 || count > 8) throw new Error("GOST 28147-89: bad padding");
  return padded.subarray(0, padded.length - count);
}
