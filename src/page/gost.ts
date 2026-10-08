// Hashes and GOST R 34.10 signature checks in the page itself, without the Rutoken Plugin or a token:
// @li0ard/gost (on @noble/curves) and @noble/hashes. The byte order is the one of X.509 and CMS, established
// on the stand (tests/tools/gost_ca.py): a public key is x||y and a hash is read as a number, each
// little-endian; a signature is s||r, big-endian.
import { gost256A, gost256B, gost256C, gost256D, gost512A, gost512B, gost512C } from "@li0ard/gost/gost3410.js";
import { gost341194 } from "@li0ard/gost/gost341194.js";
import { streebog256, streebog512 } from "@li0ard/gost/streebog.js";
import { md5, sha1 } from "@noble/hashes/legacy.js";
import { sha256, sha384, sha512 } from "@noble/hashes/sha2.js";
import type { X509 } from "./x509.ts";

export type DigestName = "gost94" | "streebog256" | "streebog512" | "md5" | "sha1" | "sha256" | "sha384" | "sha512";

// GOST R 34.11-94 with CryptoPro's S-box (1.2.643.2.2.30.1), the one CryptoPro CSP and its certificates use.
const digests: Record<DigestName, (data: Uint8Array) => Uint8Array> = {
  gost94: gost341194,
  streebog256,
  streebog512,
  md5,
  sha1,
  sha256,
  sha384,
  sha512,
};

export function digest(name: DigestName, data: Uint8Array): Uint8Array {
  return digests[name](data);
}

export const GOST_2001 = "1.2.643.2.2.19";
export const GOST_2012_256 = "1.2.643.7.1.1.1.1";
export const GOST_2012_512 = "1.2.643.7.1.1.1.2";

// Digest algorithm OIDs, as CMS names them.
export const digestOids = new Map<string, DigestName>([
  ["1.2.643.2.2.9", "gost94"],
  ["1.2.643.7.1.1.2.2", "streebog256"],
  ["1.2.643.7.1.1.2.3", "streebog512"],
  ["1.2.840.113549.2.5", "md5"],
  ["1.3.14.3.2.26", "sha1"],
  ["2.16.840.1.101.3.4.2.1", "sha256"],
  ["2.16.840.1.101.3.4.2.2", "sha384"],
  ["2.16.840.1.101.3.4.2.3", "sha512"],
]);

// Certificate signature algorithms: the hash each one signs.
const signatureDigests = new Map<string, DigestName>([
  ["1.2.643.2.2.3", "gost94"],
  ["1.2.643.7.1.1.3.2", "streebog256"],
  ["1.2.643.7.1.1.3.3", "streebog512"],
]);

// Parameter sets (RFC 4357, RFC 7836) by curve; CryptoPro's names for the 2001 ones point at the same curves.
type Curve = typeof gost256A;
const curves = new Map<string, Curve>([
  ["1.2.643.7.1.2.1.1.1", gost256A],
  ["1.2.643.7.1.2.1.1.2", gost256B],
  ["1.2.643.2.2.35.1", gost256B],
  ["1.2.643.2.2.36.0", gost256B],
  ["1.2.643.7.1.2.1.1.3", gost256C],
  ["1.2.643.2.2.35.2", gost256C],
  ["1.2.643.7.1.2.1.1.4", gost256D],
  ["1.2.643.2.2.35.3", gost256D],
  ["1.2.643.2.2.36.1", gost256D],
  ["1.2.643.7.1.2.1.2.1", gost512A],
  ["1.2.643.7.1.2.1.2.2", gost512B],
  ["1.2.643.7.1.2.1.2.3", gost512C],
]);

const keySizes = new Map<string, number>([
  [GOST_2001, 32],
  [GOST_2012_256, 32],
  [GOST_2012_512, 64],
]);

function reversed(bytes: Uint8Array): Uint8Array {
  return Uint8Array.from(bytes).reverse();
}

// The key's point x||y (each little-endian): the OCTET STRING inside the subjectPublicKey BIT STRING.
function point(key: X509, size: number): Uint8Array | undefined {
  const bits = key.publicKey;
  if (bits[0] !== 0x04) return undefined;
  const long = bits[1]! & 0x80 ? bits[1]! & 0x7f : 0;
  const length = long ? bits.subarray(2, 2 + long).reduce((sum, byte) => sum * 256 + byte, 0) : bits[1]!;
  const value = bits.subarray(2 + long, 2 + long + length);
  return value.length === 2 * size ? value : undefined;
}

// Whether the certificate's GOST key can be checked here: its curve is known.
export function isGostKey(key: X509): boolean {
  return keySizes.has(key.publicKeyAlgorithm) && curves.has(key.publicKeyParameters ?? "");
}

// Checks a GOST R 34.10 signature (s||r, as in X.509 and CMS) of `hash` made with the certificate's key.
export function verifyHash(key: X509, hash: Uint8Array, signature: Uint8Array): boolean {
  const size = keySizes.get(key.publicKeyAlgorithm);
  const curve = curves.get(key.publicKeyParameters ?? "");
  const xy = size && point(key, size);
  if (!size || !curve || !xy || signature.length !== 2 * size || hash.length !== size) return false;
  const publicKey = noblePoint(xy);
  const rs = new Uint8Array(2 * size);
  rs.set(signature.subarray(size), 0);
  rs.set(signature.subarray(0, size), size);
  try {
    return curve.verify(publicKey, reversed(hash), rs);
  } catch {
    return false;
  }
}

// A public key x||y (each little-endian, as in a certificate) as @noble/curves takes it: 04, then x and y big-endian.
function noblePoint(xy: Uint8Array): Uint8Array {
  const size = xy.length / 2;
  const result = new Uint8Array(1 + xy.length);
  result[0] = 0x04;
  result.set(reversed(xy.subarray(0, size)), 1);
  result.set(reversed(xy.subarray(size)), 1 + size);
  return result;
}

// VKO GOST R 34.10-2012 with Streebog-256 (RFC 7836, 4.3.1), the key-encryption key for GOST 28147-89, for 512-bit
// keys too: the shared key of `secretKey` (little-endian) and `publicKey` (x||y, each little-endian) on the curve of
// `paramSet`, the UKM read as a little-endian number, as OpenSSL's GOST engine does.
export function vko256(paramSet: string, secretKey: Uint8Array, publicKey: Uint8Array, ukm: Uint8Array): Uint8Array {
  const curve = curves.get(paramSet);
  if (!curve) throw new Error(`GOST R 34.10: unknown curve ${paramSet}`);
  return curve.getSharedSecret(streebog256, reversed(secretKey), noblePoint(publicKey), reversed(ukm));
}

// VKO with a fresh ephemeral key on the recipient's curve: the key-encryption key and the ephemeral public key (x||y,
// each little-endian); undefined for keys other than GOST R 34.10-2012 on a known curve.
export function ephemeralAgreement(recipient: X509, ukm: Uint8Array): { publicKey: Uint8Array; kek: Uint8Array } | undefined {
  const size = keySizes.get(recipient.publicKeyAlgorithm);
  const paramSet = recipient.publicKeyParameters ?? "";
  const curve = curves.get(paramSet);
  const xy = size && point(recipient, size);
  if (!size || !curve || !xy || recipient.publicKeyAlgorithm === GOST_2001) return undefined;
  const { secretKey } = curve.keygen();
  const uncompressed = curve.getPublicKey(secretKey, false);
  const publicKey = new Uint8Array(2 * size);
  publicKey.set(reversed(uncompressed.subarray(1, 1 + size)), 0);
  publicKey.set(reversed(uncompressed.subarray(1 + size)), size);
  return { publicKey, kek: vko256(paramSet, reversed(secretKey), xy, ukm) };
}

// Whether `issuer`'s key signed `certificate`.
export function verifyCertificate(certificate: X509, issuer: X509): boolean {
  const name = signatureDigests.get(certificate.signatureAlgorithm);
  return name !== undefined && verifyHash(issuer, digest(name, certificate.tbs), certificate.signature);
}
