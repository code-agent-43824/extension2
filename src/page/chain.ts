// Certificate chains to the extension's root store, checked in the page. As CryptoPro's plug-in 2.0.15700
// answers VerifyCades (docs/JOURNAL.md, 2026-09-24): no chain to a trusted root is CERT_E_CHAINING, also when
// it ends in a self-signed certificate the store lacks; a certificate outside its validity period now (not
// at the signing time) is CERT_E_EXPIRED. Revocation is not checked: the owner's decision, 2026-09-24
// (CryptoPro refuses a certificate whose CRL it cannot get).
import { verifyCertificate } from "./gost.ts";
import type { X509 } from "./x509.ts";

export const CERT_E_EXPIRED = 0x800b0101;
export const CERT_E_CHAINING = 0x800b010a;

// Chains longer than this are refused rather than searched; real ones have three or four certificates.
const MAX_DEPTH = 8;

function same(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

function valid(certificate: X509, at: number): boolean {
  return certificate.notBefore.getTime() <= at && at <= certificate.notAfter.getTime();
}

// The error of the best chain from `certificate` up to one of `roots`, through `pool` (the certificates the
// signature carries), or null when a whole chain is trusted and valid at `at`. Issuers are matched by name and
// proven by their signature. A trusted chain with a certificate out of its period is CERT_E_EXPIRED.
export function chainError(certificate: X509, pool: readonly X509[], roots: readonly X509[], at = Date.now()): number | null {
  let best = CERT_E_CHAINING;
  const walk = (current: X509, depth: number, expired: boolean, seen: X509[]): boolean => {
    const outdated = expired || !valid(current, at);
    if (roots.some((root) => same(root.der, current.der))) {
      if (!outdated) return true;
      best = CERT_E_EXPIRED;
      return false;
    }
    if (depth >= MAX_DEPTH) return false;
    for (const issuer of [...roots, ...pool]) {
      if (seen.some((certificate) => same(certificate.der, issuer.der)) || !same(issuer.subjectDer, current.issuerDer) || !verifyCertificate(current, issuer)) continue;
      if (walk(issuer, depth + 1, outdated, [...seen, issuer])) return true;
    }
    return false;
  };
  return walk(certificate, 0, false, [certificate]) ? null : best;
}

// Certificate.IsValid() in the extended mode (the options page's switch): the chain CryptoPro's plug-in 2.0.15700
// reports (docs/JOURNAL.md, 2026-09-24), from the certificate up, with a CERT_TRUST_* status for each element.
// A certificate outside its period now is CERT_TRUST_IS_NOT_TIME_VALID; an issuer found by name whose key does
// not verify the certificate below it is CERT_TRUST_IS_NOT_SIGNATURE_VALID, on the issuer, as the plug-in marks
// it; a self-signed top the store lacks is CERT_TRUST_IS_UNTRUSTED_ROOT; no issuer at all ends the chain with no
// status, and the certificate is still not valid. Revocation is not checked (the owner's decision, 2026-09-24).
export const CERT_TRUST_IS_NOT_TIME_VALID = 0x1;
export const CERT_TRUST_IS_NOT_SIGNATURE_VALID = 0x8;
export const CERT_TRUST_IS_UNTRUSTED_ROOT = 0x20;

export interface ValidationChain {
  // The certificate first, then its issuers.
  certificates: X509[];
  statuses: number[];
  valid: boolean;
}

export function validationChain(certificate: X509, pool: readonly X509[], roots: readonly X509[], at = Date.now()): ValidationChain {
  const certificates = [certificate];
  const statuses = [valid(certificate, at) ? 0 : CERT_TRUST_IS_NOT_TIME_VALID];
  let trusted = false;
  for (let current = certificate; ; ) {
    if (roots.some((root) => same(root.der, current.der))) {
      trusted = true;
      break;
    }
    if (same(current.subjectDer, current.issuerDer)) {
      statuses[statuses.length - 1]! |= CERT_TRUST_IS_UNTRUSTED_ROOT;
      break;
    }
    if (certificates.length >= MAX_DEPTH) break;
    const candidates = [...roots, ...pool].filter(
      (issuer) => same(issuer.subjectDer, current.issuerDer) && !certificates.some((seen) => same(seen.der, issuer.der)),
    );
    if (!candidates.length) break;
    // The issuer whose key verifies the certificate; of several, one that leads to a trusted root, whatever the
    // dates (at minus infinity every certificate is out of its period, so only CERT_E_CHAINING means no chain).
    const proven = candidates.filter((issuer) => verifyCertificate(current, issuer));
    const issuer = proven.find((candidate) => chainError(candidate, pool, roots, Number.NEGATIVE_INFINITY) !== CERT_E_CHAINING) ?? proven[0] ?? candidates[0]!;
    certificates.push(issuer);
    statuses.push((valid(issuer, at) ? 0 : CERT_TRUST_IS_NOT_TIME_VALID) | (proven.includes(issuer) ? 0 : CERT_TRUST_IS_NOT_SIGNATURE_VALID));
    current = issuer;
  }
  return { certificates, statuses, valid: trusted && statuses.every((status) => status === 0) };
}
