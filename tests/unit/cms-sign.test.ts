// CMS SignedData made in the page (docs/PLAN.md, action 35c): the attributes, the layout CryptoPro's signatures have,
// the signature checked by the page's own verification, and certificates added to a signature as sign() made it.
import { gost256B } from "@li0ard/gost/gost3410.js";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { repoRoot } from "../../scripts/fetch-vendor.ts";
import { children, decodeOid, read } from "../../src/page/asn1.ts";
import { attribute, encodeTime, signedAttributes, signedData, withCertificates } from "../../src/page/cms-sign.ts";
import { ATTRIBUTE_SIGNING_TIME, checkSigner, parseSignedData, signingCertificateMatches, signingTime } from "../../src/page/cms.ts";
import { digest } from "../../src/page/gost.ts";
import { parseCertificate, pemToDer, type X509 } from "../../src/page/x509.ts";

const fixture = (name: string) => parseCertificate(pemToDer(readFileSync(join(repoRoot, "tests", "fixtures", name), "utf8")));
const reversed = (bytes: Uint8Array) => Uint8Array.from(bytes).reverse();

// The stand user's certificate with a key of the test's own (the curve of its parameters, gost256B), so that the
// signature can be made here.
function signerWithKey(): { signer: X509; sign: (hash: Uint8Array) => Uint8Array } {
  const base = fixture("stand-user.pem");
  const { secretKey } = gost256B.keygen();
  const point = gost256B.getPublicKey(secretKey, false);
  const der = Uint8Array.from(base.der);
  const at = Buffer.from(der).indexOf(Buffer.from(base.publicKey.subarray(2)));
  der.set([...reversed(point.subarray(1, 33)), ...reversed(point.subarray(33))], at);
  const sign = (hash: Uint8Array) => {
    const rs = gost256B.sign(secretKey, reversed(hash));
    return Uint8Array.from([...rs.subarray(32), ...rs.subarray(0, 32)]);
  };
  return { signer: parseCertificate(der), sign };
}

const DOCUMENT_NAME = "1.3.6.1.4.1.311.88.2.1";

describe("signed attributes", () => {
  it("are CryptoPro's four plus the site's, in DER order, and verify through the page's checks", () => {
    const { signer, sign } = signerWithKey();
    const content = new TextEncoder().encode("Привет");
    const name = attribute(DOCUMENT_NAME, Uint8Array.of(0x04, 4, 0x41, 0, 0, 0));
    const attributes = signedAttributes({ signer, messageDigest: digest("streebog256", content), signingTime: new Date(Date.UTC(2026, 9, 21, 12, 0, 0)), extra: [name] });
    const signature = sign(digest("streebog256", attributes));
    const cms = signedData({ signer, signedAttributes: attributes, signature, content, certificates: [signer] });
    const parsed = parseSignedData(cms);
    expect(parsed.content).toEqual(content);
    const info = parsed.signers[0]!;
    expect([...info.signedAttributes.keys()].sort()).toEqual(["1.2.840.113549.1.9.16.2.47", "1.2.840.113549.1.9.3", "1.2.840.113549.1.9.4", "1.2.840.113549.1.9.5", DOCUMENT_NAME].sort());
    // DER's SET OF: in the order of the encodings (here the short name first).
    const encodings = children(read(attributes)).map((element) => Buffer.from(element.der));
    expect(encodings).toEqual([...encodings].sort(Buffer.compare));
    expect(signingTime(info)).toEqual(new Date(Date.UTC(2026, 9, 21, 12, 0, 0)));
    expect(checkSigner(info, signer, digest("streebog256", content))).toBe("valid");
    expect(signingCertificateMatches(info, signer)).toBe(true);
    expect(info.digestAlgorithm).toBe("1.2.643.7.1.1.2.2");
  });

  it("take the site's signing time in place of their own", () => {
    const { signer } = signerWithKey();
    const site = attribute(ATTRIBUTE_SIGNING_TIME, encodeTime(new Date(Date.UTC(2030, 0, 1))));
    const set = read(signedAttributes({ signer, messageDigest: new Uint8Array(32), signingTime: new Date(), extra: [site] }));
    const times = children(set).filter((element) => decodeOid(children(element)[0]!.value) === ATTRIBUTE_SIGNING_TIME);
    expect(times).toHaveLength(1);
    expect(times[0]!.der).toEqual(site);
  });

  it("write UTCTime through 2049 and GeneralizedTime after", () => {
    expect(new TextDecoder().decode(read(encodeTime(new Date(Date.UTC(2026, 9, 21, 7, 8, 9, 500)))).value)).toBe("261021070809Z");
    expect(read(encodeTime(new Date(Date.UTC(2050, 0, 1)))).tag).toBe(0x18);
  });
});

describe("certificates of a signature", () => {
  it("are added after the ones it carries, once each, the rest of it unchanged", () => {
    const { signer, sign } = signerWithKey();
    const ca = fixture("stand-ca.pem");
    const attributes = signedAttributes({ signer, messageDigest: new Uint8Array(32), signingTime: new Date(), extra: [] });
    const cms = signedData({ signer, signedAttributes: attributes, signature: sign(digest("streebog256", attributes)), certificates: [signer] });
    const more = withCertificates(cms, [signer, ca]);
    const parsed = parseSignedData(more);
    expect(parsed.certificates.map((certificate) => certificate.thumbprint)).toEqual([signer.thumbprint, ca.thumbprint]);
    expect(parsed.signers).toEqual(parseSignedData(cms).signers);
    expect(withCertificates(more, [ca])).toEqual(more);
  });

  it("make a certificates field where a signature had none", () => {
    const { signer, sign } = signerWithKey();
    const attributes = signedAttributes({ signer, messageDigest: new Uint8Array(32), signingTime: new Date(), extra: [] });
    const cms = signedData({ signer, signedAttributes: attributes, signature: sign(digest("streebog256", attributes)), certificates: [] });
    expect(parseSignedData(cms).certificates).toEqual([]);
    expect(parseSignedData(withCertificates(cms, [signer])).certificates.map((certificate) => certificate.thumbprint)).toEqual([signer.thumbprint]);
  });
});
