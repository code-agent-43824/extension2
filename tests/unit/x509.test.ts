import { X509Certificate, createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { repoRoot } from "../../scripts/fetch-vendor.ts";
import { formatName } from "../../src/page/dn.ts";
import { sha1 } from "../../src/page/sha1.ts";
import { parseCertificate, pemToDer } from "../../src/page/x509.ts";

// Copies of a stand certificate and its CA (public data), so the tests do not need the stand.
const userPem = join(repoRoot, "tests", "fixtures", "stand-user.pem");
const caPem = join(repoRoot, "tests", "fixtures", "stand-ca.pem");

describe("sha1", () => {
  it("matches Node's SHA-1 at block-boundary lengths", () => {
    for (const length of [0, 1, 55, 56, 63, 64, 65, 1000]) {
      const data = randomBytes(length);
      expect(Buffer.from(sha1(data)).toString("hex")).toBe(createHash("sha1").update(data).digest("hex"));
    }
  });
});

describe("formatName", () => {
  const name = (...rdns: [string, string][]) => rdns.map(([oid, value]) => [{ oid, value }]);

  it("reverses DER order and uses CryptoAPI and CryptoPro attribute names", () => {
    expect(formatName(name(["2.5.4.6", "RU"], ["1.2.643.100.4", "7710474375"], ["2.5.4.3", "Минцифры России"]))).toBe(
      "CN=Минцифры России, ИНН ЮЛ=7710474375, C=RU",
    );
  });

  it("quotes values with special characters and doubles inner quotes", () => {
    expect(formatName(name(["2.5.4.9", "Пресненская набережная, дом 10"]))).toBe('STREET="Пресненская набережная, дом 10"');
    expect(formatName(name(["2.5.4.10", 'ООО "Рога"']))).toBe('O="ООО ""Рога"""');
    expect(formatName(name(["2.5.4.3", " padded"]))).toBe('CN=" padded"');
  });

  it("writes unknown attribute types as OID.<dotted>", () => {
    expect(formatName(name(["1.2.3.4", "x"]))).toBe("OID.1.2.3.4=x");
  });

  it("joins a multi-valued RDN with +", () => {
    expect(formatName([[{ oid: "2.5.4.3", value: "a" }, { oid: "2.5.4.11", value: "b" }]])).toBe("CN=a + OU=b");
  });
});

describe("parseCertificate on a stand certificate", () => {
  const pem = readFileSync(userPem, "utf8");
  const cert = parseCertificate(pemToDer(pem));
  const node = new X509Certificate(pem);

  it("agrees with Node on thumbprint, serial number and validity", () => {
    expect(cert.thumbprint).toBe(node.fingerprint.replaceAll(":", ""));
    expect(cert.serialNumber).toBe(node.serialNumber.toUpperCase());
    expect(cert.notBefore.getTime()).toBe(new Date(node.validFrom).getTime());
    expect(cert.notAfter.getTime()).toBe(new Date(node.validTo).getTime());
    expect(cert.version).toBe(3);
  });

  it("keeps the subject values and their DER order", () => {
    // Node prints one attribute per line in DER order, escaping , and " with a backslash.
    const values = node.subject.split("\n").map((line) => line.slice(line.indexOf("=") + 1).replace(/\\(.)/g, "$1"));
    expect(cert.subject.map((rdn) => rdn[0]!.value)).toEqual(values);
  });

  it("formats the names as CryptoPro does", () => {
    expect(formatName(cert.subject)).toBe(
      'E=stand@example.com, СНИЛС=00000000000, ИНН=007700000000, CN=Stand User, G=Тест Тестович, SN=Тестов, ' +
        'O="ООО ""Стенд""", STREET="ул. Тестовая, д. 1", L=г. Москва, S=77 Москва, C=RU',
    );
    expect(formatName(cert.issuer)).toBe("CN=Stand Test CA, O=Стенд, C=RU");
  });

  it("reads the GOST key algorithm and the private key usage period", () => {
    expect(cert.publicKeyAlgorithm).toBe("1.2.643.7.1.1.1.1");
    expect(cert.privateKeyNotBefore?.getTime()).toBe(cert.notBefore.getTime());
    expect(cert.privateKeyNotAfter!.getTime() - cert.notBefore.getTime()).toBe(366 * 86400_000);
  });
});

describe("parseCertificate on the stand CA", () => {
  it("has no private key usage period", () => {
    const cert = parseCertificate(pemToDer(readFileSync(caPem, "utf8")));
    expect(cert.privateKeyNotBefore).toBeNull();
    expect(cert.privateKeyNotAfter).toBeNull();
  });
});
