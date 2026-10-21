// Certificate's CAPICOM methods (docs/PLAN.md, action 35d): GetInfo, KeyUsage, ExtendedKeyUsage, BasicConstraints,
// Extensions, Display, PublicKey's encodings, and the Find criteria by root, template, extension and policies. The
// stand's certificates, and one made here with the extensions they lack (its signature is not looked at).
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { repoRoot } from "../../scripts/fetch-vendor.ts";
import { encode, encodeOid } from "../../src/page/asn1.ts";
import { constants } from "../../src/page/constants.ts";
import type { Certificate, Certificates } from "../../src/page/objects/certificate.ts";
import { createObject } from "../../src/page/objects/index.ts";
import type { Session } from "../../src/page/objects/session.ts";
import type { Store } from "../../src/page/objects/store.ts";
import { derToBase64, parseCertificate, pemToDer } from "../../src/page/x509.ts";
import { fakePlugin, FakePinDialog, fakeSession } from "./fakes.ts";

const fixture = (name: string) => readFileSync(join(repoRoot, "tests", "fixtures", name), "utf8");
const standCa = parseCertificate(pemToDer(fixture("stand-ca.pem")));

const seq = (...parts: Uint8Array[]) => encode(0x30, ...parts);
const oid = (dotted: string) => encode(0x06, encodeOid(dotted));
const text = (tag: number, value: string) => encode(tag, tag === 0x1e ? Uint8Array.from(Buffer.from(value, "utf16le").swap16()) : new TextEncoder().encode(value));
const extension = (id: string, critical: boolean, value: Uint8Array) => seq(oid(id), ...(critical ? [encode(0x01, Uint8Array.of(0xff))] : []), encode(0x04, value));
const name = (...pairs: [string, string][]) => seq(...pairs.map(([id, value]) => encode(0x31, seq(oid(id), text(0x0c, value)))));

// The stand CA's own certificate taken apart for its key and dates, with another subject and these extensions.
function certificate(subject: Uint8Array, extensions: Uint8Array[]): string {
  const tbs = seq(
    encode(0xa0, encode(0x02, Uint8Array.of(2))),
    encode(0x02, Uint8Array.of(0x01, 0x23)),
    seq(oid("1.2.643.7.1.1.3.2")),
    standCa.subjectDer,
    seq(encode(0x17, new TextEncoder().encode("260101000000Z")), encode(0x17, new TextEncoder().encode("360101000000Z"))),
    subject,
    seq(standCa.publicKeyAlgorithmDer, encode(0x03, Uint8Array.of(0, ...standCa.publicKey))),
    encode(0xa3, seq(...extensions)),
  );
  return derToBase64(seq(tbs, seq(oid("1.2.643.7.1.1.3.2")), encode(0x03, new Uint8Array(65))));
}

const rich = certificate(name(["2.5.4.6", "RU"], ["2.5.4.10", "Организация"], ["2.5.4.3", "Иванов"]), [
  extension(
    "2.5.29.17",
    false,
    seq(
      encode(0xa0, oid("1.3.6.1.4.1.311.20.2.3"), encode(0xa0, text(0x0c, "ivanov@corp.example"))),
      encode(0x81, new TextEncoder().encode("ivanov@example.ru")),
      encode(0x82, new TextEncoder().encode("ivanov.example.ru")),
    ),
  ),
  extension("2.5.29.37", true, seq(oid("1.3.6.1.5.5.7.3.2"), oid("1.2.643.2.2.34.6"))),
  extension("2.5.29.19", true, seq(encode(0x01, Uint8Array.of(0xff)), encode(0x02, Uint8Array.of(0)))),
  extension("2.5.29.32", false, seq(seq(oid("1.2.643.100.113.1")), seq(oid("1.2.643.100.113.2")))),
  extension("1.3.6.1.4.1.311.21.10", false, seq(seq(oid("1.3.6.1.5.5.7.3.4")))),
  extension("1.3.6.1.4.1.311.20.2", false, text(0x1e, "User")),
  extension("1.3.6.1.4.1.311.21.7", false, seq(oid("1.3.6.1.4.1.311.21.8.1.2.3"), encode(0x02, Uint8Array.of(100)))),
]);

// Only an organizational unit and an e-mail in the name, no alternative names.
const plain = certificate(name(["2.5.4.11", "Отдел"], ["1.2.840.113549.1.9.1", "box@example.ru"]), []);

async function imported(session: Session, base64: string): Promise<Certificate> {
  const result = createObject("CAdESCOM.Certificate", session) as Certificate;
  await result.Import(base64);
  return result;
}

function setup() {
  const shown: [string, string][][] = [];
  const session = fakeSession(fakePlugin(), new FakePinDialog([]), [standCa], [], { shown });
  return { session, shown };
}

describe("GetInfo", () => {
  it("gives the subject's and the issuer's simple name, e-mail, UPN and DNS name by CertGetNameString's rules", async () => {
    const { session } = setup();
    const certificate = await imported(session, rich);
    const info = await Promise.all([0, 1, 2, 3, 4, 5, 6, 7].map((type) => certificate.GetInfo(type)));
    expect(info).toEqual(["Иванов", "Stand Test CA", "ivanov@example.ru", "", "ivanov@corp.example", "", "ivanov.example.ru", "Stand Test CA"]);
    const other = await imported(session, plain);
    expect(await Promise.all([0, 2, 4, 6].map((type) => other.GetInfo(type)))).toEqual(["Отдел", "box@example.ru", "", ""]);
    await expect(certificate.GetInfo(8)).rejects.toMatchObject({ number: 0x80070057 });
  });
});

describe("the extensions' objects", () => {
  it("KeyUsage and ExtendedKeyUsage of the stand's user certificate", async () => {
    const { session } = setup();
    const store = createObject("CAdESCOM.Store", session) as Store;
    await store.Open();
    const user = await (await (store.Certificates as Promise<Certificates>)).Item(1);
    const usage = await user.KeyUsage();
    expect([await usage.IsPresent, await usage.IsCritical, await usage.IsDigitalSignatureEnabled, await usage.IsNonRepudiationEnabled, await usage.IsKeyCertSignEnabled]).toEqual([
      true,
      true,
      true,
      true,
      false,
    ]);
    const eku = await user.ExtendedKeyUsage();
    expect([await eku.IsPresent, await eku.IsCritical]).toEqual([true, false]);
    const ekus = await eku.EKUs;
    expect(await ekus.Count).toBe(2);
    const first = await ekus.Item(1);
    expect([await first.Name, await first.OID]).toEqual([constants.CAPICOM_EKU_CLIENT_AUTH, "1.3.6.1.5.5.7.3.2"]);
    expect(await (await ekus.Item(2)).Name).toBe(4);
    const constraints = await user.BasicConstraints();
    expect([await constraints.IsPresent, await constraints.IsCertificateAuthority]).toEqual([false, false]);
  });

  it("BasicConstraints with a path length, an unknown EKU, and Extensions by index and by OID", async () => {
    const { session } = setup();
    const certificate = await imported(session, rich);
    const constraints = await certificate.BasicConstraints();
    expect(await Promise.all([constraints.IsPresent, constraints.IsCritical, constraints.IsCertificateAuthority, constraints.IsPathLenConstraintPresent, constraints.PathLenConstraint])).toEqual([
      true,
      true,
      true,
      true,
      0,
    ]);
    expect(await (await (await (await certificate.ExtendedKeyUsage()).EKUs).Item(2)).Name).toBe(constants.CAPICOM_EKU_OTHER);
    expect(await (await certificate.KeyUsage()).IsPresent).toBe(false);
    const extensions = await certificate.Extensions();
    expect(await extensions.Count).toBe(7);
    const eku = await extensions.Item(2);
    expect([await (await eku.OID).Value, await (await eku.OID).Name, await eku.IsCritical]).toEqual(["2.5.29.37", 21, true]);
    const policies = await extensions.Item("2.5.29.32");
    expect(await (await policies.EncodedData).Value()).toBe(`${Buffer.from(seq(seq(oid("1.2.643.100.113.1")), seq(oid("1.2.643.100.113.2")))).toString("base64")}\n`);
    await expect((await policies.EncodedData).Format()).rejects.toMatchObject({ number: 0x80004001 });
    await expect(extensions.Item(8)).rejects.toMatchObject({ number: 0x80070057 });
  });

  it("PublicKey's EncodedKey and EncodedParameters are the key and its parameters as the certificate has them", async () => {
    const { session } = setup();
    const key = await (await imported(session, rich)).PublicKey();
    expect(await (await key.EncodedKey).Value()).toBe(`${(Buffer.from(standCa.publicKey).toString("base64").match(/.{1,64}/g) ?? []).join("\n")}\n`);
    expect(Buffer.from((await (await key.EncodedParameters).Value()).replace(/\n/g, ""), "base64")[0]).toBe(0x30);
    expect(await key.Length).toBe(512);
  });

  it("Display shows the certificate's fields in the extension's window", async () => {
    const { session, shown } = setup();
    await (await imported(session, rich)).Display();
    expect(shown).toHaveLength(1);
    expect(Object.fromEntries(shown[0]!)).toMatchObject({ "Кому выдан": "Иванов", "Кем выдан": "Stand Test CA", "Серийный номер": "0123", "Улучшенный ключ": "1.3.6.1.5.5.7.3.2, 1.2.643.2.2.34.6", "Закрытый ключ": "нет" });
  });
});

describe("Certificates.Find", () => {
  async function found(session: Session, type: number, criteria: unknown): Promise<string[]> {
    const certificates = createObject("CAdESCOM.Store", session) as Store;
    await certificates.Open();
    const user = await (await (certificates.Certificates as Promise<Certificates>)).Item(1);
    const all = [user, await imported(session, rich), await imported(session, plain)];
    const { Certificates: Collection } = await import("../../src/page/objects/certificate.ts");
    const result = await new Collection(all).Find(type, criteria);
    const names: string[] = [];
    for (let i = 1; i <= (await result.Count); i++) names.push(await (await result.Item(i)).GetInfo(0));
    return names;
  }

  it("by a piece of the root's name, the chain going through the extension's stores", async () => {
    const { session } = setup();
    expect(await found(session, constants.CAPICOM_CERTIFICATE_FIND_ROOT_NAME, "stand test")).toEqual(["Stand User", "Иванов", "Отдел"]);
    const without = fakeSession(fakePlugin(), new FakePinDialog([]));
    expect(await found(without, constants.CAPICOM_CERTIFICATE_FIND_ROOT_NAME, "Stand")).toEqual([]);
  });

  it("by template name or OID, extension, application policy and certificate policy", async () => {
    const { session } = setup();
    expect(await found(session, constants.CAPICOM_CERTIFICATE_FIND_TEMPLATE_NAME, "user")).toEqual(["Иванов"]);
    expect(await found(session, constants.CAPICOM_CERTIFICATE_FIND_TEMPLATE_NAME, "1.3.6.1.4.1.311.21.8.1.2.3")).toEqual(["Иванов"]);
    expect(await found(session, constants.CAPICOM_CERTIFICATE_FIND_EXTENSION, "2.5.29.37")).toEqual(["Stand User", "Иванов"]);
    expect(await found(session, constants.CAPICOM_CERTIFICATE_FIND_EXTENSION, constants.CAPICOM_OID_KEY_USAGE_EXTENSION)).toEqual(["Stand User"]);
    expect(await found(session, constants.CAPICOM_CERTIFICATE_FIND_APPLICATION_POLICY, "1.3.6.1.5.5.7.3.4")).toEqual(["Stand User", "Иванов"]);
    expect(await found(session, constants.CAPICOM_CERTIFICATE_FIND_CERTIFICATE_POLICY, "1.2.643.100.113.2")).toEqual(["Иванов"]);
    await expect(found(session, constants.CAPICOM_CERTIFICATE_FIND_EXTENSION, "Key Usage")).rejects.toMatchObject({ number: 0x80070057 });
  });
});
