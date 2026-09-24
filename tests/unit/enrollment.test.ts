import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { repoRoot } from "../../scripts/fetch-vendor.ts";
import { parseNameString } from "../../src/page/dn.ts";
import { endEntity, offeredRoot, responseCertificates } from "../../src/page/objects/enrollment.ts";
import { isCertificateLink, offerInFile } from "../../src/page/root-links.ts";
import { createObject } from "../../src/page/objects/index.ts";
import type { Session } from "../../src/page/objects/session.ts";
import type { RutokenPlugin } from "../../src/page/rutoken.ts";
import { fakePlugin, FakePinDialog, fakeSession, pem, requestPem, userPin, type FakeStores } from "./fakes.ts";

// A CMC response of testgost2012.cryptopro.ru's certsrv (certfnsh.asp): the issued certificate and the CA's.
const response = readFileSync(join(repoRoot, "tests", "fixtures", "testgost-response.b64"), "utf8");

type Obj = Record<string, (...args: unknown[]) => Promise<unknown>> & Record<string, Promise<unknown>>;
const create = (name: string, session: Session) => createObject(name, session) as Obj;

function setup(answers: (string | null)[] = [userPin], overrides: Partial<RutokenPlugin> = {}) {
  const plugin = fakePlugin([pem], overrides);
  const dialog = new FakePinDialog(answers);
  return { plugin, dialog, session: fakeSession(plugin, dialog) };
}

// The calls certrqma.asp makes (async_code.js), with its default form: the type-80 provider, key
// usage "both", client-auth + e-mail EKUs, the first hash in the list.
async function requestLikeTestgost(session: Session, providerIndex = 0, keySpec = 1): Promise<string> {
  const csps = create("X509Enrollment.CCspInformations", session);
  await csps.AddAvailableCsps();
  const csp = (await csps.ItemByIndex(providerIndex)) as Obj;
  const name = (await csp.Name) as string;
  const key = create("X509Enrollment.CX509PrivateKey", session);
  await key.propset_ProviderName(name);
  await key.propset_ProviderType(await csp.Type);
  const status = (await csps.GetCspStatusFromProviderName(name, keySpec)) as Obj;
  const length = await ((await status.CspAlgorithm) as Obj).DefaultLength;
  const algorithms = (await ((await csps.ItemByName(name)) as Obj).CspAlgorithms) as Obj;
  let hashOid = "";
  for (let i = 0; i < ((await algorithms.Count) as number); i++) {
    const algorithm = (await algorithms.ItemByIndex(i)) as Obj;
    if ((await algorithm.Type) === 2 && !hashOid) hashOid = (await ((await algorithm.GetAlgorithmOid(0, 0)) as Obj).Value) as string;
  }

  const request = create("X509Enrollment.CX509CertificateRequestPkcs10", session);
  await key.propset_KeySpec(keySpec);
  await key.propset_KeyProtection(0);
  await key.propset_ExportPolicy(0);
  await key.propset_Length(length);
  await key.propset_MachineContext(false);
  await request.InitializeFromPrivateKey(1, key, "");
  const keyUsage = create("X509Enrollment.CX509ExtensionKeyUsage", session);
  await keyUsage.InitializeEncode(keySpec === 2 ? 0xc0 : 0xf0);
  await ((await request.X509Extensions) as Obj).Add(keyUsage);
  const dn = create("X509Enrollment.CX500DistinguishedName", session);
  await dn.Encode('C="RU";S="77 Москва";L="Москва";O="ООО ""Ромашка""";OU="";CN="Иван Петров";E="ivan@example.ru";', 2097152);
  await request.propset_Subject(dn);
  const ids = create("X509Enrollment.CObjectIds", session);
  for (const oid of ["1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.4"]) {
    const id = create("X509Enrollment.CObjectId", session);
    await id.InitializeFromValue(oid);
    await ids.Add(id);
  }
  const eku = create("X509Enrollment.CX509ExtensionEnhancedKeyUsage", session);
  await eku.InitializeEncode(ids);
  await ((await request.X509Extensions) as Obj).Add(eku);
  const hash = create("X509Enrollment.CObjectId", session);
  await hash.InitializeFromValue(hashOid);
  await request.propset_HashAlgorithm(hash);
  const enroll = create("X509Enrollment.CX509Enrollment", session);
  await enroll.InitializeFromRequest(request);
  return (await enroll.CreateRequest(3)) as string;
}

// certfnsh.asp's Install(): a fresh CX509Enrollment, Initialize(ContextUser), InstallResponse.
async function installLikeTestgost(session: Session, text = response): Promise<void> {
  const enroll = create("X509Enrollment.CX509Enrollment", session);
  await enroll.Initialize(1);
  await enroll.InstallResponse(4, text, 7, "");
}

describe("certificate request (certrqma.asp)", () => {
  it("lists a 256-bit and a 512-bit provider named after About.CSPName", async () => {
    const { session } = setup();
    const csps = create("X509Enrollment.CCspInformations", session);
    await csps.AddAvailableCsps();
    expect(await csps.Count).toBe(2);
    const items = [(await csps.ItemByIndex(0)) as Obj, (await csps.ItemByIndex(1)) as Obj];
    expect(await Promise.all(items.map((item) => item.Name))).toEqual(["Rutoken Plugin 4.12.3.0", "Rutoken Plugin 4.12.3.0 (ГОСТ Р 34.10-2012 512 бит)"]);
    expect(await Promise.all(items.map((item) => item.Type))).toEqual([80, 81]);
    expect(await items[0]!.LegacyCsp).toBe(true);
    await expect(csps.ItemByName("Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider")).rejects.toThrow("0x80092004");
  });

  it("creates the key and the request on the token after the PIN", async () => {
    const { plugin, dialog, session } = setup();
    const text = await requestLikeTestgost(session);
    expect(text).toBe("-----BEGIN NEW CERTIFICATE REQUEST-----\r\nMIIBAA==\r\n-----END NEW CERTIFICATE REQUEST-----\r\n");
    expect(plugin.calls.login).toEqual([userPin]);
    expect(plugin.calls.generateKeyPair).toEqual([[0, undefined, "", { publicKeyAlgorithm: 3, signatureSize: 512, keySpec: 8 }]]);
    expect(plugin.calls.createPkcs10).toEqual([
      [
        0,
        "ke:y1",
        [
          { rdn: "countryName", value: "RU" },
          { rdn: "stateOrProvinceName", value: "77 Москва" },
          { rdn: "localityName", value: "Москва" },
          { rdn: "organizationName", value: 'ООО "Ромашка"' },
          { rdn: "organizationalUnitName", value: "" },
          { rdn: "commonName", value: "Иван Петров" },
          { rdn: "emailAddress", value: "ivan@example.ru" },
        ],
        {
          keyUsage: ["digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment"],
          extKeyUsage: ["1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.4"],
        },
        { hashAlgorithm: 5 },
      ],
    ]);
    expect(plugin.calls.logout).toBe(1);
    expect(dialog.requests).toEqual([
      {
        origin: "https://site.example",
        action: "просит создать на Рутокене ключ и запрос на сертификат.",
        details: ["Владелец: Иван Петров", "Ключ: ГОСТ Р 34.10-2012 256 бит", "Рутокен 1669552163"],
        confirm: "Создать",
      },
    ]);
  });

  it("makes a 512-bit signature-only key for the second provider", async () => {
    const { plugin, session } = setup();
    await requestLikeTestgost(session, 1, 2);
    expect(plugin.calls.generateKeyPair[0]![3]).toEqual({ publicKeyAlgorithm: 4, signatureSize: 1024, keySpec: 7 });
    expect(plugin.calls.createPkcs10[0]![3]).toEqual({ keyUsage: ["digitalSignature", "nonRepudiation"], extKeyUsage: ["1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.4"] });
    expect(plugin.calls.createPkcs10[0]![4]).toEqual({ hashAlgorithm: 6 });
  });

  it("removes the new key when the request fails", async () => {
    const { plugin, session } = setup([userPin], {
      createPkcs10: async () => {
        throw new Error("2");
      },
    });
    await expect(requestLikeTestgost(session)).rejects.toThrow("2");
    expect(plugin.calls.deleteKeyPair).toEqual(["ke:y1"]);
    expect(plugin.calls.logout).toBe(1);
  });

  it("creates nothing when the user cancels the PIN window", async () => {
    const { plugin, session } = setup([null]);
    await expect(requestLikeTestgost(session)).rejects.toThrow("(0x8010006E)");
    expect(plugin.calls.generateKeyPair).toEqual([]);
  });

  it("refuses to reuse an existing key or to create one for the machine", async () => {
    const { session } = setup();
    const csps = create("X509Enrollment.CCspInformations", session);
    await csps.AddAvailableCsps();
    const key = create("X509Enrollment.CX509PrivateKey", session);
    await key.propset_ProviderName(await ((await csps.ItemByIndex(0)) as Obj).Name);
    const request = create("X509Enrollment.CX509CertificateRequestPkcs10", session);
    await expect(request.InitializeFromPrivateKey(2, key, "")).rejects.toThrow("0x80004001");
    await key.propset_Existing(true);
    await expect(request.InitializeFromPrivateKey(1, key, "")).rejects.toThrow("0x80004001");
    expect(await key.Existing).toBe(true);
  });

  it("asks for one token when several are connected", async () => {
    const { plugin, session } = setup([userPin], { enumerateDevices: async () => [0, 1] });
    await expect(requestLikeTestgost(session)).rejects.toThrow("несколько Рутокенов");
    expect(plugin.calls.login).toEqual([]);
  });
});

describe("certificate install (certfnsh.asp)", () => {
  it("finds the user's certificate in the CA's CMC response", () => {
    const certificates = responseCertificates(response);
    expect(certificates).toHaveLength(2);
    expect(endEntity(certificates)?.subject).toEqual([[{ oid: "2.5.4.11", value: "Отдел" }], [{ oid: "2.5.4.3", value: "Probe" }]]);
  });

  it("writes only the user's certificate, after the PIN, and checks its key is there", async () => {
    const { plugin, dialog, session } = setup();
    await installLikeTestgost(session);
    expect(plugin.calls.importCertificate).toHaveLength(1);
    expect(plugin.calls.importCertificate[0]).toMatch(/^-----BEGIN CERTIFICATE-----\n/);
    expect(plugin.calls.deleteCertificate).toEqual([]);
    expect(plugin.calls.logout).toBe(1);
    expect(dialog.requests[0]).toMatchObject({ action: "просит записать сертификат на Рутокен.", confirm: "Записать" });
    expect(dialog.requests[0]!.details[0]).toBe("Сертификат: Probe");
  });

  it("takes the certificate back off when the token has no key for it", async () => {
    const { plugin, session } = setup([userPin], {
      getKeyByCertificate: async () => {
        throw new Error("20");
      },
    });
    const failed = installLikeTestgost(session);
    await expect(failed).rejects.toThrow("(0x80092004)");
    expect(plugin.calls.deleteCertificate).toEqual(["ne:w1"]);
  });

  it("accepts a certificate that is already on the token", async () => {
    const { plugin, session } = setup([userPin], {
      importCertificate: async () => {
        throw new Error("6");
      },
    });
    await installLikeTestgost(session);
    expect(plugin.calls.logout).toBe(1);
  });

  it("accepts a single certificate in PEM", async () => {
    const { plugin, session } = setup();
    await installLikeTestgost(session, pem);
    expect(plugin.calls.importCertificate).toHaveLength(1);
  });
});

describe("X.500 name strings", () => {
  it("parse quoted and bare values, semicolons and commas, OIDs", () => {
    expect(parseNameString('CN="a;b", O=Org, OID.1.2.643.100.1=123;1.2.3.4="x""y"')).toEqual([
      { oid: "2.5.4.3", value: "a;b" },
      { oid: "2.5.4.10", value: "Org" },
      { oid: "1.2.643.100.1", value: "123" },
      { oid: "1.2.3.4", value: 'x"y' },
    ]);
    expect(parseNameString("ИНН=001234567890;SNILS=12345678901")).toEqual([
      { oid: "1.2.643.3.131.1.1", value: "001234567890" },
      { oid: "1.2.643.100.3", value: "12345678901" },
    ]);
    expect(() => parseNameString("XX=1")).toThrow("XX");
    expect(() => parseNameString('CN="open')).toThrow("кавычка");
  });
});

// The options page's "Предлагать установить корневой сертификат при установке сертификата" (docs/PLAN.md, action 22).
describe("the root offer when installing (certfnsh.asp)", () => {
  const certificates = responseCertificates(response);
  const user = endEntity(certificates)!;
  const root = certificates.find((certificate) => certificate !== user)!;

  function withStores(stores: FakeStores, roots: typeof certificates = [], overrides: Partial<RutokenPlugin> = {}) {
    const plugin = fakePlugin([pem], overrides);
    return { plugin, session: fakeSession(plugin, new FakePinDialog([userPin]), roots, [], stores) };
  }

  it("offers the response's root when the stores do not trust it", () => {
    expect(offeredRoot(user, certificates, [], [])).toEqual({ root, intermediates: [] });
    expect(offeredRoot(user, certificates, [root], [])).toBeUndefined();
    // Without the root in the response there is nothing to offer.
    expect(offeredRoot(user, [user], [], [])).toBeUndefined();
  });

  it("answers CERT_E_UNTRUSTEDROOT after writing the certificate, leaving the root to the page's link", async () => {
    const stores: FakeStores = { offerRoot: true, added: [], offered: [] };
    const { plugin, session } = withStores(stores);
    await expect(installLikeTestgost(session)).rejects.toThrow("(0x800B0109)");
    expect(plugin.calls.importCertificate).toHaveLength(1);
    expect(plugin.calls.deleteCertificate).toEqual([]);
    // Nothing is added until the user clicks the link.
    expect(stores.added).toEqual([]);
    expect(stores.offered).toEqual([{ root, intermediates: [] }]);
  });

  it("installs quietly when the root is trusted, the switch is off or the certificate is not written", async () => {
    const trusted: FakeStores["offered"] = [];
    await installLikeTestgost(withStores({ offerRoot: true, offered: trusted }, [root]).session);
    const off: FakeStores["offered"] = [];
    await installLikeTestgost(withStores({ offerRoot: false, offered: off }).session);
    const noKey: FakeStores["offered"] = [];
    const failed = installLikeTestgost(
      withStores({ offerRoot: true, offered: noKey }, [], {
        getKeyByCertificate: async () => {
          throw new Error("20");
        },
      }).session,
    );
    await expect(failed).rejects.toThrow("(0x80092004)");
    expect([trusted, off, noKey]).toEqual([[], [], []]);
  });
});

describe("the CA page's link to the root", () => {
  const certificates = responseCertificates(response);
  const user = endEntity(certificates)!;
  const root = certificates.find((certificate) => certificate !== user)!;
  const offer = { root, intermediates: [] };

  it("finds the offered root in the file in any of its forms, and only that root", () => {
    const pemText = `-----BEGIN CERTIFICATE-----\r\n${Buffer.from(root.der).toString("base64").replace(/.{64}/g, "$&\r\n")}\r\n-----END CERTIFICATE-----\r\n`;
    expect(offerInFile(new TextEncoder().encode(pemText), [offer])).toBe(offer);
    expect(offerInFile(root.der, [offer])).toBe(offer);
    expect(offerInFile(Buffer.from(response, "base64"), [offer])).toBe(offer);
    expect(offerInFile(user.der, [offer])).toBeUndefined();
    expect(offerInFile(new TextEncoder().encode("<html>not a certificate</html>"), [offer])).toBeUndefined();
  });

  it("takes links to certificate files only", () => {
    expect(isCertificateLink(new URL("https://ca.example/certsrv/certnew.cer?ReqID=CACert&Renewal=21&Mode=inst&Enc=b64"))).toBe(true);
    expect(isCertificateLink(new URL("https://ca.example/root.CRT"))).toBe(true);
    expect(isCertificateLink(new URL("https://ca.example/certsrv/certrmpn.asp"))).toBe(false);
    expect(isCertificateLink(new URL("javascript:void(0)"))).toBe(false);
  });
});
