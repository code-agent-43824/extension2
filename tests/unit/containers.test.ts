// The keys on a Rutoken as CryptoPro's containers, named and described by their certificates without a PIN
// (docs/PLAN.md, actions 25 (e) and 51).
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { constants } from "../../src/page/constants.ts";
import { getLastError } from "../../src/page/errors.ts";
import type { Certificate } from "../../src/page/objects/certificate.ts";
import type { Container, ContainerKey, Containers } from "../../src/page/objects/containers.ts";
import type { CspInformation } from "../../src/page/objects/csp-information.ts";
import { createObject } from "../../src/page/objects/index.ts";
import { repoRoot } from "../../scripts/fetch-vendor.ts";
import { certId, fakePlugin, FakePinDialog, fakeSession, pem, tokenModel, tokenReader, tokenSerial, userPin, type FakePlugin } from "./fakes.ts";

function setup(answers: (string | null)[], plugin: FakePlugin = fakePlugin()) {
  const dialog = new FakePinDialog(answers);
  const session = fakeSession(plugin, dialog);
  return { plugin, dialog, session, information: () => createObject("X509Enrollment.CCspInformation", session) as CspInformation };
}

async function keyOf(container: Container): Promise<ContainerKey> {
  const keys = await container.Keys;
  expect(await keys.Count).toBe(1);
  return keys.ItemByIndex(0);
}

describe("containers of the keys on a Rutoken", () => {
  const name = "ID_cdea7eab5be6b167f22b713bf376e9b28adb14a3";

  it("names each certificate's container as CryptoPro names a key, with the certificate's thumbprint, without a PIN", async () => {
    const { plugin, dialog, information } = setup([]);
    const list: Containers = await information().EnumContainers();
    expect(await list.Count).toBe(1);
    const first = await list.ItemByIndex(0);
    expect(await first.Name).toBe(name);
    expect(await first.FQCN).toBe(`\\\\.\\${tokenReader}\\${name}`);
    expect(await first.UniqueName).toBe(await first.FQCN);
    expect([await first.Reader, await first.Media]).toEqual([tokenReader, `${tokenModel} ${tokenSerial}`]);
    expect(dialog.requests).toHaveLength(0);
    expect(plugin.calls.login).toEqual([]);
  });

  it("describes each container's key from its certificate: type, algorithm, fingerprint, certificate and validity", async () => {
    const noKeyUsage = readFileSync(join(repoRoot, "tests", "fixtures", "no-key-usage.pem"), "utf8");
    const { information } = setup([], fakePlugin([pem, noKeyUsage]));
    const list = await information().EnumContainers();
    // keyEncipherment and keyAgreement in the certificate: an exchange key.
    const gost = await keyOf(await list.ItemByIndex(0));
    expect(await gost.Type).toBe(constants.AT_KEYEXCHANGE);
    expect(await gost.KP_ALGID).toBe(0xaa46);
    // The first 8 bytes of the point.
    expect(await gost.KP_FP).toBe("ACA34CDC77B88174");
    expect(await gost.IsExportable).toBe(false);
    expect(await gost.HasCertificate).toBe(true);
    const certificate: Certificate = await gost.Certificate;
    expect(await certificate.SubjectName).toContain("CN=Stand User");
    expect(await gost.ExpirationTime).toBe("2027-09-23T14:10:24.000Z");
    const key = await gost.PublicKey;
    expect([await (await key.Algorithm).Value, await key.Length]).toEqual(["1.2.643.7.1.1.1.1", 512]);

    // No key usage extension: nothing forbids exchange; no private key usage period: no date.
    const rsa = await keyOf(await list.ItemByIndex(1));
    expect([await rsa.Type, await rsa.KP_ALGID, await (await rsa.PublicKey).Length]).toEqual([constants.AT_KEYEXCHANGE, 0xa400, 2048]);
    expect(await rsa.KP_FP).toBe("DE9DD7EA571849A1");
    expect(getLastError(await rsa.ExpirationTime.catch((e: unknown) => e))).toContain("0x80092004");
  });

  it("calls a key a signature key when its certificate does not let it encrypt", async () => {
    // The stand CA's: keyCertSign and cRLSign only.
    const signingOnly = readFileSync(join(repoRoot, "tests", "fixtures", "stand-ca.pem"), "utf8");
    const { information } = setup([], fakePlugin([signingOnly]));
    const key = await keyOf(await (await information().EnumContainers()).ItemByIndex(0));
    expect([await key.Type, await key.KP_ALGID]).toEqual([constants.AT_SIGNATURE, 0x2e49]);
  });

  it("finds a container by its FQCN or its name, in any case", async () => {
    const { information } = setup([]);
    const info = information();
    expect(await (await info.ContainerByName(`\\\\.\\${tokenReader}\\${name}`)).Name).toBe(name);
    expect(await (await info.ContainerByName(name.toUpperCase())).Name).toBe(name);
    expect(getLastError(await info.ContainerByName("ID_ffff").catch((e: unknown) => e))).toContain("0x80090016");
  });

  it("refuses the certificate's own key link at once, as the demo page looks it up for the card", async () => {
    const { dialog, information } = setup([]);
    const link = `\\\\.\\Rutoken ${tokenSerial}\\${certId}`;
    expect(getLastError(await information().ContainerByName(link).catch((e: unknown) => e))).toContain("0x80090016");
    expect(dialog.requests).toHaveLength(0);
  });

  it("deletes a container's key, found by its certificate after the PIN, and the certificate", async () => {
    const { plugin, dialog, information } = setup([userPin]);
    const container = await (await information().EnumContainers()).ItemByIndex(0);
    await container.Delete();
    expect(dialog.requests).toEqual([expect.objectContaining({ action: "просит удалить ключ с Рутокена.", confirm: "Удалить" })]);
    expect(dialog.requests[0]!.details[0]).toBe(`Контейнер \\\\.\\${tokenReader}\\${name}.`);
    expect(dialog.requests[0]!.details.at(-1)).toBe("Ключ и сертификат удаляются безвозвратно.");
    expect(plugin.calls.deleteKeyPair).toEqual(["ke:y1"]);
    expect(plugin.calls.deleteCertificate).toEqual([certId]);
    expect([plugin.calls.login, plugin.calls.logout]).toEqual([[userPin], 1]);
  });

  it("deletes the certificate alone when its key is gone", async () => {
    const { plugin, information } = setup([userPin], fakePlugin(undefined, { getKeyByCertificate: async () => Promise.reject(new Error("23")) }));
    await (await (await information().EnumContainers()).ItemByIndex(0)).Delete();
    expect(plugin.calls.deleteKeyPair).toEqual([]);
    expect(plugin.calls.deleteCertificate).toEqual([certId]);
  });

  it("answers CryptoPro's code for no containers", async () => {
    const noToken = setup([], fakePlugin(undefined, { enumerateDevices: async () => [] }));
    expect(getLastError(await noToken.information().EnumContainers().catch((e: unknown) => e))).toContain("0x80070103");
    expect(getLastError(await setup([], fakePlugin([])).information().EnumContainers().catch((e: unknown) => e))).toContain("0x80070103");
  });
});
