// The keys on a Rutoken as CryptoPro's containers, listed after the token's PIN (docs/PLAN.md, action 25 (e)).
import { describe, expect, it } from "vitest";
import { constants } from "../../src/page/constants.ts";
import { getLastError } from "../../src/page/errors.ts";
import type { Certificate } from "../../src/page/objects/certificate.ts";
import type { Container, ContainerKey, Containers } from "../../src/page/objects/containers.ts";
import type { CspInformation } from "../../src/page/objects/csp-information.ts";
import { createObject } from "../../src/page/objects/index.ts";
import { certId, fakePlugin, FakePinDialog, fakeSession, tokenModel, tokenReader, tokenSerial, userPin, type FakePlugin } from "./fakes.ts";

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
  it("names each key as CryptoPro does, after the token's PIN, and asks it once per page", async () => {
    const { plugin, dialog, information } = setup([userPin]);
    const list: Containers = await information().EnumContainers();
    expect(await list.Count).toBe(2);
    const [first, second] = [await list.ItemByIndex(0), await list.ItemByIndex(1)];
    expect(await first.Name).toBe("ID_key1");
    expect(await first.FQCN).toBe(`\\\\.\\${tokenReader}\\ID_key1`);
    expect(await first.UniqueName).toBe(await first.FQCN);
    expect([await first.Reader, await first.Media]).toEqual([tokenReader, `${tokenModel} ${tokenSerial}`]);
    expect(await second.FQCN).toBe(`\\\\.\\${tokenReader}\\ID_0abc`);
    expect(dialog.requests).toEqual([expect.objectContaining({ action: "просит показать ключи на Рутокене.", confirm: "Показать" })]);
    expect(plugin.calls.logout).toBe(1);

    expect(await (await information().EnumContainers()).Count).toBe(2);
    expect(plugin.calls.login).toEqual([userPin]);
  });

  it("opens one PIN window for listings that come at the same time, and asks again after a cancel", async () => {
    const { dialog, information } = setup([userPin]);
    const [a, b] = await Promise.all([information().EnumContainers(), information().EnumContainers()]);
    expect([await a.Count, await b.Count]).toEqual([2, 2]);
    expect(dialog.requests).toHaveLength(1);

    const cancelled = setup([null, userPin]);
    await cancelled.information().EnumContainers().catch(() => undefined);
    expect(await (await cancelled.information().EnumContainers()).Count).toBe(2);
    expect(cancelled.dialog.requests).toHaveLength(2);
  });

  it("describes each container's key: type, algorithm, fingerprint, certificate and validity", async () => {
    const { information } = setup([userPin]);
    const list = await information().EnumContainers();
    const withCertificate = await keyOf(await list.ItemByIndex(0));
    expect(await withCertificate.Type).toBe(constants.AT_KEYEXCHANGE);
    expect(await withCertificate.KP_ALGID).toBe(0xaa46);
    expect(await withCertificate.KP_FP).toBe("0102030405060708");
    expect(await withCertificate.IsExportable).toBe(false);
    expect(await withCertificate.HasCertificate).toBe(true);
    const certificate: Certificate = await withCertificate.Certificate;
    expect(await certificate.SubjectName).toContain("CN=Stand User");
    expect(getLastError(await withCertificate.ExpirationTime.catch((e: unknown) => e))).toContain("0x80092004");
    const key = await withCertificate.PublicKey;
    expect([await (await key.Algorithm).Value, await key.Length]).toEqual(["1.2.643.7.1.1.1.1", 512]);

    const alone = await keyOf(await list.ItemByIndex(1));
    expect([await alone.Type, await alone.KP_ALGID, await alone.HasCertificate]).toEqual([constants.AT_SIGNATURE, 0x2e3d, false]);
    expect(await alone.ExpirationTime).toBe("2030-01-01T00:00:00.000Z");
    expect(getLastError(await alone.Certificate.catch((e: unknown) => e))).toContain("0x80092004");
    expect(await (await alone.PublicKey).Length).toBe(1024);
  });

  it("finds a container by its FQCN or its name, in any case", async () => {
    const { information } = setup([userPin]);
    const info = information();
    expect(await (await info.ContainerByName(`\\\\.\\${tokenReader}\\ID_key1`)).Name).toBe("ID_key1");
    expect(await (await info.ContainerByName("id_0ABC")).Name).toBe("ID_0abc");
    expect(getLastError(await info.ContainerByName("ID_ffff").catch((e: unknown) => e))).toContain("0x80090016");
  });

  it("refuses the certificate's own key link at once, without the PIN, as the demo page looks it up for the card", async () => {
    const { dialog, information } = setup([]);
    const link = `\\\\.\\Rutoken ${tokenSerial}\\${certId}`;
    expect(getLastError(await information().ContainerByName(link).catch((e: unknown) => e))).toContain("0x80090016");
    expect(dialog.requests).toHaveLength(0);
  });

  it("deletes a container's key and its certificate after the PIN, and lists anew afterwards", async () => {
    const { plugin, dialog, information } = setup([userPin, userPin, userPin]);
    const container = await (await information().EnumContainers()).ItemByIndex(0);
    await container.Delete();
    expect(dialog.requests[1]).toMatchObject({ action: "просит удалить ключ с Рутокена.", confirm: "Удалить" });
    expect(dialog.requests[1]!.details.at(-1)).toBe("Ключ и сертификат удаляются безвозвратно.");
    expect(plugin.calls.deleteKeyPair).toEqual(["ke:y1"]);
    expect(plugin.calls.deleteCertificate).toEqual([certId]);
    await information().EnumContainers();
    expect(dialog.requests).toHaveLength(3);
  });

  it("answers CryptoPro's code for no containers, and the user's cancel as such", async () => {
    const noToken = setup([], fakePlugin(undefined, { enumerateDevices: async () => [] }));
    expect(getLastError(await noToken.information().EnumContainers().catch((e: unknown) => e))).toContain("0x80070103");
    expect(noToken.dialog.requests).toHaveLength(0);

    const empty = fakePlugin(undefined, { enumerateKeys: async () => [] });
    expect(getLastError(await setup([userPin], empty).information().EnumContainers().catch((e: unknown) => e))).toContain("0x80070103");

    const cancelled = setup([null]);
    expect(getLastError(await cancelled.information().EnumContainers().catch((e: unknown) => e))).toContain("0x8010006E");
  });
});
