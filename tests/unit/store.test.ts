import { afterEach, describe, expect, it, vi } from "vitest";
import { constants } from "../../src/page/constants.ts";
import type { Certificate, Certificates } from "../../src/page/objects/certificate.ts";
import { createObject } from "../../src/page/objects/index.ts";
import type { Store } from "../../src/page/objects/store.ts";
import type { RutokenPlugin } from "../../src/page/rutoken.ts";
import { certId, fakePlugin, fakeSession, pem } from "./fakes.ts";

async function openStore(plugin: RutokenPlugin, ...args: unknown[]): Promise<Certificates> {
  const store = createObject("CAdESCOM.Store", fakeSession(plugin)) as Store;
  await (store.Open as (...a: unknown[]) => Promise<void>)(...args);
  return store.Certificates;
}

afterEach(() => {
  vi.useRealTimers();
});

describe("CAdESCOM.Store", () => {
  it("lists the token's user certificates in My, with and without arguments, and in the container store", async () => {
    const plugin = fakePlugin();
    for (const args of [[], [constants.CAPICOM_CURRENT_USER_STORE, "My", constants.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED], [constants.CADESCOM_CONTAINER_STORE]]) {
      expect(await (await openStore(plugin, ...args)).Count).toBe(1);
    }
  });

  it("keeps Root and CA empty", async () => {
    expect(await (await openStore(fakePlugin(), constants.CAPICOM_CURRENT_USER_STORE, "Root")).Count).toBe(0);
    expect(await (await openStore(fakePlugin(), constants.CAPICOM_CURRENT_USER_STORE, "CA")).Count).toBe(0);
  });

  it("skips a certificate that does not parse", async () => {
    expect(await (await openStore(fakePlugin([pem, "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"]))).Count).toBe(1);
  });

  it("indexes certificates from 1 and rejects out-of-range indexes", async () => {
    const certs = await openStore(fakePlugin());
    await expect(certs.Item(1)).resolves.toBeDefined();
    await expect(certs.Item(0)).rejects.toThrow("индекс");
    await expect(certs.Item(2)).rejects.toThrow("индекс");
  });
});

describe("CAdESCOM.Certificate", () => {
  async function certificate(): Promise<Certificate> {
    return (await openStore(fakePlugin())).Item(1);
  }

  it("reports what the demo page's certificate card reads", async () => {
    const cert = await certificate();
    expect(await cert.Thumbprint).toBe("CDEA7EAB5BE6B167F22B713BF376E9B28ADB14A3");
    expect(await cert.SerialNumber).toBe("4C348384107C9CE89D96A8855FF9672B");
    expect(await cert.SubjectName).toMatch(/^E=stand@example\.com, .*CN=Stand User, .*C=RU$/);
    expect(await cert.IssuerName).toBe("CN=Stand Test CA, O=Стенд, C=RU");
    expect(await cert.ValidFromDate).toBe("2026-09-22T14:10:24.000Z");
    expect(await cert.ValidToDate).toBe("2028-09-22T14:10:24.000Z");
    expect(await cert.PrivateKeyUsagePeriodFrom).toBe("2026-09-22T14:10:24.000Z");
    expect(await cert.PrivateKeyUsagePeriodTo).toBe("2027-09-23T14:10:24.000Z");
    expect(await cert.HasPrivateKey()).toBe(true);
    expect(await (await (await cert.PublicKey()).Algorithm).FriendlyName).toBe("ГОСТ Р 34.10-2012 256 бит");
    const key = await cert.PrivateKey;
    expect(await key.ProviderName).toBe("Rutoken Plugin 4.12.3.0");
    expect(await key.UniqueContainerName).toBe(`\\\\.\\Rutoken 1669552163\\${certId}`);
  });

  it("is valid only inside its validity period", async () => {
    const cert = await certificate();
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2027-01-01T00:00:00Z"));
    expect(await (await cert.IsValid()).Result).toBe(true);
    vi.setSystemTime(new Date("2029-01-01T00:00:00Z"));
    expect(await (await cert.IsValid()).Result).toBe(false);
  });
});
