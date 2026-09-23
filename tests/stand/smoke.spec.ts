// Smoke test of the stand itself: the real Rutoken Plugin, reached through the
// real adapter, sees the fake Rutoken, its provisioned certificate, and signs
// with it; the plugin's own verify() checks the signature and the chain to the
// stand's test CA. Requires `npm run stand` first.
import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { caDir, subjectCommonName } from "../../scripts/provision-token.ts";
import { userPin } from "../../scripts/setup-stand.ts";
import { blankPage, launchStand, loadPluginSource, openStandPage, servePages, type PageServer } from "./harness.ts";
import { verifyCms } from "./verify.ts";
import type { BrowserContext } from "@playwright/test";

let server: PageServer;
let context: BrowserContext;

test.beforeAll(async () => {
  server = await servePages({ "/": blankPage });
  context = await launchStand();
});

test.afterAll(async () => {
  await context?.close();
  await server?.close();
});

test("Rutoken Plugin finds the fake token and signs with its certificate", async () => {
  const page = await openStandPage(context, `${server.url}/`);
  const caPem = readFileSync(join(caDir, "ca.pem"), "utf8");
  const result = await page.evaluate(
    async ({ loadPlugin, pin, caPem }) => {
      const plugin = await (0, eval)(loadPlugin)();
      const devices: number[] = await plugin.enumerateDevices();
      const deviceId = devices[0]!;
      const certs: string[] = await plugin.enumerateCertificates(deviceId, plugin.CERT_CATEGORY_USER);
      const parsed = await plugin.parseCertificate(deviceId, certs[0]);
      await plugin.login(deviceId, pin);
      const data = btoa("Hello World");
      const attached = await plugin.sign(deviceId, certs[0], data, plugin.DATA_FORMAT_BASE64, {
        detached: false,
        addEssCert: true,
        addSignTime: true,
      });
      const detached = await plugin.sign(deviceId, certs[0], data, plugin.DATA_FORMAT_BASE64, {
        detached: true,
        addEssCert: true,
        addSignTime: true,
      });
      const verifyAttached = await plugin.verify(deviceId, attached, { CA: [caPem], verifyCertificate: true });
      const verifyDetached = await plugin.verify(deviceId, detached, {
        data,
        base64: true,
        CA: [caPem],
        verifyCertificate: true,
      });
      // Without the test CA the chain cannot be built: proves verify() really checks the certificate.
      let verifyWithoutCa: unknown;
      try {
        verifyWithoutCa = await plugin.verify(deviceId, attached, { verifyCertificate: true });
      } catch (e) {
        verifyWithoutCa = `error ${(e as Error).message}`;
      }
      await plugin.logout(deviceId);
      return { attached, detached, verifyWithoutCa, version: await plugin.version, devices, certCount: certs.length, subject: JSON.stringify(parsed.subject), verifyAttached, verifyDetached };
    },
    { loadPlugin: loadPluginSource, pin: userPin, caPem },
  );
  expect(result.version).toBe("4.12.3.0");
  expect(result.devices).toHaveLength(1);
  expect(result.certCount).toBe(1);
  expect(result.subject).toContain(subjectCommonName);
  expect(result.verifyAttached).toBe(true);
  expect(result.verifyDetached).toBe(true);
  expect(result.verifyWithoutCa).not.toBe(true);

  // The independent verifier accepts both signatures, and rejects them against other content.
  const content = Buffer.from("Hello World");
  const attached = verifyCms(result.attached);
  expect(attached.checks).toEqual({ message_digest: true, signature: true, certificate_by_ca: true, cades_bes_attributes: true });
  expect(attached.detached).toBe(false);
  expect(verifyCms(result.detached, content).valid).toBe(true);
  expect(verifyCms(result.detached, Buffer.from("Hello World!")).checks.message_digest).toBe(false);
  // Flip one bit of the signature value (the last 64-byte OCTET STRING, in the SignerInfo).
  const tampered = Buffer.from(result.attached, "base64");
  tampered[tampered.lastIndexOf(Buffer.from([0x04, 0x40])) + 10]! ^= 1;
  expect(verifyCms(tampered.toString("base64")).checks.signature).toBe(false);
});
