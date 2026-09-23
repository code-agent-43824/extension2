// Puts a GOST R 34.10-2012/256 key and a certificate for it on the stand's fake
// Rutoken, going through the real Rutoken Plugin: the plugin generates the key
// and the PKCS #10 request, the independent test CA (tests/tools/gost_ca.py)
// issues the certificate, and the plugin imports it as a user certificate.
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { blankPage, launchStand, loadPluginSource, openStandPage, servePages } from "../tests/stand/harness.ts";
import { repoRoot } from "./fetch-vendor.ts";
import { standDir, userPin, venvPython } from "./setup-stand.ts";

export const caDir = join(standDir, "ca");
export const subjectCommonName = "Stand User";

// The subject of a qualified certificate in the usual DER order, with Cyrillic, a comma and quotes
// in values: enough to exercise how the shim formats SubjectName.
export const subjectAttributes = [
  { rdn: "countryName", value: "RU" },
  { rdn: "stateOrProvinceName", value: "77 Москва" },
  { rdn: "localityName", value: "г. Москва" },
  { rdn: "streetAddress", value: "ул. Тестовая, д. 1" },
  { rdn: "organizationName", value: 'ООО "Стенд"' },
  { rdn: "surname", value: "Тестов" },
  { rdn: "givenName", value: "Тест Тестович" },
  { rdn: "commonName", value: subjectCommonName },
  { rdn: "INN", value: "007700000000" },
  { rdn: "SNILS", value: "00000000000" },
  { rdn: "emailAddress", value: "stand@example.com" },
];

export async function provisionToken(): Promise<void> {
  const server = await servePages({ "/": blankPage });
  const context = await launchStand();
  try {
    const page = await openStandPage(context, `${server.url}/`);
    const { deviceId, csr } = await page.evaluate(
      async ({ loadPlugin, pin, subject }) => {
        const plugin = await (0, eval)(loadPlugin)();
        const [deviceId] = await plugin.enumerateDevices();
        await plugin.login(deviceId, pin);
        const keyId = await plugin.generateKeyPair(deviceId, undefined, "", {
          publicKeyAlgorithm: plugin.PUBLIC_KEY_ALGORITHM_GOST3410_2012_256,
          signatureSize: 512,
          keySpec: plugin.KEY_SPEC_SIGN_AND_EXCHANGE,
        });
        const csr = await plugin.createPkcs10(
          deviceId,
          keyId,
          subject,
          { keyUsage: ["digitalSignature", "nonRepudiation"], extKeyUsage: ["clientAuth", "emailProtection"] },
          { hashAlgorithm: plugin.HASH_TYPE_GOST3411_12_256 },
        );
        return { deviceId, csr };
      },
      { loadPlugin: loadPluginSource, pin: userPin, subject: subjectAttributes },
    );

    const csrPath = join(standDir, "user.csr.pem");
    const certPath = join(standDir, "user.pem");
    writeFileSync(csrPath, csr);
    execFileSync(venvPython, [join(repoRoot, "tests", "tools", "gost_ca.py"), "issue", caDir, csrPath, certPath]);
    const certificate = readFileSync(certPath, "utf8");

    await page.evaluate(
      async ({ loadPlugin, pin, deviceId, certificate }) => {
        const plugin = await (0, eval)(loadPlugin)();
        await plugin.login(deviceId, pin);
        await plugin.importCertificate(deviceId, certificate, plugin.CERT_CATEGORY_USER);
        await plugin.logout(deviceId);
      },
      { loadPlugin: loadPluginSource, pin: userPin, deviceId, certificate },
    );
  } finally {
    await context.close();
    await server.close();
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await provisionToken();
  console.log("token provisioned");
}
