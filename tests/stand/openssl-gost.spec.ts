// Opt-in experiment:
// STAND_OPENSSL_GOST=1 npx playwright test tests/stand/openssl-gost.spec.ts
// (needs OpenSSL's GOST engine: apt install libengine-gost-openssl). CPEnvelopedData's CMS checked against an
// implementation that shares no code with the Rutoken Plugin: the extension encrypts for the stand CA's
// certificate, whose key is in software, and OpenSSL decrypts; OpenSSL encrypts for the token's certificate and the
// extension decrypts. Messages shorter than one CTR-ACPKM section: on longer ones OpenSSL's engine 3.0.2 changes the
// key where the Rutoken Plugin does not (docs/JOURNAL.md, 2026-10-08).
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { caDir } from "../../scripts/provision-token.ts";
import { stand, standDir } from "../../scripts/setup-stand.ts";
import { blankPage, clearSites, enableSite, launchStand, openStandPage, servePages, standExtension, type PageServer } from "./harness.ts";
import { enterPin, pinDialog } from "./testgost-certs.ts";
import { standCaKeyPem } from "./verify.ts";

test.skip(!process.env.STAND_OPENSSL_GOST, "needs OpenSSL's GOST engine: set STAND_OPENSSL_GOST=1");

const text = "Сообщение для проверки шифрования.";
// CryptoPro's names for the algorithms, and OpenSSL's for the same ciphers.
const ciphers = [
  [25, "gost89"],
  [35, "magma-ctr-acpkm"],
  [36, "magma-ctr-acpkm-omac"],
  [45, "kuznyechik-ctr-acpkm"],
  [46, "kuznyechik-ctr-acpkm-omac"],
] as const;

let server: PageServer;
let context: BrowserContext;
let page: Page;
let dir: string;

function openssl(args: string[], input?: Buffer): Buffer {
  const run = spawnSync("openssl", ["cms", "-engine", "gost", ...args], { input });
  if (run.status !== 0) throw new Error(`openssl cms ${args.join(" ")}: ${run.stderr.toString()}`);
  return run.stdout;
}

test.beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "openssl-gost-"));
  writeFileSync(join(dir, "ca-key.pem"), standCaKeyPem());
  server = await servePages({ "/": blankPage });
  context = await launchStand({ extensions: [stand.adapter, standExtension()] });
  await clearSites(context);
  await enableSite(context, server.url);
  page = await openStandPage(context, `${server.url}/`);
});

test.afterAll(async () => {
  await context?.close();
  await server?.close();
  if (dir) rmSync(dir, { recursive: true, force: true });
});

// Runs CPEnvelopedData in the page, answering the PIN window it opens.
async function withPin<T>(run: () => Promise<T>): Promise<T> {
  const result = run();
  await expect(pinDialog(page)).toBeVisible({ timeout: 30_000 });
  await enterPin(page);
  return result;
}

for (const [algorithm, name] of ciphers) {
  test(`OpenSSL decrypts what the extension encrypts with ${name}`, async () => {
    const caPem = readFileSync(join(caDir, "ca.pem"), "utf8");
    const message = await withPin(() =>
      page.evaluate(
        async ({ caPem, algorithm, content }) => {
          const plugin = (window as unknown as { cadesplugin: Promise<void> & { CreateObjectAsync(name: string): Promise<any> } }).cadesplugin;
          await plugin;
          const certificate = await plugin.CreateObjectAsync("CAdESCOM.Certificate");
          await certificate.Import(caPem);
          const data = await plugin.CreateObjectAsync("CAdESCOM.CPEnvelopedData");
          await (await data.Algorithm).propset_Name(algorithm);
          await (await data.Recipients).Add(certificate);
          await data.propset_ContentEncoding(1);
          await data.propset_Content(content);
          return (await data.Encrypt(0)) as string;
        },
        { caPem, algorithm, content: Buffer.from(text).toString("base64") },
      ),
    );
    const decrypted = openssl(["-decrypt", "-inform", "DER", "-inkey", join(dir, "ca-key.pem"), "-recip", join(caDir, "ca.pem")], Buffer.from(message.replace(/\s+/g, ""), "base64"));
    expect(decrypted.toString()).toBe(text);
  });

  // The fake token answers cmsDecrypt of GOST 28147-89 with error 147 (docs/JOURNAL.md, 2026-10-08).
  if (name === "gost89") continue;
  test(`the extension decrypts what OpenSSL encrypts with ${name}`, async () => {
    const message = openssl(["-encrypt", "-binary", `-${name}`, "-outform", "DER", join(standDir, "user.pem")], Buffer.from(text));
    const decrypted = await withPin(() =>
      page.evaluate(async (message) => {
        const plugin = (window as unknown as { cadesplugin: Promise<void> & { CreateObjectAsync(name: string): Promise<any> } }).cadesplugin;
        await plugin;
        const data = await plugin.CreateObjectAsync("CAdESCOM.CPEnvelopedData");
        await data.propset_ContentEncoding(1);
        await data.Decrypt(message);
        return (await data.Content) as string;
      }, message.toString("base64")),
    );
    expect(Buffer.from(decrypted, "base64").toString()).toBe(text);
  });
}
