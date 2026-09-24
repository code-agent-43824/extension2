// Installing a certificate from a CA page, offline (docs/PLAN.md, action 22): the calls certrqma.asp and
// certfnsh.asp of CryptoPro's test CA make, with the stand's CA issuing the certificate. Its root is in none of
// the extension's stores, so with the root switch on (the default) InstallResponse writes the certificate and
// answers CERT_E_UNTRUSTEDROOT, as Windows does; certfnsh.asp then shows «Данный ЦС не является доверенным» and
// a link to the CA certificate, and a click on it asks in the extension's window whether to add the root.
// It runs on a copy of the stand HOME, so the stand's own token keeps its single certificate.
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { repoRoot } from "../../scripts/fetch-vendor.ts";
import { caDir } from "../../scripts/provision-token.ts";
import { stand, standDir, venvPython } from "../../scripts/setup-stand.ts";
import { blankPage, clearSites, enableSite, extensionOrigin, launchStand, openStandPage, servePages, setOptionSwitch, standExtension, type PageServer } from "./harness.ts";
import { enterPin, pinDialog } from "./testgost-certs.ts";

const outDir = join(standDir, "enrollment");
const home = join(outDir, "home");
const caDer = Buffer.from(readFileSync(join(caDir, "ca.pem"), "utf8").replace(/-----[^-]+-----|\s/g, ""), "base64");
const caThumbprint = createHash("sha1").update(caDer).digest("hex").toUpperCase();

let server: PageServer;
let context: BrowserContext;

test.describe.configure({ mode: "serial" });

test.beforeAll(async () => {
  rmSync(outDir, { recursive: true, force: true });
  mkdirSync(outDir, { recursive: true });
  cpSync(stand.home, home, { recursive: true, verbatimSymlinks: true });
  server = await servePages({ "/": blankPage, "/certnew.cer": { type: "application/x-x509-ca-cert", body: readFileSync(join(caDir, "ca.pem"), "utf8") } });
  context = await launchStand({ home, extensions: [stand.adapter, standExtension()] });
  await clearSites(context);
  await enableSite(context, server.url);
});

test.afterAll(async () => {
  await context?.close();
  await server?.close();
});

// Runs `code` in the page; resolves with its result or with getLastError of what it threw.
async function start(page: Page, code: string): Promise<void> {
  await page.evaluate(`window.flowResult = undefined; void (async () => {
    try {
      await cadesplugin;
      window.flowResult = { value: await (async () => { ${code} })() };
    } catch (e) {
      window.flowResult = { error: cadesplugin.getLastError(e) };
    }
  })()`);
}

async function result(page: Page): Promise<{ value?: string; error?: string }> {
  await page.waitForFunction(() => (window as unknown as { flowResult?: unknown }).flowResult !== undefined, undefined, { timeout: 60_000 });
  return page.evaluate(() => (window as unknown as { flowResult: { value?: string; error?: string } }).flowResult);
}

// certrqma.asp's calls (async_code.js) for its default form: the type-80 provider, key usage "both".
const createRequest = `
  const create = (name) => cadesplugin.CreateObjectAsync(name);
  const csps = await create("X509Enrollment.CCspInformations");
  await csps.AddAvailableCsps();
  const csp = await csps.ItemByIndex(0);
  const name = await csp.Name;
  const key = await create("X509Enrollment.CX509PrivateKey");
  await key.propset_ProviderName(name);
  await key.propset_ProviderType(await csp.Type);
  const status = await csps.GetCspStatusFromProviderName(name, 1);
  const length = await (await status.CspAlgorithm).DefaultLength;
  await key.propset_KeySpec(1);
  await key.propset_Length(length);
  await key.propset_MachineContext(false);
  const request = await create("X509Enrollment.CX509CertificateRequestPkcs10");
  await request.InitializeFromPrivateKey(1, key, "");
  const dn = await create("X509Enrollment.CX500DistinguishedName");
  await dn.Encode('C="RU";CN="Enrollment User";', 2097152);
  await request.propset_Subject(dn);
  const enroll = await create("X509Enrollment.CX509Enrollment");
  await enroll.InitializeFromRequest(request);
  return enroll.CreateRequest(3);`;

// certfnsh.asp's Install() (XE_Enroll_InstallPKCS7Ex): AllowUntrustedRoot, CRYPT_STRING_ANY.
const installResponse = (response: string) => `
  const enroll = await cadesplugin.CreateObjectAsync("X509Enrollment.CX509Enrollment");
  await enroll.Initialize(1);
  await enroll.InstallResponse(4, ${JSON.stringify(response)}, 7, "");
  return "installed";`;

function der(tag: number, ...parts: Buffer[]): Buffer {
  const body = Buffer.concat(parts);
  const length = body.length < 0x80 ? Buffer.from([body.length]) : Buffer.from([0x82, body.length >> 8, body.length & 0xff]);
  return Buffer.concat([Buffer.from([tag]), length, body]);
}

// A certs-only PKCS#7, the shape of certsrv's certnew.p7b.
function certsOnly(certificates: Buffer[]): string {
  const oid = (hex: string) => der(0x06, Buffer.from(hex, "hex"));
  const signedData = der(0x30, der(0x02, Buffer.from([1])), der(0x31), der(0x30, oid("2a864886f70d010701")), der(0xa0, ...certificates), der(0x31));
  return der(0x30, oid("2a864886f70d010702"), der(0xa0, signedData)).toString("base64");
}

async function confirmWindow(): Promise<Page> {
  const origin = await extensionOrigin(context);
  const window = await context.waitForEvent("page", (candidate) => candidate.url().startsWith(`${origin}/confirm.html`));
  await expect(window.locator("#subject")).toContainText("Stand Test CA");
  await expect(window.locator("#fingerprint")).toHaveText(`Отпечаток (sha1): ${caThumbprint.match(/.{8}/g)!.join(" ")}`);
  // For a look at the window afterwards.
  await window.screenshot({ path: join(outDir, "confirm.png") });
  return window;
}

async function extraTab(): Promise<string[]> {
  const page = await context.newPage();
  await page.goto(`${await extensionOrigin(context)}/options.html`);
  await page.locator("#tab-extra").click();
  await expect(page.locator("#extra-count")).not.toBeEmpty();
  const thumbprints = await page.locator("#extra li").evaluateAll((items) => items.map((item) => (item as HTMLElement).dataset.thumbprint ?? ""));
  await page.close();
  return thumbprints;
}

let response = "";

test("a certificate for a key made on the token is issued by the stand's CA", async () => {
  const page = await openStandPage(context, `${server.url}/`);
  await start(page, createRequest);
  await expect(pinDialog(page)).toContainText("Владелец: Enrollment User", { timeout: 30_000 });
  await enterPin(page);
  const { value, error } = await result(page);
  expect(error).toBeUndefined();
  const csr = join(outDir, "request.pem");
  writeFileSync(csr, `-----BEGIN CERTIFICATE REQUEST-----\n${value}\n-----END CERTIFICATE REQUEST-----\n`);
  const certificate = join(outDir, "certificate.pem");
  execFileSync(venvPython, [join(repoRoot, "tests", "tools", "gost_ca.py"), "issue", caDir, csr, certificate]);
  response = certsOnly([Buffer.from(readFileSync(certificate, "utf8").replace(/-----[^-]+-----|\s/g, ""), "base64"), caDer]);
  await page.close();
});

// certfnsh.asp's link «установите этот сертификат ЦС»: the CA certificate as a file.
async function clickRootLink(page: Page): Promise<Page> {
  const opened = confirmWindow();
  await page.evaluate(() => {
    const link = Object.assign(document.createElement("a"), { href: "/certnew.cer?ReqID=CACert&Renewal=21&Mode=inst&Enc=b64", textContent: "установите этот сертификат ЦС" });
    document.body.replaceChildren(link);
  });
  await page.getByText("установите этот сертификат ЦС").click();
  return opened;
}

test("the page gets CERT_E_UNTRUSTEDROOT at once, the certificate on the token and nothing asked", async () => {
  const page = await openStandPage(context, `${server.url}/`);
  let asked = false;
  const onPage = () => (asked = true);
  context.on("page", onPage);
  await start(page, installResponse(response));
  await expect(pinDialog(page)).toContainText("Сертификат: Enrollment User", { timeout: 30_000 });
  await enterPin(page);
  expect((await result(page)).error).toMatch(/0x800B0109/);
  context.off("page", onPage);
  expect(asked).toBe(false);
  expect(await extraTab()).not.toContain(caThumbprint);
  await page.close();
});

test("the page's link to the root asks; no leaves it out, yes adds it, and installing again succeeds", async () => {
  const page = await openStandPage(context, `${server.url}/`);
  const alerts: string[] = [];
  page.on("dialog", (dialog) => {
    alerts.push(dialog.message());
    void dialog.accept();
  });
  await start(page, installResponse(response));
  await expect(pinDialog(page)).toBeVisible({ timeout: 30_000 });
  await enterPin(page);
  expect((await result(page)).error).toMatch(/0x800B0109/);
  await (await clickRootLink(page)).locator("button[name=cancel]").click();
  expect(await extraTab()).not.toContain(caThumbprint);
  await (await clickRootLink(page)).locator("button[name=install]").click();
  await expect.poll(() => alerts).toEqual(["Корневой сертификат «Stand Test CA» установлен в расширении. Установите свой сертификат ещё раз."]);
  expect(await extraTab()).toContain(caThumbprint);
  // The page still works: it was not navigated to the file.
  expect(page.url()).toBe(`${server.url}/`);
  await start(page, installResponse(response));
  await expect(pinDialog(page)).toBeVisible({ timeout: 30_000 });
  await enterPin(page);
  expect(await result(page)).toEqual({ value: "installed" });
  await page.close();
});

test("with the switch off, the certificate is installed without a word about the root", async () => {
  await clearSites(context);
  await enableSite(context, server.url);
  await setOptionSwitch(context, "offer-root", false);
  const page = await openStandPage(context, `${server.url}/`);
  await start(page, installResponse(response));
  await expect(pinDialog(page)).toBeVisible({ timeout: 30_000 });
  await enterPin(page);
  expect(await result(page)).toEqual({ value: "installed" });
  expect(await extraTab()).not.toContain(caThumbprint);
  await page.close();
});
