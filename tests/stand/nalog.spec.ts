// The owner's experiment (docs/PLAN.md, action 11): sign in to the FNS personal accounts of an individual
// (lkfl2.nalog.ru) and of a sole trader (lkip2.nalog.ru) "by certificate", the way that needs CryptoPro's
// extension and plug-in, with a certificate from CryptoPro's test CA whose key is on the (fake) Rutoken. The
// certificate is not from an accredited CA, so success is getting through the page's checks to the signature
// and having the server refuse the certificate. Opt-in, since it needs the internet and outside services:
// STAND_ONLINE=1 npx playwright test tests/stand/nalog.spec.ts
// It runs on its own copy of the stand HOME and leaves screenshots in stand/nalog/.
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { cpSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { stand, standDir, userPin } from "../../scripts/setup-stand.ts";
import { clearSites, enableSite, launchStand, openStandPage, standExtension } from "./harness.ts";

const ca = "https://testgost2012.cryptopro.ru";
const lkfl = "https://lkfl2.nalog.ru";
const lkip = "https://lkip2.nalog.ru";
const outDir = join(standDir, "nalog");
const home = join(outDir, "home");

// The cabinets read the taxpayer from the certificate: an INN (and SNILS) for an individual, an OGRNIP too for
// a sole trader. The numbers are made up, with valid check digits.
const individual = { commonName: "Тестов Физлицо Тестович", dn: 'SN="Тестов";G="Физлицо Тестович";INN="770700000190";SNILS="11223344595";' };
const soleTrader = {
  commonName: "ИП Тестов Предприниматель Тестович",
  dn: 'SN="Тестов";G="Предприниматель Тестович";INN="770700000264";SNILS="12345678964";OGRNIP="326770000000016";',
};

test.skip(!process.env.STAND_ONLINE, "needs the internet: set STAND_ONLINE=1");
test.describe.configure({ mode: "serial" });

let context: BrowserContext;

test.beforeAll(async () => {
  rmSync(outDir, { recursive: true, force: true });
  mkdirSync(outDir, { recursive: true });
  cpSync(stand.home, home, { recursive: true, verbatimSymlinks: true });
  const sites = [ca, lkfl, lkip];
  context = await launchStand({
    home,
    online: sites.map((site) => new URL(site).hostname),
    extensions: [stand.adapter, standExtension(sites.map((site) => `${site}/*`)), stand.cryptoproExtension],
  });
  await clearSites(context);
  for (const site of sites) await enableSite(context, site);
});

test.afterAll(async () => {
  await context?.close();
});

const pinDialog = (page: Page) => page.locator("#rutoken-cades-bridge-pin [role=dialog]");

async function enterPin(page: Page) {
  await pinDialog(page).locator("input[name=pin]").fill(userPin);
  await pinDialog(page).locator("button[name=confirm]").click();
}

// The CA's form has no fields for INN, SNILS or OGRNIP; they are added to the name the page passes to
// X500DistinguishedName.Encode, which our extension turns into the request on the token.
async function issue({ commonName, dn }: { commonName: string; dn: string }) {
  const page = await openStandPage(context, `${ca}/certsrv/certrqma.asp`);
  page.on("dialog", (dialog) => dialog.accept());
  await expect(page.locator("select[name=lbCSP] option").first()).toHaveText("Rutoken Plugin 4.12.3.0", { timeout: 60_000 });
  await page.locator("select[name=lbCSP]").selectOption("80");
  await page.locator("input[name=tbCommonName]").fill(commonName);
  await page.locator("input[name=tbEmail]").fill("rutoken@example.ru");
  await page.locator("input[name=tbCountry]").fill("RU");
  await page.evaluate((extra) => {
    const win = window as unknown as { BuildDistinguishedName: () => string };
    const original = win.BuildDistinguishedName;
    win.BuildDistinguishedName = () => original() + extra;
  }, dn);
  await page.locator("input[name=btnSubmit]").click();
  await expect(pinDialog(page)).toContainText(`Владелец: ${commonName}`, { timeout: 30_000 });
  await enterPin(page);
  await page.waitForURL(/certfnsh\.asp/i, { timeout: 60_000 });
  await expect(page.locator("#locInstallCert1")).toBeVisible({ timeout: 60_000 });
  await page.locator("#locInstallCert1").click();
  await expect(pinDialog(page)).toContainText(`Сертификат: ${commonName}`, { timeout: 30_000 });
  await enterPin(page);
  await expect(page.locator("body")).toContainText("Новый сертификат успешно установлен.", { timeout: 60_000 });
  await page.close();
}

test("the test CA issues 256-bit certificates with an INN for an individual and a sole trader", async () => {
  test.setTimeout(300_000);
  await issue(individual);
  await issue(soleTrader);
});

test("lkfl2: the page lists the certificate, the Rutoken signs, and the server refuses the CA", async () => {
  test.setTimeout(300_000);
  const page = await openStandPage(context, `${lkfl}/lkfl/`, 60_000);
  // lkfl2 answers 502 now and then; the page is up when it offers the sign-in with a signature.
  const signIn = page.getByText("Войти с помощью ЭП").first();
  await expect(async () => {
    if (!(await signIn.isVisible())) await page.reload();
    await expect(signIn).toBeVisible({ timeout: 20_000 });
  }).toPass({ timeout: 120_000 });
  await signIn.click();
  const dialog = page.locator("[role=dialog]").last();
  await dialog.locator("[aria-haspopup=listbox]").click({ timeout: 60_000 });
  await page.locator("[role=option]", { hasText: `CN=${individual.commonName}` }).click();
  await expect(dialog).not.toContainText("Вы не можете воспользоваться");
  await page.screenshot({ path: join(outDir, "lkfl-1-certificate.png"), fullPage: true });
  const token = page.waitForResponse((response) => response.url().endsWith("/api/auth/oauth/token"));
  await dialog.locator("button[type=submit]").click();
  await expect(pinDialog(page)).toContainText(`Сертификат: ${individual.commonName}`, { timeout: 60_000 });
  await expect(pinDialog(page)).toContainText("отсоединённая подпись");
  await page.screenshot({ path: join(outDir, "lkfl-2-pin.png") });
  await enterPin(page);
  // The signature reached the server, which checked the certificate and turned it down.
  const response = await token;
  expect(response.status()).toBe(400);
  expect(await response.json()).toMatchObject({ error: "invalid_grant", error_description: "CERTIFICATE_IS_NOT_TRUSTED" });
  await expect(dialog).toContainText("УЦ, выдавший сертификат, не аккредитован", { timeout: 30_000 });
  await page.screenshot({ path: join(outDir, "lkfl-3-refused.png"), fullPage: true });
});

// The sole trader's sign-in itself is on lkipgost2.nalog.ru, which speaks only GOST TLS, out of reach for
// Chrome. What lkip2 offers without it is its check of the conditions for signing in, which ends with a
// signature and the server's verdict on the certificate. Its browser step is not about our extension and is
// got past: it tells a GOST browser by the user agent alone. Its root certificate step finds the head CA and
// the Ministry in the Root store, which is the extension's built-in root store (docs/JOURNAL.md).
test("lkip2: the conditions check finds the plug-in, the CSP, the roots and the certificate, signs, and the server refuses the CA", async () => {
  test.setTimeout(180_000);
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  const userAgent = (await page.evaluate(() => navigator.userAgent)).replace("HeadlessChrome", "Chrome");
  await cdp.send("Emulation.setUserAgentOverride", { userAgent: `${userAgent} Chromium GOST` });
  await page.goto(`${lkip}/lk#/certificate/requirements`);
  await expect(page.getByText("Начать проверку")).toBeVisible({ timeout: 60_000 });
  const verdict = page.waitForResponse((response) => response.url().endsWith("/api/certificate/checkAuthority"));
  await page.getByText("Начать проверку").click();
  const list = page.locator(".certificate-list__fancy");
  await expect(list).toBeVisible({ timeout: 60_000 });
  await page.screenshot({ path: join(outDir, "lkip-1-certificates.png"), fullPage: true });
  const item = list.locator("div").filter({ hasText: "326770000000016" }).filter({ has: page.getByText("Выбрать", { exact: true }) }).last();
  // The page takes a choice made in the first second after the list opens as the end of the check, without
  // a signature: its poll (every second) has to clear processLoaded first. A person does not click that fast.
  await page.waitForFunction(() => (window as unknown as { checker: { processLoaded: boolean } }).checker.processLoaded === false);
  await item.getByText("Выбрать", { exact: true }).click();
  await expect(pinDialog(page)).toContainText(`Сертификат: ${soleTrader.commonName}`, { timeout: 60_000 });
  await page.screenshot({ path: join(outDir, "lkip-2-pin.png") });
  await enterPin(page);
  expect(await (await verdict).json()).toMatchObject({ response: { trusted: false, error: "authority_not_found" } });
  const state = await page.evaluate(() => {
    const checker = (window as unknown as { checker: { currentResult: unknown; userInfo: Record<string, unknown> } }).checker;
    return { result: checker.currentResult, userInfo: checker.userInfo };
  });
  expect(state.result).toBe("untrustedCA");
  expect(state.userInfo).toMatchObject({
    plugin: { status: true },
    CryptoproCSP: { status: true },
    ca: { store: { created: true, opened: true }, gnivc: true },
    signature: { CPSigner: { created: true }, CadesSignedData: { created: true }, SignCades: { created: true } },
  });
  await page.screenshot({ path: join(outDir, "lkip-3-refused.png"), fullPage: true });
});
