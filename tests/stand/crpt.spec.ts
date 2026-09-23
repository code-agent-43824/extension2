// The owner's experiment (docs/PLAN.md, action 14) on Честный знак: sign in "with an electronic signature" on
// markirovka.crpt.ru with a certificate from CryptoPro's test CA whose key is on the (fake) Rutoken. The site
// takes both CryptoPro's plug-in and the Rutoken Plugin (through the adapter) itself, so every certificate is
// listed twice: first as CryptoPro's, which is our extension, then as its own Rutoken's. We go the CryptoPro way
// and expect the server to refuse the certificate. No CryptoPro extension here: with it but without its plug-in
// the site waits for it forever. Opt-in, since it needs the internet and outside services:
// STAND_ONLINE=1 npx playwright test tests/stand/crpt.spec.ts
// It runs on its own copy of the stand HOME and leaves screenshots in stand/crpt/.
import { expect, test, type BrowserContext } from "@playwright/test";
import { cpSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { stand, standDir } from "../../scripts/setup-stand.ts";
import { clearSites, enableSite, launchStand, openStandPage, standExtension } from "./harness.ts";
import { enterPin, issueTestgost, pinDialog, soleTrader, testgostCa } from "./testgost-certs.ts";
import { verifyCms } from "./verify.ts";

const crpt = "https://markirovka.crpt.ru";
const outDir = join(standDir, "crpt");
const home = join(outDir, "home");

test.skip(!process.env.STAND_ONLINE, "needs the internet: set STAND_ONLINE=1");

let context: BrowserContext;

test.afterAll(async () => {
  await context?.close();
});

test("markirovka.crpt.ru: the CryptoPro way lists the certificate, the Rutoken signs, and the server refuses it", async () => {
  test.setTimeout(420_000);
  rmSync(outDir, { recursive: true, force: true });
  mkdirSync(outDir, { recursive: true });
  cpSync(stand.home, home, { recursive: true, verbatimSymlinks: true });
  const sites = [testgostCa, crpt];
  context = await launchStand({
    home,
    online: sites.map((site) => new URL(site).hostname),
    extensions: [stand.adapter, standExtension(sites.map((site) => `${site}/*`))],
  });
  await clearSites(context);
  for (const site of sites) await enableSite(context, site);
  const caPem = await issueTestgost(context, soleTrader);

  const page = await openStandPage(context, `${crpt}/login-kep`, 60_000);
  // The site's own Rutoken way asks for the PIN with prompt(); it must not be the one that signs.
  page.on("dialog", (dialog) => dialog.dismiss());
  await page.getByText("Войти с электронной подписью").click({ timeout: 60_000 });
  const entries = page.getByText(soleTrader.commonName, { exact: true });
  await expect(entries).toHaveCount(2, { timeout: 60_000 });
  await page.screenshot({ path: join(outDir, "1-certificates.png"), fullPage: true });
  const login = page.waitForRequest((request) => request.url().endsWith("/bff-elk/v1/united-auth/login"));
  const answer = page.waitForResponse((response) => response.url().endsWith("/bff-elk/v1/united-auth/login"));
  await entries.first().click();
  await expect(pinDialog(page)).toContainText(`Сертификат: ${soleTrader.commonName}`, { timeout: 60_000 });
  await page.screenshot({ path: join(outDir, "2-pin.png") });
  await enterPin(page);
  // What the server got is a CAdES-BES signature that verifies against the test CA.
  const signature = (JSON.parse((await login).postData()!) as { kep: { data: string } }).kep.data;
  const caPath = join(outDir, "ca.pem");
  writeFileSync(caPath, caPem);
  expect(verifyCms(signature, undefined, caPath)).toMatchObject({ valid: true, detached: false });
  const response = await answer;
  expect(response.status()).toBe(403);
  expect(await response.json()).toMatchObject({ error_message: "Проверка подписи не пройдена" });
  await expect(page.getByText("Проверка подписи не пройдена")).toBeVisible();
  await page.screenshot({ path: join(outDir, "3-refused.png"), fullPage: true });
});
