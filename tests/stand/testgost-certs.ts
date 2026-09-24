// Certificates for the online experiments on government sites (docs/PLAN.md, actions 11 and 14): issued by
// CryptoPro's test CA testgost2012.cryptopro.ru, with the key made on the (fake) Rutoken through our extension.
import { expect, type BrowserContext, type Page } from "@playwright/test";
import { userPin } from "../../scripts/setup-stand.ts";
import { openStandPage } from "./harness.ts";

export const testgostCa = "https://testgost2012.cryptopro.ru";

export interface Holder {
  commonName: string;
  // Added to the name the CA's page builds.
  dn: string;
}

// The cabinets read the taxpayer from the certificate: an INN (and SNILS) for an individual, an OGRNIP too for
// a sole trader. The numbers are made up, with valid check digits.
export const individual: Holder = {
  commonName: "Тестов Физлицо Тестович",
  dn: 'SN="Тестов";G="Физлицо Тестович";INN="770700000190";SNILS="11223344595";',
};
export const soleTrader: Holder = {
  commonName: "ИП Тестов Предприниматель Тестович",
  dn: 'SN="Тестов";G="Предприниматель Тестович";INN="770700000264";SNILS="12345678964";OGRNIP="326770000000016";',
};

export const pinDialog = (page: Page) => page.locator("#rutoken-cades-bridge-pin [role=dialog]");

export async function enterPin(page: Page) {
  await pinDialog(page).locator("input[name=pin]").fill(userPin);
  await pinDialog(page).locator("button[name=confirm]").click();
}

// Issues a 256-bit certificate and installs it on the token; returns the CA certificate (PEM). The CA's form
// has no fields for INN, SNILS or OGRNIP; they are added to the name the page passes to
// X500DistinguishedName.Encode, which our extension turns into the request on the token. The CA's site must be
// enabled in the extension.
export async function issueTestgost(context: BrowserContext, { commonName, dn }: Holder): Promise<string> {
  const page = await openStandPage(context, `${testgostCa}/certsrv/certrqma.asp`);
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
  const caLink = (await page.locator("a[href*='ReqID=CACert']").first().getAttribute("href"))!;
  const caPem = await page.evaluate((href) => fetch(href).then((response) => response.text()), caLink);
  expect(caPem).toContain("-----BEGIN CERTIFICATE-----");
  // The extension asks whether to trust the test CA's root the first time (docs/PLAN.md, action 22): yes.
  const trustRoot = (window: Page) => {
    if (window.url().includes("/confirm.html")) void window.locator("button[name=install]").click();
  };
  context.on("page", trustRoot);
  await page.locator("#locInstallCert1").click();
  await expect(pinDialog(page)).toContainText(`Сертификат: ${commonName}`, { timeout: 30_000 });
  await enterPin(page);
  await expect(page.locator("body")).toContainText("Новый сертификат успешно установлен.", { timeout: 60_000 });
  context.off("page", trustRoot);
  await page.close();
  return caPem;
}
