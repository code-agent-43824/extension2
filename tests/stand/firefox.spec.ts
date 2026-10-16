// Our dist/firefox build in Firefox (docs/PLAN.md, action 31), on the stand's fake Rutoken through the Rutoken adapter
// for Firefox: the plug-in itself, enabling a site on the options page, CryptoPro's demo page signing, XAdES-T, whose
// timestamp Firefox's background script fetches after the user's yes in the extension's window, and webtools.html's
// readers and containers.
import { expect, test } from "@playwright/test";
import { join } from "node:path";
import { packageVersion } from "../../scripts/build.ts";
import { vendorDir } from "../../scripts/fetch-vendor.ts";
import { tokenLabel, userPin } from "../../scripts/setup-stand.ts";
import { blankPage, directoryRoutes, loadPluginSource, servePages, type PageServer } from "./harness.ts";
import { enableSite, enterPin, Firefox, pinDialog, type FirefoxTab } from "./firefox.ts";
import { startTsa, verifyCms, verifyXml, type TimestampService } from "./verify.ts";

test.describe.configure({ mode: "serial" });

const demoPath = "/sites/default/files/products/cades/demopage/cades_bes_sample.html";

let server: PageServer;
let other: PageServer;
let tsa: TimestampService;
let firefox: Firefox;

test.beforeAll(async () => {
  server = await servePages({ ...directoryRoutes(join(vendorDir, "cryptopro"), "/sites/default/files"), "/blank.html": blankPage });
  // A second site: on another port, which Firefox's access covers along with the first (sites.ts, matchPattern).
  other = await servePages({ "/blank.html": blankPage });
  tsa = await startTsa();
  firefox = await Firefox.launch();
});

test.afterAll(async () => {
  await firefox?.close();
  await server?.close();
  await other?.close();
  tsa?.close();
});

async function plainPage(url: string): Promise<FirefoxTab> {
  return firefox.newTab(url);
}

test("loads the Rutoken Plugin through the adapter for Firefox; a site not enabled gets no cadesplugin", async () => {
  const tab = await plainPage(`${server.url}/blank.html`);
  await tab.waitFor(`"C3B7563B-BF85-45B7-88FC-7CFF1BD3C2DB" in window`);
  const token = await tab.evaluate<{ version: string; label: string }>(`(async () => {
    const plugin = await (${loadPluginSource})();
    const [device] = await plugin.enumerateDevices();
    return { version: await plugin.version, label: await plugin.getDeviceInfo(device, plugin.TOKEN_INFO_LABEL) };
  })()`);
  expect(token).toEqual({ version: "4.12.3.0", label: tokenLabel });
  expect(await tab.evaluate(`typeof window.cadesplugin`)).toBe("undefined");
  await tab.close();
});

test("the options page turns a site on: page.js defines cadesplugin there, on every port of the host", async () => {
  await enableSite(firefox, server.url);
  const tab = await plainPage(`${server.url}/blank.html`);
  expect(await tab.evaluate(`typeof window.cadesplugin`)).toBe("object");
  await tab.navigate(`${other.url}/blank.html`);
  expect(await tab.evaluate(`typeof window.cadesplugin`)).toBe("object");
  await tab.close();
});

const text = (id: string) => `document.getElementById(${JSON.stringify(id)})?.textContent`;

async function demoPage(): Promise<FirefoxTab> {
  const tab = await plainPage(server.url + demoPath);
  await tab.waitFor(`${text("CertificatesCountTxt")} === "Сертификаты My:1, Cont:0"`);
  return tab;
}

test("the demo page shows the plug-in, the provider and the token certificate", async () => {
  const tab = await demoPage();
  const ids = ["ExtensionEnabledTxt", "PluginEnabledTxt", "CspEnabledTxt", "PlugInVersionTxt", "CSPNameTxt", "ExtVersionTxt"];
  await tab.waitFor(`${text("ExtVersionTxt")}?.startsWith("Версия расширения: ")`);
  const shown = await tab.evaluate(`${JSON.stringify(ids)}.map((id) => document.getElementById(id)?.textContent)`);
  expect(shown).toEqual([
    "Расширение загружено",
    "Плагин загружен",
    "Криптопровайдер загружен",
    "Версия плагина: 2.0.15000",
    "Криптопровайдер: Rutoken Plugin 4.12.3.0",
    `Версия расширения: ${packageVersion()}`,
  ]);
  const options = await tab.evaluate<string[]>(`[...document.getElementById("CertListBox").options].map((option) => option.text)`);
  expect(options).toHaveLength(1);
  expect(options[0]).toContain("CN=Stand User; Выдан: ");
  await tab.close();
});

test("the demo page signs Hello World after the PIN, and the signature verifies", async () => {
  const tab = await demoPage();
  await tab.evaluate(`(() => { const list = document.getElementById("CertListBox"); list.selectedIndex = 0; list.dispatchEvent(new Event("change")); return true; })()`);
  await tab.waitFor(`${text("subject")} === "Владелец: CN=Stand User"`);
  await tab.click(`document.getElementById("SignBtn")`);
  const request = await tab.waitFor<string>(`${pinDialog}?.textContent`);
  expect(request).toContain(new URL(server.url).origin);
  expect(request).toContain("11 байт, присоединённая подпись.");
  await enterPin(tab, userPin);
  await tab.waitFor(`document.querySelector("[name=SignatureTitle]")?.textContent === "Подпись сформирована успешно:"`);
  const signature = await tab.evaluate<string>(`document.getElementById("SignatureTxtBox").value.trim()`);
  const report = verifyCms(signature);
  expect(report.checks).toEqual({ message_digest: true, signature: true, certificate_by_ca: true, cades_bes_attributes: true });
  expect(await tab.evaluate(`!${pinDialog}`)).toBe(true);
  await tab.close();
});

test("signs XAdES-T: the extension's window asks for the timestamp service, the background script gets the stamp", async () => {
  const tab = await plainPage(`${server.url}/blank.html`);
  await tab.evaluate(`(() => {
    window.flowResult = undefined;
    void (async () => {
      try {
        await cadesplugin;
        const store = await cadesplugin.CreateObjectAsync("CAdESCOM.Store");
        await store.Open();
        const signer = await cadesplugin.CreateObjectAsync("CAdESCOM.CPSigner");
        await signer.propset_Certificate(await (await store.Certificates).Item(1));
        await signer.propset_TSAAddress(${JSON.stringify(tsa.url)});
        const xml = await cadesplugin.CreateObjectAsync("CAdESCOM.SignedXML");
        await xml.propset_Content("<doc>Документ</doc>");
        await xml.propset_SignatureType(cadesplugin.CADESCOM_XML_SIGNATURE_TYPE_ENVELOPED | cadesplugin.CADESCOM_XADES_T);
        window.flowResult = { signed: await xml.Sign(signer) };
      } catch (e) {
        window.flowResult = { error: cadesplugin.getLastError(e) };
      }
    })();
    return true;
  })()`);
  const access = await firefox.windowAt(firefox.extensionUrl("tsa-access.html"));
  expect(await access.waitFor<string>(`${text("request")}`)).toContain(tsa.url);
  await access.waitFor(`!document.querySelector("button[name=allow]").disabled`);
  await access.click(`document.querySelector("button[name=allow]")`);
  await enterPin(tab, userPin);
  const result = await tab.waitFor<{ signed?: string; error?: string }>(`window.flowResult`, 60_000);
  expect(result.error).toBeUndefined();
  const report = verifyXml(result.signed!);
  expect(report.valid).toBe(true);
  expect(report.signatures[0]!.checks).toMatchObject({ timestamp_imprint: true, timestamp_signature: true, timestamp_tsa_by_ca: true });
  await tab.close();
});

test("webtools.html lists the token as a reader and, after the PIN it asks for at load, its key as a container", async () => {
  const tab = await plainPage(`${server.url}/sites/default/files/products/cades/demopage/webtools.html`);
  await tab.waitFor(`${text("CspEnabledTxt")} === "Криптопровайдер загружен"`);
  expect(await tab.waitFor<string>(`${pinDialog}?.textContent`)).toContain("просит показать ключи на Рутокене.");
  await enterPin(tab, userPin);
  await tab.click(`document.getElementById("navbtnreaders")`);
  const reader = await tab.waitFor<string>(`document.querySelector("#UlReaders li")?.textContent`);
  expect(reader.trim()).toMatch(new RegExp(`^Aktiv Rutoken ECP \\d+/${tokenLabel}/Rutoken ECP [\\d.]+ \\d+$`));
  await tab.click(`document.getElementById("navbtnconts")`);
  const container = await tab.waitFor<string>(`document.querySelector("#UlContainer li")?.textContent`);
  expect(container.trim()).toMatch(/^\\\\\.\\Aktiv Rutoken ECP \d+\\ID_[0-9a-f]+$/);
  await tab.close();
});
