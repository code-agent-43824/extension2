// The window on the extension's button: the current site and its switch.
import { disableSite, enabledSites, enableSite, hasAccess, siteOf } from "./sites.ts";

const byId = (id: string) => document.getElementById(id)!;

async function main(): Promise<void> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const site = siteOf(tab?.url);
  const note = byId("note");
  if (!site || tab?.id === undefined) {
    note.textContent = "На этой странице расширение не работает.";
    return;
  }
  byId("site").textContent = site;
  const toggle = byId("toggle");
  const checkbox = toggle.querySelector("input")!;
  checkbox.checked = (await enabledSites()).includes(site) && (await hasAccess(site));
  toggle.hidden = false;
  checkbox.addEventListener("change", async () => {
    // enableSite asks Chrome for access first, while the click still counts as a user gesture.
    if (checkbox.checked && !(await enableSite(site))) {
      checkbox.checked = false;
      note.textContent = "Chrome не дал доступ к сайту.";
      return;
    }
    if (!checkbox.checked) await disableSite(site);
    // The page-world script runs at document_start, so the change takes effect on reload.
    await chrome.tabs.reload(tab.id!);
    window.close();
  });
}

void main();
