// The window on the extension's button: the current site and a switch for each plug-in the extension can play there.
import { BROWSER_NAME } from "./browser.ts";
import { disablePlugin, enableSite, hasAccess, PLUGINS, siteOf, sitePlugins, whenRegistered } from "./sites.ts";

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
  const on = (await hasAccess(site)) ? await sitePlugins(site) : [];
  const fieldset = byId("plugins");
  for (const plugin of PLUGINS) {
    const checkbox = fieldset.querySelector<HTMLInputElement>(`input[name=${plugin}]`)!;
    checkbox.checked = on.includes(plugin);
    checkbox.addEventListener("change", async () => {
      // enableSite asks Chrome for access first, while the click still counts as a user gesture. Chrome's prompt may
      // close this window; the service worker then turns the plug-in on and reloads the tab (sites.ts).
      if (checkbox.checked && !(await enableSite(site, chrome, tab.id, [plugin]))) {
        checkbox.checked = false;
        note.textContent = `${BROWSER_NAME} не дал доступ к сайту.`;
        return;
      }
      if (!checkbox.checked) await disablePlugin(site, plugin);
      // The page-world script runs at document_start, so the change takes effect on reload, once the service worker
      // has registered it anew.
      await whenRegistered();
      await chrome.tabs.reload(tab.id!);
      window.close();
    });
  }
  fieldset.hidden = false;
}

void main();
