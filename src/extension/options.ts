// The options page: every enabled site, with a way to turn it off or to add one by address.
import { disableSite, enabledSites, enableSite, siteOf, STORAGE_KEY } from "./sites.ts";

const byId = (id: string) => document.getElementById(id)!;

async function render(): Promise<void> {
  const sites = await enabledSites();
  const list = byId("sites");
  list.replaceChildren(
    ...sites.map((site) => {
      const item = document.createElement("li");
      const name = document.createElement("span");
      name.textContent = site;
      const off = document.createElement("button");
      off.type = "button";
      off.textContent = "Выключить";
      off.addEventListener("click", () => void disableSite(site));
      item.append(name, off);
      return item;
    }),
  );
  byId("empty").hidden = sites.length > 0;
}

const form = byId("add") as HTMLFormElement;
form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const error = byId("error");
  const input = form.elements.namedItem("site") as HTMLInputElement;
  const site = siteOf(input.value.trim());
  if (!site) {
    error.textContent = "Нужен адрес сайта, начинающийся с http:// или https://.";
    return;
  }
  error.textContent = "";
  if (await enableSite(site)) input.value = "";
  else error.textContent = "Chrome не дал доступ к сайту.";
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && STORAGE_KEY in changes) void render();
});
void render();
