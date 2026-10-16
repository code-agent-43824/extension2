// The options page: every enabled site, with a way to turn it off or to add one by address; below it, the
// extended validity switch, the confirmed timestamp services and the certificate stores (roots-view.ts).
import { EXTENDED_VALIDITY_KEY, OFFER_ROOT_KEY, extendedValidity, offerRoot, setExtendedValidity, setOfferRoot } from "./roots.ts";
import { setupRoots } from "./roots-view.ts";
import { disableSite, enabledSites, enableSite, siteOf, STORAGE_KEY } from "./sites.ts";
import { forgetTsaService, TSA_KEY, tsaServices } from "./timestamps.ts";

const byId = (id: string) => document.getElementById(id)!;

// One address a line, with the button that undoes it.
function renderList(listId: string, emptyId: string, items: string[], label: string, undo: (item: string) => Promise<void>): void {
  byId(listId).replaceChildren(
    ...items.map((value) => {
      const item = document.createElement("li");
      const name = document.createElement("span");
      name.textContent = value;
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = label;
      button.addEventListener("click", () => void undo(value));
      item.append(name, button);
      return item;
    }),
  );
  byId(emptyId).hidden = items.length > 0;
}

async function render(): Promise<void> {
  renderList("sites", "empty", await enabledSites(), "Выключить", (site) => disableSite(site));
}

async function renderServices(): Promise<void> {
  renderList("tsa-services", "tsa-empty", await tsaServices(), "Забыть", (origin) => forgetTsaService(origin));
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
  if (area === "local" && TSA_KEY in changes) void renderServices();
});
void render();
void renderServices();
setupRoots();

// A switch of the "Проверка сертификатов" section, kept in chrome.storage.local under `key`.
function setupSwitch(name: string, key: string, get: () => Promise<boolean>, set: (enabled: boolean) => Promise<void>): void {
  const input = document.querySelector<HTMLInputElement>(`input[name=${name}]`)!;
  const show = async () => {
    input.checked = await get();
  };
  input.addEventListener("change", () => void set(input.checked));
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && key in changes) void show();
  });
  void show();
}

setupSwitch("extended-validity", EXTENDED_VALIDITY_KEY, extendedValidity, setExtendedValidity);
setupSwitch("offer-root", OFFER_ROOT_KEY, offerRoot, setOfferRoot);
