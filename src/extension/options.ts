// The options page: every enabled site with its plug-ins, a way to turn one or all of them off or to add a site by
// address; the PIN switch of IFCPlugin; below, the extended validity switch, the confirmed timestamp services and the
// certificate stores (roots-view.ts).
import { EXTENDED_VALIDITY_KEY, OFFER_ROOT_KEY, extendedValidity, offerRoot, setExtendedValidity, setOfferRoot } from "./roots.ts";
import { setupRoots } from "./roots-view.ts";
import { BROWSER_NAME } from "./browser.ts";
import {
  disablePlugin,
  disableSite,
  enabledSites,
  enableSite,
  IFC_PIN_WINDOW_KEY,
  ifcPinWindow,
  LIST_KEYS,
  type Plugin,
  PLUGINS,
  setIfcPinWindow,
  siteOf,
  sitePlugins,
} from "./sites.ts";
import { forgetTsaService, TSA_KEY, tsaServices } from "./timestamps.ts";
import { IDENTITY_KEY, newIdentity, storedIdentity } from "./identity.ts";

const byId = (id: string) => document.getElementById(id)!;

const PLUGIN_NAMES: Record<Plugin, string> = { cryptopro: "КриптоПро", ifc: "Плагин Госуслуг (IFCPlugin)", gos: "Госплагин" };

// One address a line, with the button that undoes it, and before the button what `extra` adds.
function renderList(listId: string, emptyId: string, items: string[], label: string, undo: (item: string) => Promise<void>, extra?: (item: string) => Promise<Node>): Promise<void> {
  return Promise.all(
    items.map(async (value) => {
      const item = document.createElement("li");
      const name = document.createElement("span");
      name.textContent = value;
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = label;
      button.addEventListener("click", () => void undo(value));
      item.append(name, ...(extra ? [await extra(value)] : []), button);
      return item;
    }),
  ).then((list) => {
    byId(listId).replaceChildren(...list);
    byId(emptyId).hidden = items.length > 0;
  });
}

// A site's plug-ins, each with its switch. The site already has access, so turning one on asks nothing.
async function pluginSwitches(site: string): Promise<Node> {
  const on = await sitePlugins(site);
  const box = document.createElement("span");
  box.className = "plugins-inline";
  for (const plugin of PLUGINS) {
    const label = document.createElement("label");
    const input = document.createElement("input");
    input.type = "checkbox";
    input.name = plugin;
    input.checked = on.includes(plugin);
    input.addEventListener("change", async () => {
      if (!input.checked) await disablePlugin(site, plugin);
      else if (!(await enableSite(site, chrome, undefined, [plugin]))) {
        input.checked = false;
        byId("error").textContent = `${BROWSER_NAME} не дал доступ к сайту.`;
      }
    });
    label.append(input, ` ${PLUGIN_NAMES[plugin]}`);
    box.append(label);
  }
  return box;
}

async function render(): Promise<void> {
  await renderList("sites", "empty", await enabledSites(), "Выключить", (site) => disableSite(site), pluginSwitches);
}

async function renderServices(): Promise<void> {
  await renderList("tsa-services", "tsa-empty", await tsaServices(), "Забыть", (origin) => forgetTsaService(origin));
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
  const plugins = PLUGINS.filter((plugin) => (form.elements.namedItem(plugin) as HTMLInputElement).checked);
  if (!plugins.length) {
    error.textContent = "Отметьте, каким плагином быть на сайте.";
    return;
  }
  error.textContent = "";
  if (await enableSite(site, chrome, undefined, plugins)) input.value = "";
  else error.textContent = `${BROWSER_NAME} не дал доступ к сайту.`;
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && Object.values(LIST_KEYS).some((key) => key in changes)) void render();
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

// IFCPlugin's PIN: the site's, as the original, or asked in the extension's window.
function setupIfcPin(): void {
  const inputs = [...document.querySelectorAll<HTMLInputElement>("input[name=ifc-pin]")];
  const show = async () => {
    const window = await ifcPinWindow();
    for (const input of inputs) input.checked = (input.value === "window") === window;
  };
  for (const input of inputs) input.addEventListener("change", () => void setIfcPinWindow(input.value === "window"));
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && IFC_PIN_WINDOW_KEY in changes) void show();
  });
  void show();
}

setupIfcPin();

// Gosplugin's made-up user, computer and network, and a way to make new ones.
function setupIdentity(): void {
  const list = byId("identity");
  const show = async () => {
    const identity = await storedIdentity();
    byId("identity-empty").hidden = identity !== undefined;
    list.replaceChildren(
      ...(identity
        ? ([
            ["Пользователь", identity.user],
            ["Компьютер", identity.computer],
            ["IP-адрес", identity.ip],
            ["MAC-адрес", identity.mac],
            ["Откуда", identity.source.startsWith("built-in") ? `встроенный набор ${identity.source.slice("built-in ".length)}` : identity.source],
          ] as const).flatMap(([name, value]) => {
            const term = document.createElement("dt");
            term.textContent = name;
            const definition = document.createElement("dd");
            definition.textContent = value;
            return [term, definition];
          })
        : []),
    );
  };
  byId("identity-new").addEventListener("click", async () => {
    byId("identity-status").textContent = "Запрашиваю генератор…";
    const identity = await newIdentity();
    byId("identity-status").textContent = identity.source === "fakerapi.it" ? "Готово." : "Генератор не ответил: взят встроенный набор.";
  });
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && IDENTITY_KEY in changes) void show();
  });
  void show();
}

setupIdentity();
