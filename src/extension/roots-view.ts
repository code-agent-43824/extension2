// The root store's part of the options page: a card per certificate, with switches for each, for all and for
// the store as a whole, removal, and adding certificates from files.
import { formatName, type Name } from "../page/dn.ts";
import { algorithmName, type X509 } from "../page/x509.ts";
import {
  addRoots,
  certificateOf,
  isBuiltin,
  removeRoot,
  rootStore,
  ROOTS_KEY,
  setAllRootsEnabled,
  setRootEnabled,
  setStoreEnabled,
} from "./roots.ts";

const byId = (id: string) => document.getElementById(id)!;

const commonName = (name: Name) => name.flat().find((attribute) => attribute.oid === "2.5.4.3")?.value;
// RSA has no CryptoPro name among the page's GOST ones; one of the built-in roots is RSA.
const algorithm = (oid: string) => (oid === "1.2.840.113549.1.1.1" ? "RSA" : algorithmName(oid));
const date = (value: Date) => value.toLocaleDateString("ru-RU", { timeZone: "UTC" });

function element<K extends keyof HTMLElementTagNameMap>(tag: K, text?: string, className?: string): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function card(certificate: X509, enabled: boolean): HTMLLIElement {
  const subject = formatName(certificate.subject);
  const issuer = formatName(certificate.issuer);
  const item = element("li", undefined, enabled ? "card" : "card off");
  item.dataset.thumbprint = certificate.thumbprint;

  const title = element("h2", commonName(certificate.subject) ?? subject);
  const badges = element("span", undefined, "badges");
  if (isBuiltin(certificate.thumbprint)) badges.append(element("span", "встроенный", "badge"));
  const now = new Date();
  if (certificate.notAfter < now) badges.append(element("span", "истёк", "badge bad"));
  else if (certificate.notBefore > now) badges.append(element("span", "ещё не действует", "badge bad"));
  title.append(badges);

  const fields = element("dl");
  const add = (label: string, value: string) => fields.append(element("dt", label), element("dd", value));
  add("Кем выдан", issuer === subject ? "самоподписанный" : (commonName(certificate.issuer) ?? issuer));
  add("Действует", `с ${date(certificate.notBefore)} по ${date(certificate.notAfter)}`);
  add("Алгоритм", algorithm(certificate.publicKeyAlgorithm));
  add("Отпечаток SHA-1", certificate.thumbprint);
  add("Серийный номер", certificate.serialNumber);

  const names = element("details");
  names.append(element("summary", "Полные имена"), element("p", `Владелец: ${subject}`), element("p", `Издатель: ${issuer}`));

  const actions = element("div", undefined, "actions");
  const toggle = element("label");
  const checkbox = element("input");
  checkbox.type = "checkbox";
  checkbox.name = "enabled";
  checkbox.checked = enabled;
  checkbox.addEventListener("change", () => void setRootEnabled(certificate.thumbprint, checkbox.checked));
  toggle.append(checkbox, " Включён");
  const remove = element("button", "Удалить");
  remove.type = "button";
  remove.name = "remove";
  remove.addEventListener("click", () => {
    if (confirm(`Удалить сертификат «${title.firstChild?.textContent}» из хранилища?`)) void removeRoot(certificate.thumbprint);
  });
  actions.append(toggle, remove);

  item.append(title, fields, names, actions);
  return item;
}

async function render(): Promise<void> {
  const store = await rootStore();
  const certificates = store.certificates.map((root) => ({ certificate: certificateOf(root), enabled: root.enabled }));
  const storeSwitch = document.querySelector<HTMLInputElement>("input[name=roots-enabled]")!;
  storeSwitch.checked = store.enabled;
  byId("roots").classList.toggle("off", !store.enabled);
  byId("roots").replaceChildren(...certificates.map(({ certificate, enabled }) => card(certificate, enabled)));
  byId("roots-empty").hidden = certificates.length > 0;
  const on = certificates.filter(({ enabled }) => enabled).length;
  byId("roots-count").textContent = `Включено ${on} из ${certificates.length}${store.enabled ? "" : ", хранилище выключено"}`;
}

export function setupRoots(): void {
  const storeSwitch = document.querySelector<HTMLInputElement>("input[name=roots-enabled]")!;
  storeSwitch.addEventListener("change", () => void setStoreEnabled(storeSwitch.checked));
  byId("roots-all-on").addEventListener("click", () => void setAllRootsEnabled(true));
  byId("roots-all-off").addEventListener("click", () => void setAllRootsEnabled(false));

  const form = byId("roots-add") as HTMLFormElement;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const input = form.elements.namedItem("files") as HTMLInputElement;
    const lines: string[] = [];
    for (const file of input.files ?? []) {
      try {
        const { added, present } = await addRoots(new Uint8Array(await file.arrayBuffer()));
        const name = (certificate: X509) => commonName(certificate.subject) ?? certificate.thumbprint;
        if (added.length) lines.push(`${file.name}: добавлен ${added.map(name).join(", ")}`);
        if (present.length) lines.push(`${file.name}: уже есть ${present.map(name).join(", ")}`);
      } catch (error) {
        lines.push(`${file.name}: ${(error as Error).message}`);
      }
    }
    byId("roots-message").textContent = lines.join("\n");
    form.reset();
  });

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && ROOTS_KEY in changes) void render();
  });
  void render();
}
