// The certificate stores' part of the options page, a tab each (roots.ts): a card per certificate, with switches
// for each, for all and for the store as a whole, and removal; on the second tab, adding certificates from files.
import { formatName, type Name } from "../page/dn.ts";
import { algorithmName, type X509 } from "../page/x509.ts";
import {
  addCertificates,
  certificateOf,
  certificateStores,
  EXTRA_KEY,
  isSelfSigned,
  removeCertificate,
  ROOTS_KEY,
  setAllEnabled,
  setCertificateEnabled,
  setStoreEnabled,
  type Tab,
} from "./roots.ts";

const tabs: Tab[] = ["roots", "extra"];

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

function card(tab: Tab, certificate: X509, enabled: boolean): HTMLLIElement {
  const subject = formatName(certificate.subject);
  const issuer = formatName(certificate.issuer);
  const item = element("li", undefined, enabled ? "card" : "card off");
  item.dataset.thumbprint = certificate.thumbprint;

  const title = element("h2", commonName(certificate.subject) ?? subject);
  const badges = element("span", undefined, "badges");
  if (tab === "roots") badges.append(element("span", "встроенный", "badge"));
  else badges.append(isSelfSigned(certificate) ? element("span", "корневой", "badge") : element("span", "промежуточный", "badge other"));
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
  checkbox.addEventListener("change", () => void setCertificateEnabled(tab, certificate.thumbprint, checkbox.checked));
  toggle.append(checkbox, " Включён");
  const remove = element("button", "Удалить");
  remove.type = "button";
  remove.name = "remove";
  remove.addEventListener("click", () => {
    if (confirm(`Удалить сертификат «${title.firstChild?.textContent}» из хранилища?`)) void removeCertificate(tab, certificate.thumbprint);
  });
  actions.append(toggle, remove);

  item.append(title, fields, names, actions);
  return item;
}

async function render(): Promise<void> {
  const stores = await certificateStores();
  for (const tab of tabs) {
    const store = stores[tab];
    const certificates = store.certificates.map((root) => ({ certificate: certificateOf(root), enabled: root.enabled }));
    const storeSwitch = document.querySelector<HTMLInputElement>(`input[name=${tab}-enabled]`)!;
    storeSwitch.checked = store.enabled;
    byId(tab).classList.toggle("off", !store.enabled);
    byId(tab).replaceChildren(...certificates.map(({ certificate, enabled }) => card(tab, certificate, enabled)));
    byId(`${tab}-empty`).hidden = certificates.length > 0;
    const on = certificates.filter(({ enabled }) => enabled).length;
    byId(`${tab}-count`).textContent = `Включено ${on} из ${certificates.length}${store.enabled ? "" : ", хранилище выключено"}`;
  }
}

function selectTab(selected: Tab): void {
  for (const tab of tabs) {
    byId(`tab-${tab}`).setAttribute("aria-selected", String(tab === selected));
    byId(`panel-${tab}`).hidden = tab !== selected;
  }
}

export function setupRoots(): void {
  for (const tab of tabs) {
    byId(`tab-${tab}`).addEventListener("click", () => selectTab(tab));
    const storeSwitch = document.querySelector<HTMLInputElement>(`input[name=${tab}-enabled]`)!;
    storeSwitch.addEventListener("change", () => void setStoreEnabled(tab, storeSwitch.checked));
    byId(`${tab}-all-on`).addEventListener("click", () => void setAllEnabled(tab, true));
    byId(`${tab}-all-off`).addEventListener("click", () => void setAllEnabled(tab, false));
  }

  const form = byId("extra-add") as HTMLFormElement;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const input = form.elements.namedItem("files") as HTMLInputElement;
    const lines: string[] = [];
    const name = (certificate: X509) => commonName(certificate.subject) ?? certificate.thumbprint;
    const kind = (certificate: X509) => `${name(certificate)} (${isSelfSigned(certificate) ? "корневой" : "промежуточный"})`;
    for (const file of input.files ?? []) {
      try {
        const { added, restored, present } = await addCertificates(new Uint8Array(await file.arrayBuffer()));
        if (added.length) lines.push(`${file.name}: добавлен ${added.map(kind).join(", ")}`);
        if (restored.length) lines.push(`${file.name}: встроенный ${restored.map(name).join(", ")} возвращён на вкладку «Корневые»`);
        if (present.length) lines.push(`${file.name}: уже есть ${present.map(name).join(", ")}`);
      } catch (error) {
        lines.push(`${file.name}: ${(error as Error).message}`);
      }
    }
    byId("extra-message").textContent = lines.join("\n");
    form.reset();
  });

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && (ROOTS_KEY in changes || EXTRA_KEY in changes)) void render();
  });
  void render();
}
