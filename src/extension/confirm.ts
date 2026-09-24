// The window asking whether a site may add a root certificate (install.ts): which site, which store, the
// certificate itself. Closing it is a no.
import { formatName } from "../page/dn.ts";
import { parseCertificate } from "../page/x509.ts";
import { CONFIRM_ANSWER, CONFIRM_DETAILS, CONFIRM_PING, CONFIRM_PING_MS, type ConfirmDetails } from "./install.ts";
import { base64ToDer, isSelfSigned } from "./roots.ts";

const byId = (id: string) => document.getElementById(id)!;
const button = (name: string) => document.querySelector<HTMLButtonElement>(`button[name=${name}]`)!;
const date = (value: Date) => value.toLocaleDateString("ru-RU", { timeZone: "UTC" });

const id = new URLSearchParams(location.search).get("id");

async function show(): Promise<void> {
  const details = (await chrome.runtime.sendMessage({ type: CONFIRM_DETAILS, id })) as ConfirmDetails | undefined;
  if (!details) {
    byId("request").textContent = "Запрос уже не действует.";
    button("install").disabled = true;
    return;
  }
  const certificate = parseCertificate(base64ToDer(details.certificate));
  const origin = document.createElement("strong");
  origin.textContent = details.origin;
  const store = details.store === "root" ? "«Доверенные корневые центры сертификации» (Root)" : "«Промежуточные центры сертификации» (CA)";
  byId("request").append("Сайт ", origin, ` просит добавить сертификат в хранилище ${store}.`);
  const fields = byId("fields");
  const add = (label: string, value: string) => {
    const term = document.createElement("dt");
    term.textContent = label;
    const text = document.createElement("dd");
    text.textContent = value;
    fields.append(term, text);
  };
  add("Кому выдан", formatName(certificate.subject));
  add("Кем выдан", isSelfSigned(certificate) ? "самоподписанный" : formatName(certificate.issuer));
  add("Действует", `с ${date(certificate.notBefore)} по ${date(certificate.notAfter)}`);
  add("Отпечаток SHA-1", certificate.thumbprint);
  byId("warning").textContent =
    "Расширение будет считать доверенными подписи и сертификаты, которые выдал этот центр. Устанавливайте, только если " +
    "доверяете ему и сверили отпечаток. Сертификат появится в настройках расширения на вкладке «Промежуточные и " +
    "сторонние корневые», там его можно выключить или удалить.";
  button("install").focus();
}

async function answer(install: boolean): Promise<void> {
  await chrome.runtime.sendMessage({ type: CONFIRM_ANSWER, id, install });
  window.close();
}

button("install").addEventListener("click", () => void answer(true));
button("cancel").addEventListener("click", () => void answer(false));
setInterval(() => void chrome.runtime.sendMessage({ type: CONFIRM_PING }), CONFIRM_PING_MS);
void show();
