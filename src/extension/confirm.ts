// The window asking whether a site may add a root certificate (install.ts), worded after Windows' security
// warning for a new root (the owner's wish, docs/PLAN.md, action 22): who the CA says it is, the site asking,
// the thumbprint to check, the risk, and Да/Нет. Closing it is a no.
import { commonName } from "../page/signing.ts";
import { parseCertificate } from "../page/x509.ts";
import { CONFIRM_ANSWER, CONFIRM_DETAILS, CONFIRM_PING, CONFIRM_PING_MS, type ConfirmDetails } from "./install.ts";
import { base64ToDer } from "./roots.ts";

const byId = (id: string) => document.getElementById(id)!;
const button = (name: string) => document.querySelector<HTMLButtonElement>(`button[name=${name}]`)!;
const strong = (text: string) => Object.assign(document.createElement("strong"), { textContent: text });

// As Windows shows it: upper case, in groups of eight.
const groupedThumbprint = (thumbprint: string) => thumbprint.toUpperCase().match(/.{1,8}/g)!.join(" ");

const id = new URLSearchParams(location.search).get("id");

async function show(): Promise<void> {
  const details = (await chrome.runtime.sendMessage({ type: CONFIRM_DETAILS, id })) as ConfirmDetails | undefined;
  if (!details) {
    byId("request").textContent = "Запрос уже не действует.";
    button("install").disabled = true;
    return;
  }
  const certificate = parseCertificate(base64ToDer(details.certificate));
  const name = commonName(certificate.subject);
  byId("subject").append("Вы собираетесь установить сертификат от центра сертификации (ЦС), утверждающего, что он представляет:", document.createElement("br"), strong(name));
  const store = details.store === "root" ? "«Доверенные корневые центры сертификации» (Root)" : "«Промежуточные центры сертификации» (CA)";
  byId("request").append(
    "Его устанавливает сайт ",
    strong(details.origin),
    ` в хранилище ${store}. Расширение не может проверить, что сертификат действительно получен от «${name}». ` +
      `Обратитесь к «${name}» для подтверждения его происхождения. В этом поможет отпечаток:`,
  );
  byId("fingerprint").append("Отпечаток (sha1): ", strong(groupedThumbprint(certificate.thumbprint)));
  byId("danger").append(
    strong("Предупреждение:"),
    " если вы установите этот корневой сертификат, расширение будет автоматически доверять любому сертификату, " +
      "выданному этим ЦС. Установка сертификата с неподтверждённым отпечатком представляет риск для безопасности. " +
      "Если вы нажмёте кнопку «Да», вы принимаете на себя этот риск.",
  );
  byId("where").textContent =
    "Сертификат появится в настройках расширения на вкладке «Промежуточные и сторонние корневые», там его можно " +
    "выключить или удалить.";
  button("cancel").focus();
}

async function answer(install: boolean): Promise<void> {
  await chrome.runtime.sendMessage({ type: CONFIRM_ANSWER, id, install });
  window.close();
}

button("install").addEventListener("click", () => void answer(true));
button("cancel").addEventListener("click", () => void answer(false));
setInterval(() => void chrome.runtime.sendMessage({ type: CONFIRM_PING }), CONFIRM_PING_MS);
void show();
