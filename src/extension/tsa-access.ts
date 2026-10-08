// The window asking whether the extension may reach a timestamp service for a site's XAdES-T signature
// (timestamps.ts). «Разрешить» makes Chrome's own permission request for the service's address, which only a click in
// an extension page may do, and reports what Chrome answered; «Отмена» and closing the window are a no.
import { CONFIRM_PING, CONFIRM_PING_MS } from "./install.ts";
import { matchPattern, siteOf } from "./sites.ts";
import { TSA_ANSWER, TSA_DETAILS, type TsaAccessDetails } from "./timestamps.ts";

const byId = (id: string) => document.getElementById(id)!;
const button = (name: string) => document.querySelector<HTMLButtonElement>(`button[name=${name}]`)!;
const strong = (text: string) => Object.assign(document.createElement("strong"), { textContent: text });

const id = new URLSearchParams(location.search).get("id");
let service: string | undefined;

async function show(): Promise<void> {
  const details = (await chrome.runtime.sendMessage({ type: TSA_DETAILS, id })) as TsaAccessDetails | undefined;
  service = siteOf(details?.url);
  if (!details || !service) {
    byId("request").textContent = "Запрос уже не действует.";
    return;
  }
  byId("request").append("Сайт ", strong(details.origin), " просит подписать XML-документ подписью XAdES-T со штампом времени службы ", strong(details.url), ".");
  byId("what").append(
    "Чтобы получить штамп, расширению нужен доступ к ",
    strong(service),
    ": туда уходит только хеш подписи. Если у расширения ещё нет доступа к этому адресу, после «Разрешить» Chrome спросит о нём сам.",
  );
  byId("where").textContent = "Доступ можно забрать в Chrome: «Расширения» → это расширение → «Доступ к сайтам».";
  button("allow").disabled = false;
  button("cancel").focus();
}

// Chrome's request comes first, while the click still counts as the user's.
async function allow(): Promise<void> {
  let granted = false;
  try {
    granted = await chrome.permissions.request({ origins: [matchPattern(service!)] });
  } catch (error) {
    console.error(error);
  }
  await chrome.runtime.sendMessage({ type: TSA_ANSWER, id, granted });
  window.close();
}

async function cancel(): Promise<void> {
  await chrome.runtime.sendMessage({ type: TSA_ANSWER, id, granted: false });
  window.close();
}

button("allow").addEventListener("click", () => void allow());
button("cancel").addEventListener("click", () => void cancel());
setInterval(() => void chrome.runtime.sendMessage({ type: CONFIRM_PING }), CONFIRM_PING_MS);
void show();
