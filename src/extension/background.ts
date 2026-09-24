// Service worker: keeps the page-world script registered for exactly the enabled sites, and adds the
// certificates sites add to the Root and CA stores, asking the user first for a root (install.ts).
import { ADD_MESSAGE, CONFIRM_ANSWER, CONFIRM_DETAILS, CONFIRM_PING, Installer, type AddMessage } from "./install.ts";
import { finishPendingSite, pruneSites, STORAGE_KEY, syncContentScript } from "./sites.ts";

// One sync at a time: two overlapping syncs would register the same script id twice.
let queue: Promise<unknown> = Promise.resolve();
function schedule(task: () => Promise<unknown>): void {
  queue = queue.then(task).catch((error: unknown) => console.error("КриптоПро через Рутокен:", error));
}

const sync = () => schedule(() => syncContentScript());

chrome.runtime.onInstalled.addListener(sync);
chrome.runtime.onStartup.addListener(sync);
chrome.permissions.onAdded.addListener(() => {
  schedule(() => finishPendingSite());
  sync();
});
chrome.permissions.onRemoved.addListener(() => {
  schedule(() => pruneSites());
  sync();
});
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && STORAGE_KEY in changes) sync();
});

const installer = new Installer();
const confirmPage = chrome.runtime.getURL("confirm.html");

chrome.runtime.onMessage.addListener((message: { type?: string; id?: unknown; install?: unknown }, sender, sendResponse) => {
  // Only the confirmation window answers for the user; a content script shares the extension's id, not its URL.
  if (sender.id === chrome.runtime.id && sender.url?.startsWith(confirmPage)) {
    if (message?.type === CONFIRM_DETAILS) sendResponse(installer.details(message.id));
    else if (message?.type === CONFIRM_ANSWER) sendResponse(installer.answer(message.id, message.install === true));
    else if (message?.type === CONFIRM_PING) sendResponse(true);
    return false;
  }
  if (message?.type === ADD_MESSAGE && sender.id === chrome.runtime.id && sender.tab) {
    installer.add(message as Partial<AddMessage>, sender.url).then(sendResponse, (error: unknown) =>
      sendResponse({ error: { message: error instanceof Error ? error.message : String(error), code: 0x80004005 } }),
    );
    return true;
  }
  return false;
});
chrome.windows.onRemoved.addListener((windowId) => installer.windowClosed(windowId));
