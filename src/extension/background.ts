// Service worker: keeps the page-world script registered for exactly the enabled sites, adds the certificates sites
// add to the Root and CA stores, asking the user first for a root (install.ts), and gets XAdES-T's timestamps from the
// services the user let the extension reach (timestamps.ts).
import { ADD_MESSAGE, CONFIRM_ANSWER, CONFIRM_DETAILS, CONFIRM_PING, Installer, type AddMessage } from "./install.ts";
import { finishPendingSite, pruneSites, STORAGE_KEY, syncContentScript } from "./sites.ts";
import { TSA_ACCESS_MESSAGE, TSA_ANSWER, TSA_DETAILS, TSA_FETCH_MESSAGE, Timestamps, type TsaAccessMessage, type TsaFetchMessage, type TsaResult } from "./timestamps.ts";

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
const timestamps = new Timestamps();
const confirmPage = chrome.runtime.getURL("confirm.html");
const tsaPage = chrome.runtime.getURL("tsa-access.html");

const failed = (error: unknown): TsaResult => ({ error: { message: error instanceof Error ? error.message : String(error), code: 0x80004005 } });

chrome.runtime.onMessage.addListener((message: { type?: string; id?: unknown; install?: unknown; granted?: unknown }, sender, sendResponse) => {
  // Only the extension's windows answer for the user; a content script shares the extension's id, not its URL.
  if (sender.id === chrome.runtime.id && sender.url?.startsWith(confirmPage)) {
    if (message?.type === CONFIRM_DETAILS) sendResponse(installer.details(message.id));
    else if (message?.type === CONFIRM_ANSWER) sendResponse(installer.answer(message.id, message.install === true));
    else if (message?.type === CONFIRM_PING) sendResponse(true);
    return false;
  }
  if (sender.id === chrome.runtime.id && sender.url?.startsWith(tsaPage)) {
    if (message?.type === TSA_DETAILS) sendResponse(timestamps.details(message.id));
    else if (message?.type === TSA_ANSWER) sendResponse(timestamps.answer(message.id, message.granted === true));
    else if (message?.type === CONFIRM_PING) sendResponse(true);
    return false;
  }
  if (sender.id !== chrome.runtime.id || !sender.tab) return false;
  if (message?.type === ADD_MESSAGE) {
    installer.add(message as Partial<AddMessage>, sender.url).then(sendResponse, (error: unknown) => sendResponse(failed(error)));
    return true;
  }
  if (message?.type === TSA_ACCESS_MESSAGE) {
    timestamps.access(message as Partial<TsaAccessMessage>, sender.url).then(sendResponse, (error: unknown) => sendResponse(failed(error)));
    return true;
  }
  if (message?.type === TSA_FETCH_MESSAGE) {
    timestamps.request(message as Partial<TsaFetchMessage>, sender.url).then(sendResponse, (error: unknown) => sendResponse(failed(error)));
    return true;
  }
  return false;
});
chrome.windows.onRemoved.addListener((windowId) => {
  installer.windowClosed(windowId);
  timestamps.windowClosed(windowId);
});
