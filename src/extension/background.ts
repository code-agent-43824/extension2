// Service worker: keeps the page-world script registered for exactly the enabled sites.
import { pruneSites, STORAGE_KEY, syncContentScript } from "./sites.ts";

// One sync at a time: two overlapping syncs would register the same script id twice.
let queue: Promise<unknown> = Promise.resolve();
function schedule(task: () => Promise<unknown>): void {
  queue = queue.then(task).catch((error: unknown) => console.error("КриптоПро через Рутокен:", error));
}

const sync = () => schedule(() => syncContentScript());

chrome.runtime.onInstalled.addListener(sync);
chrome.runtime.onStartup.addListener(sync);
chrome.permissions.onAdded.addListener(sync);
chrome.permissions.onRemoved.addListener(() => {
  schedule(() => pruneSites());
  sync();
});
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && STORAGE_KEY in changes) sync();
});
