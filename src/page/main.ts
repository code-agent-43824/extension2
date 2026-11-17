// Page-world content script, injected at document_start before any site script, as the plug-ins the user turned on
// for the site (modes.ts). The site's own cadesplugin_api.js returns early when window.cadesplugin already exists, so
// ours stays in place.
import { createCadesplugin } from "./cadesplugin.ts";
import { takePlugins } from "./modes.ts";

const page = window as unknown as Window & Record<string | symbol, unknown>;
const plugins = takePlugins(page);
// While the service worker moves a site to another set of plug-ins, a page may get page.js from both registrations
// (src/extension/sites.ts): the first one to run plays its set, the second stands aside.
const RUNNING = Symbol.for("cryptopro-via-rutoken.page");
if (!page[RUNNING]) {
  Object.defineProperty(page, RUNNING, { value: true });
  if (plugins.includes("cryptopro") && !page.cadesplugin) {
    page.cadesplugin = createCadesplugin(page, {
      setTimeout: (callback, ms) => window.setTimeout(callback, ms),
      now: () => Date.now(),
    });
  }
}
