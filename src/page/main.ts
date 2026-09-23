// Page-world content script, injected at document_start before any site script. The site's own
// cadesplugin_api.js returns early when window.cadesplugin already exists, so ours stays in place.
import { createCadesplugin } from "./cadesplugin.ts";

const page = window as unknown as Window & Record<string, unknown>;
if (!page.cadesplugin) {
  page.cadesplugin = createCadesplugin(page, {
    setTimeout: (callback, ms) => window.setTimeout(callback, ms),
    now: () => Date.now(),
  });
}
