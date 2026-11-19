// Which plug-ins page.js plays on a page: CryptoPro's, IFCPlugin (the old Gosuslugi plug-in), Gosplugin or
// Kontur.Plugin, any set of them, as the user turned them on for the site (src/extension/sites.ts). page.js must know at document_start, before
// any site script, and a MAIN-world script cannot read chrome.storage; so each set is registered as its own content
// script, page.js after one flag script per plug-in (modes/<plugin>.js, written by scripts/build.ts from modeScript).
// The flags run first in the same registration and leave the names in MODES_KEY, which page.js takes and deletes
// before the site's scripts run.

export type Plugin = "cryptopro" | "ifc" | "gos" | "kontur";

export const PLUGINS: readonly Plugin[] = ["cryptopro", "ifc", "gos", "kontur"];

export const MODE_FILES: Record<Plugin, string> = { cryptopro: "modes/cryptopro.js", ifc: "modes/ifc.js", gos: "modes/gos.js", kontur: "modes/kontur.js" };

export const MODES_KEY = "__cryptoproViaRutokenPlugins";

// The source of a plug-in's flag script.
export function modeScript(plugin: Plugin): string {
  return `(globalThis[${JSON.stringify(MODES_KEY)}] ||= []).push(${JSON.stringify(plugin)});\n`;
}

// The plug-ins the flag scripts named, in PLUGINS' order. Without flags, CryptoPro's alone: page.js registered by
// itself is CryptoPro's plug-in, as in the builds before IFCPlugin and Gosplugin.
export function takePlugins(global: Record<string, unknown>): Plugin[] {
  const flags = global[MODES_KEY];
  delete global[MODES_KEY];
  if (!Array.isArray(flags)) return ["cryptopro"];
  return PLUGINS.filter((plugin) => flags.includes(plugin));
}
