// Builds the extension into dist/extension/ for Chrome and dist/firefox/ for Firefox, from the same code: the manifest
// with the version from package.json, the page-world script bundled into one file (a MAIN-world content script
// cannot import modules), and the extension's own pages and background script from src/extension/.
import { build } from "esbuild";
import { copyFileSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { repoRoot } from "./fetch-vendor.ts";

export const extensionDir = join(repoRoot, "dist", "extension");
export const firefoxDir = join(repoRoot, "dist", "firefox");
// The Firefox build's add-on id: the key of its storage and, once signed, of its AMO entry; never change it.
export const FIREFOX_ID = "cryptopro-via-rutoken@code-agent-43824";
// Firefox 128 is the first to run scripting.registerContentScripts in the MAIN world.
export const FIREFOX_MIN_VERSION = "128.0";

type Target = "chrome" | "firefox";
type Manifest = Record<string, unknown> & { background: { service_worker: string } };

// Firefox runs no extension service worker: the same script is its background script. Its manifest carries the
// add-on id and the minimum version instead of Chrome's; it declares that the extension collects no data, as AMO
// asks of new add-ons.
export function firefoxManifest(manifest: Manifest): Record<string, unknown> {
  const { minimum_chrome_version: _chrome, background, ...rest } = manifest;
  return {
    ...rest,
    background: { scripts: [background.service_worker] },
    browser_specific_settings: {
      gecko: { id: FIREFOX_ID, strict_min_version: FIREFOX_MIN_VERSION, data_collection_permissions: { required: ["none"] } },
    },
  };
}

// Only the canonicalizer of xmldsigjs goes into page.js (docs/JOURNAL.md, 2026-09-24): the package's entry
// point pulls in all of it, and its "exports" map hides the file, so it is reached by path. The same alias
// is in tsconfig.json (paths) and vitest.config.ts.
export const aliases = { "xmldsigjs-canonicalizer": join(repoRoot, "node_modules", "xmldsigjs", "build", "esm", "canonicalizer.js") };

export function packageVersion(): string {
  return JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8")).version;
}

async function buildTarget(target: Target, outDir: string): Promise<void> {
  rmSync(outDir, { recursive: true, force: true });
  mkdirSync(outDir, { recursive: true });
  const version = packageVersion();
  const manifest = JSON.parse(readFileSync(join(repoRoot, "src", "manifest.json"), "utf8")) as Manifest;
  manifest.version = version;
  writeFileSync(join(outDir, "manifest.json"), `${JSON.stringify(target === "firefox" ? firefoxManifest(manifest) : manifest, null, 2)}\n`);
  const common = {
    bundle: true,
    format: "iife",
    target: target === "firefox" ? `firefox${parseInt(FIREFOX_MIN_VERSION)}` : "chrome111",
    charset: "utf8",
    define: { __EXTENSION_VERSION__: JSON.stringify(version), __BROWSER__: JSON.stringify(target) },
    logLevel: "warning",
  } as const;
  await build({ ...common, entryPoints: [join(repoRoot, "src", "page", "main.ts")], outfile: join(outDir, "page.js"), alias: aliases });
  const extension = join(repoRoot, "src", "extension");
  await build({
    ...common,
    entryPoints: ["background", "popup", "options", "roots-bridge", "confirm", "tsa-access"].map((name) => join(extension, `${name}.ts`)),
    outdir: outDir,
  });
  for (const file of ["popup.html", "options.html", "confirm.html", "tsa-access.html", "ui.css"]) copyFileSync(join(extension, file), join(outDir, file));
  // page.js carries code of these MIT packages, whose licenses ask for their notice to go along.
  const notices = ["xmldsigjs", "xml-core", "@li0ard/gost", "@noble/curves", "@noble/hashes"].map((name) => `${name}\n\n${readFileSync(join(repoRoot, "node_modules", name, "LICENSE"), "utf8").trim()}\n`);
  writeFileSync(join(outDir, "THIRD-PARTY-LICENSES.txt"), `${notices.join("\n\n")}`);
}

export async function buildExtension(): Promise<void> {
  await buildTarget("chrome", extensionDir);
  await buildTarget("firefox", firefoxDir);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await buildExtension();
  console.log(`built ${extensionDir} and ${firefoxDir}`);
}
