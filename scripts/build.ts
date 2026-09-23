// Builds the extension into dist/extension/: the manifest with the version from package.json and
// the page-world script bundled into one file (a MAIN-world content script cannot import modules).
import { build } from "esbuild";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { repoRoot } from "./fetch-vendor.ts";

export const extensionDir = join(repoRoot, "dist", "extension");

export function packageVersion(): string {
  return JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8")).version;
}

export async function buildExtension(): Promise<void> {
  rmSync(extensionDir, { recursive: true, force: true });
  mkdirSync(extensionDir, { recursive: true });
  const version = packageVersion();
  const manifest = JSON.parse(readFileSync(join(repoRoot, "src", "manifest.json"), "utf8"));
  manifest.version = version;
  writeFileSync(join(extensionDir, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  await build({
    entryPoints: [join(repoRoot, "src", "page", "main.ts")],
    outfile: join(extensionDir, "page.js"),
    bundle: true,
    format: "iife",
    target: "chrome111",
    charset: "utf8",
    define: { __EXTENSION_VERSION__: JSON.stringify(version) },
    logLevel: "warning",
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await buildExtension();
  console.log(`built ${extensionDir}`);
}
