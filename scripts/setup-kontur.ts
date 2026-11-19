// The real Kontur.Plugin as the stand's reference for stage 9 (docs/PLAN.md, action 56): its native host 4.15.1,
// unpacked under stand/kontur with the fork in place of the Rutoken library it carries, beside a copy of the stand HOME.
// Not part of the stand and not in CI: the package is an optional entry of vendor-lock.json, fetched here and never
// committed; tests/stand/kontur.ts talks to the host over Native Messaging. Needs a built stand; the host is a GTK
// program and opens its windows on X (Xvfb).
//
// Usage: node scripts/setup-kontur.ts
import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, rmSync, symlinkSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { fetchVendor } from "./fetch-vendor.ts";
import { stand, standDir } from "./setup-stand.ts";

const dir = join(standDir, "kontur");
export const kontur = {
  dir,
  home: join(dir, "home"),
  // The host finds its token libraries in pkcs11/ beside itself.
  host: join(dir, "opt", "kontur.plugin", "kontur.plugin.host"),
  rutokenLibrary: join(dir, "opt", "kontur.plugin", "pkcs11", "librtpkcs11ecp.so"),
  // The extension id the host lets talk to it (its native messaging manifest).
  origin: "chrome-extension://hnhppcgejeffnbnioloohhmndpmclaga/",
};

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  execFileSync("dpkg-deb", ["-x", fetchVendor("kontur-plugin"), dir]);
  rmSync(kontur.rutokenLibrary, { force: true });
  symlinkSync(join(stand.softhsm, "libsofthsm2.so"), kontur.rutokenLibrary);
  cpSync(stand.home, kontur.home, { recursive: true, verbatimSymlinks: true });
  console.log(`Kontur.Plugin ready in ${dir}`);
}
