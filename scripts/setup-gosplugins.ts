// The real Gosuslugi plug-ins as the stand's reference for stage 8 (docs/PLAN.md, action 43): the cores of IFCPlugin 3.1.1
// and of Gosplugin 1.3.43.1, unpacked under stand/gosplugins with the fork in place of their Rutoken library, beside a copy
// of the stand HOME with a 256-bit and a 512-bit key both can use. Not part of the stand and not in CI: the packages are
// optional entries of vendor-lock.json, fetched here; tests/stand/gosplugins.ts talks to the cores over Native Messaging.
// Needs a built stand; Gosplugin's core shows its PIN window on X (Xvfb, typed into with xdotool).
//
// Usage: node scripts/setup-gosplugins.ts
import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { fetchVendor } from "./fetch-vendor.ts";
import { provisionKey } from "./provision-token.ts";
import { stand, standDir } from "./setup-stand.ts";

const dir = join(standDir, "gosplugins");
export const gosplugins = {
  dir,
  home: join(dir, "home"),
  ifc: {
    host: join(dir, "ifc", "usr", "bin", "ifc_chrome_host"),
    lib: join(dir, "ifc", "usr", "lib", "mozilla", "plugins", "lib"),
    config: join(dir, "ifc", "etc", "ifc.cfg"),
  },
  gos: {
    root: join(dir, "gos", "opt", "iitrust", "gosuslugi_plugin"),
    binary: join(dir, "gos", "opt", "iitrust", "gosuslugi_plugin", "bin", "gosuslugi_plugin"),
  },
  // Names of the keys provisioned into the HOME copy (their certificates are stand/gosplugins/<name>.pem).
  keys: { gost256: "gosplugins/user256", gost512: "gosplugins/user512" },
};

const fork = () => join(stand.softhsm, "libsofthsm2.so");

function replaceWithFork(library: string): void {
  rmSync(library, { force: true });
  symlinkSync(fork(), library);
}

function setupIfc(): void {
  const root = join(dir, "ifc");
  rmSync(root, { recursive: true, force: true });
  execFileSync("dpkg-deb", ["-x", fetchVendor("ifcplugin"), root]);
  replaceWithFork(join(gosplugins.ifc.lib, "librtpkcs11ecp.so"));
}

// The installer is a ZIP holding a shell script whose tail, after the line "PAYLOAD:", is a tar with the package.
function setupGos(): void {
  const root = join(dir, "gos");
  const work = join(dir, "gos-installer");
  rmSync(root, { recursive: true, force: true });
  rmSync(work, { recursive: true, force: true });
  mkdirSync(work, { recursive: true });
  execFileSync("unzip", ["-q", fetchVendor("gosplugin"), "-d", work]);
  const script = readFileSync(join(work, readdirSync(work).find((name) => name.endsWith(".sh"))!));
  const marker = Buffer.from("\nPAYLOAD:\n");
  writeFileSync(join(work, "payload.tar"), script.subarray(script.indexOf(marker) + marker.length));
  execFileSync("tar", ["-xf", join(work, "payload.tar"), "-C", work]);
  const deb = readdirSync(work).find((name) => name.endsWith(".deb"))!;
  execFileSync("dpkg-deb", ["-x", join(work, deb), root]);
  rmSync(work, { recursive: true, force: true });
  replaceWithFork(join(gosplugins.gos.root, "bin", "tokens", "librtpkcs11ecp.so"));
}

async function provisionHome(): Promise<void> {
  rmSync(gosplugins.home, { recursive: true, force: true });
  cpSync(stand.home, gosplugins.home, { recursive: true, verbatimSymlinks: true });
  for (const [bits, name] of [[256, gosplugins.keys.gost256], [512, gosplugins.keys.gost512]] as const) {
    mkdirSync(join(standDir, "gosplugins"), { recursive: true });
    await provisionKey({ home: gosplugins.home, bits, name, ifcNameableId: true, subject: [{ rdn: "commonName", value: `Госплагин ${bits}` }, { rdn: "countryName", value: "RU" }] });
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  mkdirSync(dir, { recursive: true });
  setupIfc();
  setupGos();
  await provisionHome();
  console.log(`gosplugins ready in ${dir}`);
}
