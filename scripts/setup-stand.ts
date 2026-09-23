// Builds the hardware-free test stand in stand/ from the files in vendor/:
// the real Rutoken Plugin (native host + plugin) with its bundled PKCS #11
// library replaced by the SoftHSMv2 fake Rutoken, a token store under a stand
// HOME, and the Rutoken adapter and CryptoPro's extension unpacked under their store ids. Nothing is
// installed into the system; everything a browser run needs is under stand/.
import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { developerKey, extensionIdFromKey, parseCrx } from "./crx.ts";
import { repoRoot, vendorPath } from "./fetch-vendor.ts";

export const standDir = join(repoRoot, "stand");
export const stand = {
  home: join(standDir, "home"),
  profile: join(standDir, "profile"),
  adapter: join(standDir, "adapter"),
  // CryptoPro's own browser extension, for checking that ours silences it on enabled sites. The
  // CryptoPro plug-in and CSP it talks to are not on the stand.
  cryptoproExtension: join(standDir, "cryptopro-extension"),
  pluginDir: join(standDir, "plugin", "opt", "aktivco", "rutokenplugin"),
  softhsm: join(standDir, "softhsm"),
};
export const adapterId = "ohedcglhbbfdgaogjhcclacoccbagkjg";
// The Manifest V3 CryptoPro extension, one of the ids cadesplugin_api.js loads nmcades_plugin_api.js from.
export const cryptoproExtensionId = "pfhgbfnnjiafkhfdkmpiflachepdcjod";
export const nativeHostName = "ru.rutoken.firewyrmhost";
// Factory PINs of a Rutoken ECP; the fake token is initialised with the same.
export const userPin = "12345678";
export const soPin = "87654321";
export const tokenLabel = "stand";

function run(cmd: string, args: string[], env: NodeJS.ProcessEnv = process.env): string {
  return execFileSync(cmd, args, { env, encoding: "utf8" });
}

export function standEnv(): NodeJS.ProcessEnv {
  // The portable SoftHSM reads only ~/softhsm/softhsm.conf, so the stand gets its own HOME.
  return { ...process.env, HOME: stand.home };
}

function setupPlugin(): void {
  run("dpkg-deb", ["-x", vendorPath("rutoken-plugin"), join(standDir, "plugin")]);
  run("unzip", ["-oq", vendorPath("softhsm-portable"), "-d", stand.softhsm]);
  // The v2.7.0-portable.42 archive stores its tools without the exec bit.
  for (const tool of ["softhsm2-util", "softhsm2-export"]) chmodSync(join(stand.softhsm, tool), 0o755);
  // The native host finds NPAPI plugins in /usr/lib/mozilla/plugins, /usr/lib64/mozilla/plugins and
  // ~/.mozilla/plugins; the plugin then loads librtpkcs11ecp.so from the directory it was loaded from
  // (a symlink is not resolved). So both go into the stand HOME, the PKCS #11 library being the fake Rutoken.
  const plugins = join(stand.home, ".mozilla", "plugins");
  mkdirSync(plugins, { recursive: true });
  symlinkSync(join(stand.pluginDir, "libnpRutokenPlugin.so"), join(plugins, "libnpRutokenPlugin.so"));
  symlinkSync(join(stand.softhsm, "libsofthsm2.so"), join(plugins, "librtpkcs11ecp.so"));
}

function setupToken(): void {
  mkdirSync(join(stand.home, "softhsm"), { recursive: true });
  writeFileSync(
    join(stand.home, "softhsm", "softhsm.conf"),
    ["directories.tokendir = tokens", "objectstore.backend = file", "log.level = ERROR", "FAKE_RUTOKEN_ECP = true", ""].join("\n"),
  );
  const util = join(stand.softhsm, "softhsm2-util");
  run(util, ["--init-token", "--slot", "0", "--label", tokenLabel, "--so-pin", soPin, "--pin", userPin], standEnv());
}

// A Chrome Web Store extension unpacked under its store id: sites and native hosts check the id.
function setupStoreExtension(vendorName: string, id: string, dir: string): void {
  const crx = parseCrx(readFileSync(vendorPath(vendorName)));
  const key = developerKey(crx);
  if (extensionIdFromKey(key) !== id) throw new Error(`${vendorName} CRX key does not give the store id`);
  mkdirSync(dir, { recursive: true });
  const zip = join(standDir, `${vendorName}.zip`);
  writeFileSync(zip, crx.zip);
  run("unzip", ["-oq", zip, "-d", dir]);
  rmSync(zip);
  // Chrome refuses an unpacked extension that carries the store's signature metadata.
  rmSync(join(dir, "_metadata"), { recursive: true, force: true });
  const manifestPath = join(dir, "manifest.json");
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  manifest.key = key.toString("base64");
  delete manifest.update_url;
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
}

function setupNativeHost(): void {
  const manifest = JSON.parse(readFileSync(join(stand.pluginDir, `${nativeHostName}.chrome.json`), "utf8"));
  manifest.path = join(stand.pluginDir, "FireWyrmNativeMessageHost");
  const text = JSON.stringify(manifest, null, 2);
  // Chromium looks in <user-data-dir>/NativeMessagingHosts and in ~/.config/chromium/NativeMessagingHosts.
  for (const dir of [join(stand.profile, "NativeMessagingHosts"), join(stand.home, ".config", "chromium", "NativeMessagingHosts")]) {
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, `${nativeHostName}.json`), text);
  }
}

export const venvPython = join(standDir, "venv", "bin", "python");

function setupPythonTools(): void {
  run("python3", ["-m", "venv", join(standDir, "venv")]);
  run(venvPython, ["-m", "pip", "install", "-q", "--require-hashes", "-r", join(repoRoot, "tests", "tools", "requirements.txt")]);
}

export function setupStand(): void {
  rmSync(standDir, { recursive: true, force: true });
  mkdirSync(standDir, { recursive: true });
  setupPlugin();
  setupToken();
  setupStoreExtension("rutoken-adapter", adapterId, stand.adapter);
  setupStoreExtension("cryptopro-extension", cryptoproExtensionId, stand.cryptoproExtension);
  setupNativeHost();
  setupPythonTools();
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  setupStand();
  console.log(`stand ready in ${standDir}`);
}
