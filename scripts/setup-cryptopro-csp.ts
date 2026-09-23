// A local experiment, not part of the stand (docs/PLAN.md, action 10): installs the real CryptoPro CSP and
// CAdES Browser plug-in into this machine and prepares them for tests/stand/with-cryptopro-csp.spec.ts.
// It needs root (dpkg, and CryptoPro keeps keys and stores per system user) and a built stand.
//
// The packages are CryptoPro's licensed files and never go into git or vendor-lock.json: the CSP ones come
// from CryptoPro's site after logging in (linux-amd64_deb.tgz), cprocsp-pki-cades and cprocsp-pki-plugin from
// the public https://cryptopro.ru/sites/default/files/products/cades/current_release_2_0/cades-linux-amd64.tar.gz.
// Without a licence key the CSP runs as a demo for 90 days.
//
// Usage: node scripts/setup-cryptopro-csp.ts DIR_WITH_DEB_FILES
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cpSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { caDir } from "./provision-token.ts";
import { standDir, stand, venvPython } from "./setup-stand.ts";
import { repoRoot } from "./fetch-vendor.ts";

export const cryptoproCsp = {
  dir: join(standDir, "cryptopro-csp"),
  // A copy of the stand profile that also knows CryptoPro's native host, so the other stand tests keep
  // seeing a machine without the CryptoPro plug-in.
  profile: join(standDir, "cryptopro-csp", "profile"),
  // The plug-in asks the user before serving a site that is not on its trusted list, in a GTK window a
  // headless browser cannot show; the native host then quits. Trusted sites match the origin with its
  // port, so the demo page is served on a fixed one.
  pagePort: 8444,
  container: "\\\\.\\HDIMAGE\\stand-cryptopro",
  commonName: "КриптоПро на стенде",
};
export const cryptoproCspTrustedSites = [`http://127.0.0.1:${cryptoproCsp.pagePort}`, "https://testgost2012.cryptopro.ru"];

// In dependency order. pcscd and GTK are left out on purpose: no card reader and no display on the stand.
const packages = [
  "lsb-cprocsp-base",
  "lsb-cprocsp-rdr-64",
  "lsb-cprocsp-kc1-64",
  "lsb-cprocsp-capilite-64",
  "lsb-cprocsp-pkcs11-64",
  "cprocsp-rdr-pcsc-64",
  "cprocsp-rdr-rutoken-64",
  "lsb-cprocsp-ca-certs",
  "lsb-cprocsp-import-ca-certs",
  "cprocsp-rdr-gui-gtk-64",
  "cprocsp-pki-cades-64",
  "cprocsp-pki-plugin-64",
];

const bin = "/opt/cprocsp/bin/amd64";
const cpconfig = "/opt/cprocsp/sbin/amd64/cpconfig";
const nativeHostManifest = "/etc/opt/chrome/native-messaging-hosts/ru.cryptopro.nmcades.json";

// CryptoPro's tools read the console, not stdin: key generation wants key presses for its random number
// generator, installing a root certificate wants "o" to a prompt. They get a pseudo-terminal.
const ptyDriver = `
import os, pty, random, select, sys, time
mode = sys.argv[1]
pid, fd = pty.fork()
if pid == 0:
    os.execv(sys.argv[2], sys.argv[2:])
out = b""
deadline = time.time() + 120
while time.time() < deadline:
    ready, _, _ = select.select([fd], [], [], 0.1)
    if ready:
        try:
            data = os.read(fd, 4096)
        except OSError:
            break
        if not data:
            break
        out += data
        if mode == "confirm" and b"(o)" in data:
            os.write(fd, b"o\\n")
    elif mode == "keys":
        try:
            os.write(fd, bytes([random.choice(b"asdfghjkl")]))
        except OSError:
            break
        time.sleep(random.uniform(0.02, 0.15))
_, status = os.waitpid(pid, 0)
sys.stdout.buffer.write(out)
sys.exit(os.waitstatus_to_exitcode(status))
`;

function run(cmd: string, args: string[]): string {
  return execFileSync(cmd, args, { encoding: "utf8" });
}

function onTerminal(mode: "keys" | "confirm", cmd: string, args: string[]): void {
  const result = spawnSync("python3", ["-c", ptyDriver, mode, cmd, ...args], { encoding: "utf8" });
  if (result.status !== 0 || !result.stdout.includes("[ErrorCode: 0x00000000]")) {
    throw new Error(`${cmd} ${args.join(" ")} failed:\n${result.stdout}${result.stderr}`);
  }
}

function install(debDir: string): void {
  const files = readdirSync(debDir).filter((name) => name.endsWith(".deb"));
  const byPackage = new Map(files.map((name) => [run("dpkg-deb", ["-f", join(debDir, name), "Package"]).trim(), join(debDir, name)]));
  const missing = packages.filter((name) => !byPackage.has(name));
  if (missing.length) throw new Error(`missing packages in ${debDir}: ${missing.join(", ")}`);
  for (const name of packages) run("dpkg", ["-i", "--force-depends", byPackage.get(name)!]);
}

// A signature key in a CryptoPro file container, without a password (the plug-in would ask for it in a
// window), with a certificate from the stand's test CA; the CA goes into the user's root store.
function provisionContainer(): void {
  const work = join(cryptoproCsp.dir, "work");
  rmSync(work, { recursive: true, force: true });
  mkdirSync(work, { recursive: true });
  spawnSync(`${bin}/csptest`, ["-keyset", "-deletekeyset", "-container", cryptoproCsp.container]);
  spawnSync(`${bin}/certmgr`, ["-delete", "-store", "uMy", "-dn", `CN=${cryptoproCsp.commonName}`], { input: "" });
  const password = "12345678";
  onTerminal("keys", `${bin}/csptest`, ["-keyset", "-newkeyset", "-provtype", "80", "-container", cryptoproCsp.container, "-password", password, "-keytype", "signature"]);
  const request = join(work, "request.pem");
  onTerminal("keys", `${bin}/cryptcp`, [
    "-createrqst", "-rdn", `CN=${cryptoproCsp.commonName},O=Проверка,C=RU`, "-provtype", "80", "-nokeygen", "-sg",
    "-hashalg", "1.2.643.7.1.1.2.2", "-cont", cryptoproCsp.container, "-pin", password, "-base64", request,
  ]);
  run(`${bin}/csptest`, ["-passwd", "-change", "", "-container", cryptoproCsp.container, "-passwd", password]);
  const certificate = join(work, "certificate.pem");
  run(venvPython, [join(repoRoot, "tests", "tools", "gost_ca.py"), "issue", caDir, request, certificate]);
  const caPem = readFileSync(join(caDir, "ca.pem"), "utf8");
  const caThumbprint = createHash("sha1").update(Buffer.from(caPem.replace(/-----[^-]+-----|\s/g, ""), "base64")).digest("hex");
  if (!run(`${bin}/certmgr`, ["-list", "-store", "uRoot"]).includes(caThumbprint)) {
    onTerminal("confirm", `${bin}/certmgr`, ["-inst", "-store", "uRoot", "-file", join(caDir, "ca.pem")]);
  }
  run(`${bin}/certmgr`, ["-inst", "-store", "uMy", "-file", certificate, "-cont", cryptoproCsp.container, "-at_signature"]);
}

function setupBrowser(): void {
  run(cpconfig, ["-ini", "\\local\\Software\\Crypto Pro\\CAdESplugin", "-add", "multistring", "TrustedSites", ...cryptoproCspTrustedSites]);
  rmSync(cryptoproCsp.profile, { recursive: true, force: true });
  cpSync(stand.profile, cryptoproCsp.profile, { recursive: true, verbatimSymlinks: true });
  const hosts = join(cryptoproCsp.profile, "NativeMessagingHosts");
  mkdirSync(hosts, { recursive: true });
  writeFileSync(join(hosts, "ru.cryptopro.nmcades.json"), readFileSync(nativeHostManifest));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const debDir = process.argv[2];
  if (!debDir) {
    console.error("usage: node scripts/setup-cryptopro-csp.ts DIR_WITH_DEB_FILES");
    process.exit(2);
  }
  install(debDir);
  provisionContainer();
  setupBrowser();
  console.log(run(`${bin}/certmgr`, ["-list", "-store", "uMy"]).split("\n").filter((line) => /Subject|Container/.test(line)).join("\n"));
}
