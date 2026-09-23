// Downloads the third-party files the test stand needs into vendor/ and checks
// each against the SHA-256 pinned in vendor-lock.json. A mismatch is an error:
// an upstream update must be reviewed and pinned by hand, never taken silently.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export interface VendorEntry {
  file: string;
  url: string;
  sha256: string;
}

export const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
export const vendorDir = join(repoRoot, "vendor");

export function readLock(): Record<string, VendorEntry> {
  return JSON.parse(readFileSync(join(repoRoot, "scripts", "vendor-lock.json"), "utf8"));
}

export function sha256File(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

export function vendorPath(name: string): string {
  const entry = readLock()[name];
  if (!entry) throw new Error(`unknown vendor entry: ${name}`);
  return join(vendorDir, entry.file);
}

function fetchEntry(name: string, entry: VendorEntry): void {
  const target = join(vendorDir, entry.file);
  if (existsSync(target) && sha256File(target) === entry.sha256) {
    console.log(`ok       ${name}: ${entry.file}`);
    return;
  }
  const partial = `${target}.part`;
  rmSync(partial, { force: true });
  // curl honours HTTPS_PROXY and the system CA store; Node's fetch does not.
  execFileSync("curl", ["-fsSL", "--retry", "3", "-o", partial, entry.url], { stdio: "inherit" });
  const actual = sha256File(partial);
  if (actual !== entry.sha256) {
    throw new Error(
      `${name}: SHA-256 mismatch for ${entry.url}\n  expected ${entry.sha256}\n  actual   ${actual}\n` +
        `The file stays at ${partial}. Review the new upstream version before pinning it in scripts/vendor-lock.json.`,
    );
  }
  renameSync(partial, target);
  console.log(`fetched  ${name}: ${entry.file}`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  mkdirSync(vendorDir, { recursive: true });
  for (const [name, entry] of Object.entries(readLock())) fetchEntry(name, entry);
}
