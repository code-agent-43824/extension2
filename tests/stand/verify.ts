// Runs the independent Python verifier (tests/tools/verify_cms.py) on a CMS signature.
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { repoRoot } from "../../scripts/fetch-vendor.ts";
import { caDir } from "../../scripts/provision-token.ts";
import { venvPython } from "../../scripts/setup-stand.ts";

export interface VerifyReport {
  valid: boolean;
  detached: boolean;
  attributes: string[];
  signing_time?: string;
  checks: Record<string, boolean>;
}

export function verifyCms(cmsBase64: string, content?: Uint8Array): VerifyReport {
  const dir = mkdtempSync(join(tmpdir(), "verify-cms-"));
  try {
    const cmsPath = join(dir, "cms.b64");
    writeFileSync(cmsPath, cmsBase64);
    const args = [join(repoRoot, "tests", "tools", "verify_cms.py"), cmsPath, join(caDir, "ca.pem")];
    if (content) {
      writeFileSync(join(dir, "content"), content);
      args.push(join(dir, "content"));
    }
    const run = spawnSync(venvPython, args, { encoding: "utf8" });
    if (!run.stdout.trim()) throw new Error(`verify_cms.py failed: ${run.stderr}`);
    return JSON.parse(run.stdout) as VerifyReport;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
