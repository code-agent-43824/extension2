// Runs the independent Python verifiers (tests/tools/verify_cms.py, verify_xmldsig.py) on signatures.
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

// caPem defaults to the stand's test CA; the testgost experiment passes CryptoPro's test CA.
export function verifyCms(cmsBase64: string, content?: Uint8Array, caPem = join(caDir, "ca.pem")): VerifyReport {
  const dir = mkdtempSync(join(tmpdir(), "verify-cms-"));
  try {
    const cmsPath = join(dir, "cms.b64");
    writeFileSync(cmsPath, cmsBase64);
    const args = [join(repoRoot, "tests", "tools", "verify_cms.py"), cmsPath, caPem];
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

export interface XmlVerifyReport {
  valid: boolean;
  signatures: { signature_method: string; references: { uri: string; digest_method: string; digest: boolean }[]; checks: Record<string, boolean> }[];
}

// Runs tests/tools/verify_xmldsig.py on a signed XML document; caPem as for verifyCms.
export function verifyXml(xml: string, caPem = join(caDir, "ca.pem")): XmlVerifyReport {
  const dir = mkdtempSync(join(tmpdir(), "verify-xml-"));
  try {
    const xmlPath = join(dir, "signed.xml");
    writeFileSync(xmlPath, xml);
    const run = spawnSync(venvPython, [join(repoRoot, "tests", "tools", "verify_xmldsig.py"), xmlPath, caPem], { encoding: "utf8" });
    if (!run.stdout.trim()) throw new Error(`verify_xmldsig.py failed: ${run.stderr}`);
    return JSON.parse(run.stdout) as XmlVerifyReport;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
