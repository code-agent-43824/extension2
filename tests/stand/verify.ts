// Runs the independent Python tools on what the extension made: the verifiers (tests/tools/verify_cms.py,
// verify_xmldsig.py) on signatures, enveloped_info.py on encrypted messages; and the stand's timestamp service
// (tsa.py) for CAdES-T.
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { repoRoot } from "../../scripts/fetch-vendor.ts";
import { caDir } from "../../scripts/provision-token.ts";
import { venvPython } from "../../scripts/setup-stand.ts";

export interface VerifyReport {
  valid: boolean;
  detached: boolean;
  attributes: string[];
  unsigned_attributes: string[];
  signing_time?: string;
  checks: Record<string, boolean>;
  // A CAdES-T signature's timestamp.
  timestamp?: { policy: string; gen_time: string };
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

export interface EnvelopedInfo {
  content_encryption: string;
  recipients: { kind: string; key_encryption?: string; serial?: string; key_id?: string }[];
}

// What tests/tools/enveloped_info.py reads from a CMS EnvelopedData: the algorithms and the recipients.
export function envelopedInfo(cmsBase64: string): EnvelopedInfo {
  const dir = mkdtempSync(join(tmpdir(), "enveloped-"));
  try {
    const cmsPath = join(dir, "cms.b64");
    writeFileSync(cmsPath, cmsBase64);
    const run = spawnSync(venvPython, [join(repoRoot, "tests", "tools", "enveloped_info.py"), cmsPath], { encoding: "utf8" });
    if (run.status !== 0) throw new Error(`enveloped_info.py failed: ${run.stderr}`);
    return JSON.parse(run.stdout) as EnvelopedInfo;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

export interface TimestampService {
  url: string;
  close(): void;
}

// tests/tools/tsa.py on a free local port, its certificate issued by the stand's test CA.
export async function startTsa(): Promise<TimestampService> {
  const tsa = spawn(venvPython, [join(repoRoot, "tests", "tools", "tsa.py"), caDir], { stdio: ["ignore", "pipe", "inherit"] });
  const port = await new Promise<number>((resolve, reject) => {
    tsa.once("exit", (code) => reject(new Error(`tsa.py exited with ${code}`)));
    tsa.stdout.on("data", (chunk: Buffer) => {
      const match = /port (\d+)/.exec(chunk.toString());
      if (match) resolve(Number(match[1]));
    });
  });
  return { url: `http://127.0.0.1:${port}/tsp`, close: () => void tsa.kill() };
}

function der(tag: number, ...parts: Buffer[]): Buffer {
  const body = Buffer.concat(parts);
  const length = body.length < 0x80 ? [body.length] : [0x81, body.length];
  return Buffer.concat([Buffer.from([tag, ...length]), body]);
}

// The stand CA's key (gost_ca.py keeps it as big-endian hex) as PKCS#8 for OpenSSL's GOST engine: GOST R 34.10-2012
// 256 bit with the CryptoPro-A curve, the private key a little-endian OCTET STRING.
export function standCaKeyPem(): string {
  const key = Buffer.from(readFileSync(join(caDir, "ca.key"), "utf8").trim(), "hex").reverse();
  const oid = (hex: string) => der(0x06, Buffer.from(hex, "hex"));
  const algorithm = der(0x30, oid("2a85030701010101"), der(0x30, oid("2a850302022301"), oid("2a85030701010202")));
  const pkcs8 = der(0x30, der(0x02, Buffer.of(0)), algorithm, der(0x04, der(0x04, key)));
  return `-----BEGIN PRIVATE KEY-----\n${pkcs8.toString("base64")}\n-----END PRIVATE KEY-----\n`;
}
