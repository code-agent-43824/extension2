import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { konturHost } from "./tests/stand/kontur.ts";
// One host per step; each answer printed.
const step = async (type: string, fields: Record<string, unknown>) => {
  const host = konturHost();
  try { const a = await host.ask(type, fields, { timeoutMs: 20000 }); return a.error ? { error: a.error } : { result: a.result }; }
  catch { return "TIMEOUT"; } finally { host.close(); }
};
const provider = ((await step("crypto.provider.search", { cryptoProviderType: "pkcs11" })) as any).result[0];
const made = ((await step("crypto.createCertRequest", { cryptoProvider: provider, sink: { type: "base64" }, subject: { type: "base64", data: "MBAxDjAMBgNVBAMMBVByb2Jl" }, extensions: { type: "base64", data: "MAA=" }, signatureAlgorithm: "1.2.643.7.1.1.3.2" })) as any).result;
const container = made.path.split("\\").pop();
const dir = mkdtempSync("/tmp/claude-0/-home-user-extension2/8e034ad6-4794-5291-97c5-82f6769df993/scratchpad/ca-");
writeFileSync(join(dir, "req.pem"), `-----BEGIN CERTIFICATE REQUEST-----\n${made.request.data}\n-----END CERTIFICATE REQUEST-----\n`);
execFileSync("stand/venv/bin/python", ["tests/tools/gost_ca.py", "issue", "stand/ca", join(dir, "req.pem"), join(dir, "cert.pem")]);
const cert = readFileSync(join(dir, "cert.pem"), "utf8").replace(/-----[^-]+-----|\s/g, "");
const other = readFileSync("stand/user.pem", "utf8").replace(/-----[^-]+-----|\s/g, "");
const cases: [string, Record<string, unknown>][] = JSON.parse(process.argv[2]!.replace(/\$CERT/g, cert).replace(/\$OTHER/g, other).replace(/\$CONTAINER/g, container).replace(/"\$PROVIDER"/g, JSON.stringify(provider)));
for (const [type, fields] of cases) console.log(type, JSON.stringify(fields).replace(cert, "<cert>").replace(other, "<user>").slice(0, 250), "=>", JSON.stringify(await step(type, fields)).slice(0, 500));
process.exit(0);
