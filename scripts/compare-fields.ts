// Compares two dumps from tools/dump-fields.js: one made with the real CryptoPro, one with our
// extension. Certificates are matched by thumbprint. Prints every value that differs or is missing on
// one side; exits 1 when there is any. Usage: node scripts/compare-fields.ts CRYPTOPRO.json OURS.json
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

export interface Difference {
  path: string;
  cryptopro: Json | undefined;
  ours: Json | undefined;
}

function isObject(value: Json | undefined): value is { [key: string]: Json } {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function walk(path: string, a: Json | undefined, b: Json | undefined, out: Difference[]): void {
  if (isObject(a) && isObject(b)) {
    for (const key of new Set([...Object.keys(a), ...Object.keys(b)])) walk(`${path}.${key}`, a[key], b[key], out);
    return;
  }
  if (JSON.stringify(a) !== JSON.stringify(b)) out.push({ path, cryptopro: a, ours: b });
}

export type Dump = { about?: Json; certificates?: { [key: string]: Json }[] };

export function compareDumps(cryptopro: Dump, ours: Dump): Difference[] {
  const out: Difference[] = [];
  walk("about", cryptopro.about, ours.about, out);
  const byThumbprint = (dump: Dump) => new Map((dump.certificates ?? []).map((c) => [String(c.Thumbprint), c]));
  const a = byThumbprint(cryptopro);
  const b = byThumbprint(ours);
  for (const thumbprint of new Set([...a.keys(), ...b.keys()])) {
    walk(`certificate ${thumbprint}`, a.get(thumbprint), b.get(thumbprint), out);
  }
  return out;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [cryptoproFile, oursFile] = process.argv.slice(2);
  if (!cryptoproFile || !oursFile) {
    console.error("usage: node scripts/compare-fields.ts CRYPTOPRO.json OURS.json");
    process.exit(2);
  }
  const differences = compareDumps(JSON.parse(readFileSync(cryptoproFile, "utf8")), JSON.parse(readFileSync(oursFile, "utf8")));
  for (const { path, cryptopro, ours } of differences) {
    console.log(`${path}\n  КриптоПро: ${JSON.stringify(cryptopro)}\n  мы:        ${JSON.stringify(ours)}`);
  }
  console.log(differences.length ? `различий: ${differences.length}` : "различий нет");
  process.exit(differences.length ? 1 : 0);
}
