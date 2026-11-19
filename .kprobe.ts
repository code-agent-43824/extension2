import { konturHost } from "./tests/stand/kontur.ts";
const variants: Record<string, unknown>[] = JSON.parse(process.argv[2]!);
const providers = await (async () => { const h = konturHost(); const r = await h.ask("crypto.provider.search", { cryptoProviderType: "pkcs11" }); h.close(); return r.result; })();
const provider = providers[0];
for (const v of variants) {
  const host = konturHost();
  const fields = JSON.parse(JSON.stringify(v).replace(/"\$PROVIDER"/g, JSON.stringify(provider)));
  try {
    const a = await host.ask(fields.type, fields, { timeoutMs: 20000 });
    console.log(JSON.stringify(v).slice(0, 300), "=>", JSON.stringify(a.error ?? a.result).slice(0, Number(process.env.LIMIT ?? 400)));
  } catch (e) { console.log(JSON.stringify(v).slice(0, 300), "=> TIMEOUT"); }
  host.close();
}
process.exit(0);
