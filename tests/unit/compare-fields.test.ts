import { describe, expect, it } from "vitest";
import { compareDumps, type Dump } from "../../scripts/compare-fields.ts";

describe("field comparison", () => {
  it("reports differing, missing and extra values, certificates matched by thumbprint and Find's results", () => {
    const cryptopro: Dump = {
      about: { CSPName: "Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider", PluginVersion: "2.0.15000" },
      certificates: [
        { Thumbprint: "AA", SubjectName: "CN=A, C=RU", GetInfo: { SUBJECT_SIMPLE_NAME: "A" } },
        { Thumbprint: "BB", SubjectName: "CN=B" },
      ],
      find: { "EXTENSION 2.5.29.15": ["AA", "BB"], "ROOT_NAME B": ["BB"] },
    };
    const ours: Dump = {
      about: { CSPName: "Rutoken Plugin 4.12.3.0", PluginVersion: "2.0.15000" },
      certificates: [{ Thumbprint: "AA", SubjectName: "CN=A, C=RU", GetInfo: { SUBJECT_SIMPLE_NAME: { error: "не поддерживается" } } }],
      find: { "EXTENSION 2.5.29.15": ["AA"], "ROOT_NAME B": ["BB"] },
    };
    expect(compareDumps(cryptopro, ours)).toEqual([
      { path: "about.CSPName", cryptopro: "Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider", ours: "Rutoken Plugin 4.12.3.0" },
      { path: "certificate AA.GetInfo.SUBJECT_SIMPLE_NAME", cryptopro: "A", ours: { error: "не поддерживается" } },
      { path: "certificate BB", cryptopro: { Thumbprint: "BB", SubjectName: "CN=B" }, ours: undefined },
      { path: "find.EXTENSION 2.5.29.15", cryptopro: ["AA", "BB"], ours: ["AA"] },
    ]);
    expect(compareDumps(ours, ours)).toEqual([]);
  });
});
