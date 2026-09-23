import { describe, expect, it } from "vitest";
import { compareDumps, type Dump } from "../../scripts/compare-fields.ts";

describe("field comparison", () => {
  it("reports differing, missing and extra values and certificates, matched by thumbprint", () => {
    const cryptopro: Dump = {
      about: { CSPName: "Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider", PluginVersion: "2.0.15000" },
      certificates: [
        { Thumbprint: "AA", SubjectName: "CN=A, C=RU", GetInfo: { SUBJECT_SIMPLE_NAME: "A" } },
        { Thumbprint: "BB", SubjectName: "CN=B" },
      ],
    };
    const ours: Dump = {
      about: { CSPName: "Rutoken Plugin 4.12.3.0", PluginVersion: "2.0.15000" },
      certificates: [{ Thumbprint: "AA", SubjectName: "CN=A, C=RU", GetInfo: { SUBJECT_SIMPLE_NAME: { error: "не поддерживается" } } }],
    };
    expect(compareDumps(cryptopro, ours)).toEqual([
      { path: "about.CSPName", cryptopro: "Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider", ours: "Rutoken Plugin 4.12.3.0" },
      { path: "certificate AA.GetInfo.SUBJECT_SIMPLE_NAME", cryptopro: "A", ours: { error: "не поддерживается" } },
      { path: "certificate BB", cryptopro: { Thumbprint: "BB", SubjectName: "CN=B" }, ours: undefined },
    ]);
    expect(compareDumps(ours, ours)).toEqual([]);
  });
});
