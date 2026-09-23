import { existsSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { developerKey, extensionIdFromKey, parseCrx } from "../../scripts/crx.ts";
import { vendorPath } from "../../scripts/fetch-vendor.ts";

const adapterCrx = vendorPath("rutoken-adapter");

describe("extensionIdFromKey", () => {
  it("maps SHA-256 nibbles to a..p", () => {
    // SHA-256("") starts with e3b0c442 98fc1c14 9afbf4c8 996fb924.
    expect(extensionIdFromKey(Buffer.alloc(0))).toBe("odlameecjipmbmbejkplpemijjgpljce");
  });
});

describe("parseCrx", () => {
  it("rejects files that are not CRX", () => {
    expect(() => parseCrx(Buffer.from("PK\x03\x04"))).toThrow("not a CRX file");
  });

  it.skipIf(!existsSync(adapterCrx))("finds the key that gives the Rutoken adapter its store id", () => {
    const crx = parseCrx(readFileSync(adapterCrx));
    expect(extensionIdFromKey(developerKey(crx))).toBe("ohedcglhbbfdgaogjhcclacoccbagkjg");
    expect(crx.zip.subarray(0, 4).toString("latin1")).toBe("PK\x03\x04");
  });
});
