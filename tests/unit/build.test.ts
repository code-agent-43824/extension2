// The Firefox build's manifest (scripts/build.ts): the same extension, with Firefox's background script and add-on
// settings in place of Chrome's.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { FIREFOX_ID, firefoxManifest } from "../../scripts/build.ts";
import { repoRoot } from "../../scripts/fetch-vendor.ts";

describe("Firefox manifest", () => {
  const chrome = JSON.parse(readFileSync(join(repoRoot, "src", "manifest.json"), "utf8"));

  it("runs the service worker's script as the background script, and names the add-on and its minimum Firefox", () => {
    const firefox = firefoxManifest(chrome);
    expect(firefox.background).toEqual({ scripts: ["background.js"] });
    expect(firefox).not.toHaveProperty("minimum_chrome_version");
    expect(firefox.browser_specific_settings).toEqual({
      gecko: { id: FIREFOX_ID, strict_min_version: "128.0", data_collection_permissions: { required: ["none"] } },
    });
  });

  it("keeps everything else, the permissions and optional site access first of all", () => {
    const { background: _a, browser_specific_settings: _b, ...firefox } = firefoxManifest(chrome);
    const { background: _c, minimum_chrome_version: _d, ...rest } = chrome;
    expect(firefox).toEqual(rest);
  });
});
