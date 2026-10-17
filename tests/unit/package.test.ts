import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { FIREFOX_MIN_VERSION } from "../../scripts/build.ts";
import { directoryEntries, releaseEntries, zip } from "../../scripts/package.ts";

const dir = mkdtempSync(join(tmpdir(), "package-test-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe("extension archive", () => {
  it("is a ZIP that an independent reader unpacks to the same files", () => {
    const source = join(dir, "src");
    mkdirSync(join(source, "sub"), { recursive: true });
    writeFileSync(join(source, "manifest.json"), '{"name": "КриптоПро через Рутокен"}\n');
    writeFileSync(join(source, "sub", "page.js"), "x".repeat(10_000));
    writeFileSync(join(source, "empty.css"), "");
    const archive = join(dir, "out.zip");
    writeFileSync(archive, zip(directoryEntries(source, "folder")));
    // Python's zipfile checks the structure and every CRC.
    const script = [
      "import json, sys, zipfile",
      "z = zipfile.ZipFile(sys.argv[1])",
      "assert z.testzip() is None",
      "print(json.dumps({i.filename: z.read(i).decode() for i in z.infolist()}, ensure_ascii=False))",
    ].join("\n");
    const run = spawnSync("python3", ["-c", script, archive], { encoding: "utf8" });
    expect(run.stderr).toBe("");
    expect(JSON.parse(run.stdout)).toEqual({
      "folder/empty.css": "",
      "folder/manifest.json": '{"name": "КриптоПро через Рутокен"}\n',
      "folder/sub/page.js": "x".repeat(10_000),
    });
    // Firefox's add-on file: the manifest at the root.
    writeFileSync(archive, zip(directoryEntries(source)));
    const root = spawnSync("python3", ["-c", script, archive], { encoding: "utf8" });
    expect(Object.keys(JSON.parse(root.stdout))).toEqual(["empty.css", "manifest.json", "sub/page.js"]);
  });
});

describe("release archive", () => {
  it("holds one folder with the Chrome build, the Firefox add-on file and the instructions with the versions filled in", () => {
    const chrome = join(dir, "chrome-build");
    const firefox = join(dir, "firefox-build");
    mkdirSync(chrome, { recursive: true });
    mkdirSync(firefox, { recursive: true });
    writeFileSync(join(chrome, "manifest.json"), '{"minimum_chrome_version": "111"}');
    writeFileSync(join(chrome, "page.js"), "chrome");
    writeFileSync(join(firefox, "manifest.json"), "{}");
    writeFileSync(join(firefox, "page.js"), "firefox");
    const archive = join(dir, "release.zip");
    writeFileSync(archive, zip(releaseEntries("9.8.7", chrome, firefox)));
    // Python's zipfile reads the archive and, inside it, the add-on file.
    const script = [
      "import io, json, sys, zipfile",
      "z = zipfile.ZipFile(sys.argv[1])",
      "assert z.testzip() is None",
      "xpi = zipfile.ZipFile(io.BytesIO(z.read('cryptopro-via-rutoken-9.8.7/firefox/cryptopro-via-rutoken-9.8.7.xpi')))",
      "readme = z.read('cryptopro-via-rutoken-9.8.7/README.txt')",
      "print(json.dumps({'names': z.namelist(), 'xpi': xpi.namelist(), 'bom': readme.startswith(b'\\xef\\xbb\\xbf'), 'readme': readme.decode('utf-8-sig')}, ensure_ascii=False))",
    ].join("\n");
    const run = spawnSync("python3", ["-c", script, archive], { encoding: "utf8" });
    expect(run.stderr).toBe("");
    const { names, xpi, bom, readme } = JSON.parse(run.stdout);
    expect(names).toEqual([
      "cryptopro-via-rutoken-9.8.7/README.txt",
      "cryptopro-via-rutoken-9.8.7/chrome/manifest.json",
      "cryptopro-via-rutoken-9.8.7/chrome/page.js",
      "cryptopro-via-rutoken-9.8.7/firefox/cryptopro-via-rutoken-9.8.7.xpi",
    ]);
    expect(xpi).toEqual(["manifest.json", "page.js"]);
    expect(bom).toBe(true);
    expect(readme).toContain("КриптоПро через Рутокен 9.8.7");
    expect(readme).toContain("Google Chrome (версия 111 или новее)");
    expect(readme).toContain(`Mozilla Firefox (версия ${parseInt(FIREFOX_MIN_VERSION)} или новее)`);
    expect(readme).toContain("/blob/v9.8.7/docs/STATUS.md");
    expect(readme).not.toContain("{{");
  });
});
