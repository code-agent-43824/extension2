import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { directoryEntries, zip } from "../../scripts/package.ts";

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
  });
});
