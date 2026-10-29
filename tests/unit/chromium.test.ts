// Which Chromium the stand runs when the environment lacks the build the pinned Playwright expects (docs/PLAN.md, 40c).
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { chromiumExecutable } from "../../scripts/setup-stand.ts";

let dir: string;

function file(path: string): string {
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(path, "");
  return path;
}

afterEach(() => rmSync(dir, { recursive: true, force: true }));

describe("the stand's Chromium", () => {
  it("is Playwright's own when it is there, else the environment's link, else its newest build", () => {
    dir = mkdtempSync(join(tmpdir(), "browsers-"));
    const expected = join(dir, "chromium-1194", "chrome-linux", "chrome");
    // Only a newer build, under the directory Chrome for Testing uses.
    const newer = file(join(dir, "chromium-1243", "chrome-linux64", "chrome"));
    file(join(dir, "chromium-999", "chrome-linux", "chrome"));
    expect(chromiumExecutable(expected, dir)).toBe(newer);
    symlinkSync(newer, join(dir, "chromium"));
    expect(chromiumExecutable(expected, dir)).toBe(join(dir, "chromium"));
    file(expected);
    expect(chromiumExecutable(expected, dir)).toBeUndefined();
    // No browsers directory at all: Playwright reports what it misses itself.
    expect(chromiumExecutable(join(dir, "none"), join(dir, "nowhere"))).toBeUndefined();
  });
});
