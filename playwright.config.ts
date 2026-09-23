import { defineConfig } from "@playwright/test";

// Stand tests drive a real browser against the stand built by `npm run stand`.
export default defineConfig({
  testDir: "tests/stand",
  testMatch: "*.spec.ts",
  workers: 1,
  timeout: 120_000,
  reporter: "list",
});
