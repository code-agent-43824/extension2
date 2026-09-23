import { defineConfig } from "vitest/config";

export default defineConfig({
  // scripts/build.ts defines the same constant for the extension build.
  define: { __EXTENSION_VERSION__: JSON.stringify("0.0.0-test") },
  test: { include: ["tests/unit/**/*.test.ts"] },
});
