import { defineConfig } from "vitest/config";
import { aliases } from "./scripts/build.ts";

export default defineConfig({
  // scripts/build.ts defines the same constant for the extension build.
  define: { __EXTENSION_VERSION__: JSON.stringify("0.0.0-test") },
  resolve: { alias: aliases },
  test: { include: ["tests/unit/**/*.test.ts"] },
});
