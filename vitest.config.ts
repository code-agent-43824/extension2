import { defineConfig } from "vitest/config";
import { aliases } from "./scripts/build.ts";

export default defineConfig({
  // scripts/build.ts defines the same constants for each build; the unit tests run as Chrome's.
  define: { __EXTENSION_VERSION__: JSON.stringify("0.0.0-test"), __BROWSER__: JSON.stringify("chrome") },
  resolve: { alias: aliases },
  test: { include: ["tests/unit/**/*.test.ts"] },
});
