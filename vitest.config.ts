import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    coverage: {
      provider: "v8",
      reporter: ["text", "json-summary"]
    },
    include: ["apps/**/*.test.ts", "lab/**/*.test.ts", "packages/**/*.test.ts"]
  }
});
