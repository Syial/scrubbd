import { resolve } from "node:path";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "@core": resolve(__dirname, "src/core"),
      "@rules": resolve(__dirname, "src/rules"),
      "@ui": resolve(__dirname, "src/ui"),
      "@i18n": resolve(__dirname, "src/i18n"),
    },
  },
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts", "src/**/*.test.ts"],
  },
});
