import { resolve } from "node:path";
import { defineConfig } from "vite";

export default defineConfig({
  resolve: {
    alias: {
      "@core": resolve(__dirname, "src/core"),
      "@rules": resolve(__dirname, "src/rules"),
      "@ui": resolve(__dirname, "src/ui"),
      "@i18n": resolve(__dirname, "src/i18n"),
    },
  },
  build: {
    target: "es2022",
    sourcemap: true,
    rollupOptions: {
      input: {
        main: resolve(__dirname, "index.html"),
        limits: resolve(__dirname, "limits.html"),
      },
    },
  },
  worker: {
    format: "es",
  },
});
