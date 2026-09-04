import { defineConfig } from "vite";
import { resolve } from "path";
import dts from "vite-plugin-dts";

export default defineConfig({
  plugins: [
    dts({
      include: ["src/**/*"],
      exclude: ["src/wasm/**/*"],
    }),
  ],
  build: {
    lib: {
      entry: resolve(import.meta.dirname, "src/index.ts"),
      formats: ["es"],
      fileName: "index",
    },
    rolldownOptions: {
      output: {
        codeSplitting: false,
      },
    },
    target: "es2022",
    sourcemap: true,
  },
  optimizeDeps: {
    exclude: ["./src/wasm"],
  },
});
