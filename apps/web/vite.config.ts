import { defineConfig } from "vite";
export default defineConfig({
  build: { outDir: "dist", emptyOutDir: true, sourcemap: true },
  server: { host: "127.0.0.1", port: 4173, strictPort: true, proxy: { "/api": "http://127.0.0.1:4310" } },
});
